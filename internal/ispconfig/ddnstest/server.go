package ddnstest

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
)

// updatePath is the path under which the ISPConfig DDNS module is reachable.
const updatePath = "/ddns/update.php"

// tokenFilter replicates `preg_replace("/[^0-9^a-f]/", "", $token)` from DdnsUpdater. The module
// **silently** removes everything except digits, a-f and `^` — a token with uppercase letters
// then matches no record and shows up as 401. The fake reproduces that so that a format error
// surfaces here just as in production.
var tokenFilter = regexp.MustCompile(`[^0-9a-f^]`)

// Request holds the raw parameters of a call as the remote side saw them. Tests use it to check
// what actually went over the wire: that `record` arrives without a trailing dot and `zone` is
// never sent.
type Request struct {
	Method string
	Action string
	Type   string
	Record string
	Data   string
	Zone   string
}

// Server is an httptest server that maps the semantics of `/ddns/update.php`
// (ispconfig-ddns-module v1.4.2, DefaultDdnsResponseWriter) onto a RecordStore. Runs as HTTP
// on purpose instead of httptest.NewTLSServer: the solver offers no hook for an additional CA
// bundle, so a test sets AllowInsecureEndpoint.
type Server struct {
	t     testing.TB
	store *RecordStore
	token string
	srv   *httptest.Server

	// zone and limitRecords replicate the remote side's token restriction; empty means
	// "no restriction".
	zone         string
	limitRecords []string

	mu       sync.Mutex
	requests []Request
}

// Option adjusts the fake before start.
type Option func(*Server)

// WithLimitRecords replicates the remote side's token restriction `limit_records`: only the given
// relative record names within zone are allowed, everything else gets 403. Without this option
// the most likely operational error could not be reproduced: a token with
// `limit_records = _acme-challenge` rejects every subdomain challenge (README, "Regular certificates and subdomains").
func WithLimitRecords(zone string, names ...string) Option {
	return func(f *Server) {
		f.zone = strings.TrimSuffix(zone, ".")
		f.limitRecords = names
	}
}

// NewServer starts the fake against store and stops it via t.Cleanup. Only token is
// accepted — any other value results in 401.
func NewServer(t testing.TB, store *RecordStore, token string, opts ...Option) *Server {
	t.Helper()

	f := &Server{t: t, store: store, token: token}
	for _, opt := range opts {
		opt(f)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(updatePath, f.handleUpdate)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)

	return f
}

// recordAllowed checks the record name against limit_records. The relative name within the zone
// is compared — just like in the module, which first strips the zone name from the absolute
// name.
func (f *Server) recordAllowed(record string) bool {
	if len(f.limitRecords) == 0 {
		return true
	}

	relative := strings.TrimSuffix(strings.TrimSuffix(record, "."), "."+f.zone)

	return slices.Contains(f.limitRecords, relative)
}

// Endpoint returns the base URL that belongs into the solver configuration as `endpoint`.
func (f *Server) Endpoint() string {
	return f.srv.URL
}

// Requests returns a copy of all received calls in order of arrival — including the rejected
// ones.
func (f *Server) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()

	return slices.Clone(f.requests)
}

func (f *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	// Read from the URL query, not from r.Form: the module is only known to read the query
	// (`$_GET['token']`), and a double that additionally accepts a form body would confirm a
	// request that fails in production with "Missing input data". ParseForm still runs so that
	// a broken body yields the same 400 as on the remote side.
	if err := r.ParseForm(); err != nil {
		f.write(w, http.StatusBadRequest, "Invalid Data: %s", err)

		return
	}

	query := r.URL.Query()
	record := query.Get("record")
	recordType := query.Get("type")
	data := query.Get("data")
	zone := query.Get("zone")

	f.mu.Lock()
	f.requests = append(f.requests, Request{
		Method: r.Method,
		Action: query.Get("action"),
		Type:   recordType,
		Record: record,
		Data:   data,
		Zone:   zone,
	})
	f.mu.Unlock()

	if !f.tokenValid(r) {
		f.write(w, http.StatusUnauthorized, "Missing or invalid token.")

		return
	}

	action := resolveAction(query.Get("action"), r.Method)

	if recordType != "TXT" {
		f.write(w, http.StatusForbidden, "Permission denied for record type %s", recordType)

		return
	}
	// For TXT, `update` is forbidden in the module. Happens exactly when the client neither sets
	// `action` nor uses POST/DELETE.
	if action == "update" {
		f.write(w, http.StatusForbidden, "Permission denied for TXT update")

		return
	}
	// If `zone` is set, the module takes `record` literally and checks the absolute name
	// against `limit_records` — with a token restricted to `_acme-challenge` that yields 403.
	// The fake pins this error so that the client never sends `zone`.
	if zone != "" {
		f.write(w, http.StatusForbidden, "Permission denied for record %s", record)

		return
	}
	if record == "" || data == "" {
		f.write(w, http.StatusBadRequest,
			"Missing input data, zone=%s, record=%s, type=%s, data=%s.", zone, record, recordType, data)

		return
	}
	if len(data) > 255 {
		f.write(w, http.StatusBadRequest, "Invalid Data: maximum 255 characters")

		return
	}
	if !f.recordAllowed(record) {
		f.write(w, http.StatusForbidden, "Permission denied for record %s", record)

		return
	}

	switch action {
	case "add":
		if !f.store.Add(record, data) {
			// noUpdateRequired: deliberately 200, the target state is reached.
			f.write(w, http.StatusOK, "ERROR: %s is already set in %s.", data, record)

			return
		}
		f.write(w, http.StatusOK,
			"Scheduled update to '%s' of record %s. Schedule runs in 0 seconds. Record TTL: 3600.", data, record)
	case "delete":
		if !f.store.Remove(record, data) {
			f.write(w, http.StatusNotFound,
				"Could not find record '%s' of type '%s' in zone '%s'", record, recordType, zone)

			return
		}
		f.write(w, http.StatusOK,
			"Scheduled delete of record %s. Schedule runs in 0 seconds. Record TTL: 3600.", record)
	}
}

// tokenValid replicates DdnsUpdater::getTokenFromRequest(): the query parameter `token` takes
// precedence over the basic auth password. Deliberately read from r.URL.Query(), not from
// r.Form: the module only reads `$_GET['token']` — r.Form would also accept a form body and
// confirm a change that fails with 401 in production.
func (f *Server) tokenValid(r *http.Request) bool {
	raw := r.URL.Query().Get("token")
	if raw == "" {
		if _, password, ok := r.BasicAuth(); ok {
			raw = password
		}
	}

	filtered := tokenFilter.ReplaceAllString(raw, "")

	return filtered != "" && filtered == f.token
}

// resolveAction replicates setAction() plus the module's method fallback: unknown `action`
// values are silently dropped, then the HTTP method decides — and everything except DELETE and
// POST ends up as `update`.
func resolveAction(action, method string) string {
	switch action {
	case "add", "delete", "update":
		return action
	}

	switch method {
	case http.MethodDelete:
		return "delete"
	case http.MethodPost:
		return "add"
	default:
		return "update"
	}
}

// write produces a response in the format of DefaultDdnsResponseWriter: plain text body with a
// trailing newline, Content-Type always text/html.
func (f *Server) write(w http.ResponseWriter, status int, format string, args ...any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	// Mirrors record/data into the body like the real DefaultDdnsResponseWriter (the client
	// checks exactly that). G705 is harmless: pure test server, inputs from the same process.
	//nolint:gosec // G705: test fake, no browser client, never shipped.
	if _, err := io.WriteString(w, fmt.Sprintf(format, args...)+"\n"); err != nil {
		f.t.Errorf("fake DDNS: could not write response: %v", err)
	}
}
