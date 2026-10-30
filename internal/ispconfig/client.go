// Package ispconfig implements the HTTP client for the ISPConfig DDNS token API.
//
// The remote side is the ISPConfig DDNS module at <base-url>/ddns/update.php. Two quirks of its
// response matrix shape this package: the state "already set" arrives as HTTP 200 with a body
// starting with "ERROR:", and a repeated delete as HTTP 404. evaluateResponse handles both.
//
// The token is a secret and must never appear in log lines, error messages or span
// attributes — see Client.redact and Config.LogValue.
package ispconfig

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/common/observability"
)

const (
	// ddnsPath is appended to the path of the base URL.
	ddnsPath = "ddns/update.php"
	// basicAuthUser is the user name the remote side ignores but expects.
	basicAuthUser = "anonymous"
	// defaultTimeout applies when Config.Timeout is not set.
	defaultTimeout = 30 * time.Second
	// maxTXTValueLength is the length of a TXT value allowed by the remote side.
	maxTXTValueLength = 255
	// maxResponseBytes limits how much of the response body is read at all.
	maxResponseBytes = 8 << 10
	// maxBodySnippetLength limits the response body in error messages and log lines.
	maxBodySnippetLength = 512
	// RedactedPlaceholder replaces the token value in every output. Exported so that secret
	// resolution uses the same placeholder and redaction is not defined in two places.
	RedactedPlaceholder = "[REDACTED]"
	// errorBodyPrefix marks the case "target state already reached" on HTTP 200.
	errorBodyPrefix = "ERROR:"
)

// Attribute names for span and metrics. Deliberately low-cardinality: no record name, no value.
const (
	attrAction     = "ddns.action"
	attrStatusCode = "http.response.status_code"
	attrOutcome    = "outcome"
)

// Values of the outcome attribute that do not come from Outcome.String().
const (
	// outcomeError marks a real error.
	outcomeError = "error"
	// outcomeNotFound marks the target state "record was already removed" (404 on delete).
	// Deliberately not "error": someone would alert on that.
	outcomeNotFound = "not_found"
)

// tokenPattern describes the only character set the remote side does not silently strip from
// the token.
var tokenPattern = regexp.MustCompile(`^[0-9a-f]+$`)

// AuthMode determines how the token is transmitted.
type AuthMode string

const (
	// AuthModeBasic sends the token as basic auth password. Default, because the token then
	// is not part of the URL and consequently not in access logs or transport errors.
	AuthModeBasic AuthMode = "basic"
	// AuthModeQuery sends the token as token query parameter. Fallback for reverse proxies
	// that do not pass the Authorization header on to PHP.
	AuthModeQuery AuthMode = "query"
)

// Action is an action supported by the DDNS API.
type Action string

const (
	// ActionAdd creates a record.
	ActionAdd Action = "add"
	// ActionDelete removes a record.
	ActionDelete Action = "delete"
)

// method returns the HTTP method of the action. The remote side silently drops an unknown
// action parameter and then falls back to the method; the redundancy makes a typo harmless.
func (a Action) method() string {
	if a == ActionDelete {
		return http.MethodDelete
	}
	return http.MethodPost
}

// Outcome describes whether the call changed anything. On error the value is meaningless.
type Outcome int

const (
	// OutcomeChanged means the remote side has scheduled a change.
	OutcomeChanged Outcome = iota
	// OutcomeUnchanged means the target state was already reached (HTTP 200 with "ERROR:"
	// prefix).
	OutcomeUnchanged
)

// String returns the label for log lines and metric attributes.
func (o Outcome) String() string {
	switch o {
	case OutcomeChanged:
		return "changed"
	case OutcomeUnchanged:
		return "unchanged"
	default:
		return "unknown"
	}
}

// Config configures a Client.
type Config struct {
	// Endpoint is the base URL, e.g. https://ispconfig.example.com. A path component is kept.
	Endpoint string
	// Token is the DDNS token. Surrounding whitespace is removed.
	Token string
	// AuthMode determines how the token is transmitted; empty means AuthModeBasic.
	AuthMode AuthMode
	// Timeout limits each call; values <= 0 mean 30s.
	Timeout time.Duration
	// AllowInsecureEndpoint allows http:// as scheme — for development only.
	AllowInsecureEndpoint bool
	// Logger receives the client's log lines; nil means slog.Default().
	Logger *slog.Logger
}

// LogValue masks the token so that a logged Config does not reveal a secret.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("endpoint", c.Endpoint),
		slog.String("auth_mode", string(c.AuthMode)),
		slog.Duration("timeout", c.Timeout),
		slog.Bool("allow_insecure_endpoint", c.AllowInsecureEndpoint),
		slog.String("token", RedactedPlaceholder),
	)
}

// Client talks to the DDNS API of an ISPConfig server. After New it is safe for concurrent
// use.
type Client struct {
	updateURL       url.URL
	host            string
	token           string
	authMode        AuthMode
	httpClient      *http.Client
	log             *slog.Logger
	tracer          trace.Tracer
	requests        metric.Int64Counter
	requestDuration metric.Float64Histogram
}

// New validates the configuration and creates a Client. Created anew per challenge (solver.go);
// the OTel SDK deduplicates metric instruments of the same name, so there is no double
// registration.
func New(cfg Config) (*Client, error) {
	endpoint, err := parseEndpoint(cfg.Endpoint, cfg.AllowInsecureEndpoint)
	if err != nil {
		return nil, err
	}

	token, err := normalizeToken(cfg.Token)
	if err != nil {
		return nil, err
	}

	authMode, err := normalizeAuthMode(cfg.AuthMode)
	if err != nil {
		return nil, err
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	meter := observability.Meter()
	requests, err := meter.Int64Counter("ispconfig.ddns.requests",
		metric.WithDescription("Number of calls to the ISPConfig DDNS API"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return nil, fmt.Errorf("cannot create counter ispconfig.ddns.requests: %w", err)
	}
	requestDuration, err := meter.Float64Histogram("ispconfig.ddns.request.duration",
		metric.WithDescription("Duration of calls to the ISPConfig DDNS API"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("cannot create histogram ispconfig.ddns.request.duration: %w", err)
	}

	return &Client{
		updateURL: *endpoint.JoinPath(ddnsPath),
		host:      endpoint.Host,
		token:     token,
		authMode:  authMode,
		httpClient: &http.Client{
			Timeout: timeout,
			// No CookieJar: the remote side's ISPCSESS cookie carries nothing of value.
			// No otelhttp transport: the exported url.full would carry the token in query mode.
			Transport: sharedTransport(),
			// No automatic redirects: a 301 would degrade POST/DELETE to GET (read by the remote
			// side as the forbidden action=update) and could pass the token to a foreign host in
			// query mode.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		log:             logger,
		tracer:          observability.Tracer(),
		requests:        requests,
		requestDuration: requestDuration,
	}, nil
}

// sharedTransport is the single process-wide transport of all clients — the solver builds a new
// client per challenge, and a transport per client would needlessly repeat the TLS handshake and
// connection pool (up to IdleConnTimeout) instead of sharing them.
var sharedTransport = sync.OnceValue(newTransport)

// newTransport clones http.DefaultTransport (otherwise proxy support, IdleConnTimeout & co.
// would be missing, which a transport literal does not bring along) and enforces TLS 1.2. The
// type assertion is safe: http.DefaultTransport is always an *http.Transport in the stdlib.
func newTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return transport
}

// AddTXTRecord creates a TXT record with the given value. If it was already set, the remote side
// reports that without an error and the result is OutcomeUnchanged.
func (c *Client) AddTXTRecord(ctx context.Context, record, value string) (Outcome, error) {
	return c.do(ctx, ActionAdd, record, value)
}

// DeleteTXTRecord removes exactly the TXT record whose value equals value. If it does not
// exist, the error is recognizable with errors.Is(err, ErrRecordNotFound).
func (c *Client) DeleteTXTRecord(ctx context.Context, record, value string) (Outcome, error) {
	return c.do(ctx, ActionDelete, record, value)
}

// do executes a call and evaluates the response.
func (c *Client) do(ctx context.Context, action Action, record, value string) (Outcome, error) {
	if err := validateRecord(record); err != nil {
		return OutcomeChanged, err
	}
	if err := validateValue(value); err != nil {
		return OutcomeChanged, err
	}

	ctx, span := c.tracer.Start(ctx, "ispconfig.ddns."+string(action),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attribute.String(attrAction, string(action))),
	)
	defer span.End()

	req, err := c.newRequest(ctx, action, record, value)
	if err != nil {
		c.report(ctx, span, callResult{action: action, record: record, err: err})
		return OutcomeChanged, err
	}

	start := time.Now()
	resp, err := c.httpClient.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		wrapped := c.redact(fmt.Errorf("cannot execute DDNS action %s: %w", action, c.stripRequestURL(err)))
		c.report(ctx, span, callResult{action: action, record: record, elapsed: elapsed, err: wrapped})
		return OutcomeChanged, wrapped
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			c.log.WarnContext(ctx, "closing DDNS API response body failed",
				"host", c.host, "ddns_action", action, "err", c.redact(closeErr))
		}
	}()

	// The remote side's maintenance case returns a PHP fatal and thus possibly an empty body;
	// conversely, io.LimitReader caps an overlong HTML response.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		wrapped := c.redact(fmt.Errorf("cannot read response body of DDNS action %s: %w", action, err))
		c.report(ctx, span, callResult{
			action: action, record: record, statusCode: resp.StatusCode, elapsed: elapsed, err: wrapped,
		})
		return OutcomeChanged, wrapped
	}

	// Redacted immediately and truncated exactly once before the same snippet flows into
	// evaluation, APIError and telemetry: a reverse proxy could mirror the request URI and then
	// carry the token in the body in query mode. The "ERROR:" prefix survives truncation.
	snippet := truncateBody(c.redactString(string(body)))

	outcome, err := evaluateResponse(action, resp.StatusCode, snippet)
	c.report(ctx, span, callResult{
		action:     action,
		record:     record,
		statusCode: resp.StatusCode,
		elapsed:    elapsed,
		outcome:    outcome,
		body:       snippet,
		err:        err,
	})
	return outcome, err
}

// stripRequestURL replaces a *url.Error with a transportError without the request URL. Applies
// before redaction, because a token cut at a byte boundary or encoded differently could survive
// the text replacement — without a URL, that path does not exist.
func (c *Client) stripRequestURL(err error) error {
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		return err
	}
	return &transportError{op: urlErr.Op, host: c.host, err: urlErr.Err}
}

// newRequest builds the request. All parameters are in the query, not in the body — the remote
// side reads the token from $_GET only, a form body is not evaluated.
func (c *Client) newRequest(ctx context.Context, action Action, record, value string) (*http.Request, error) {
	target := c.updateURL

	query := url.Values{}
	query.Set("action", string(action))
	query.Set("type", "TXT")
	query.Set("record", record)
	query.Set("data", value)
	if c.authMode == AuthModeQuery {
		query.Set("token", c.token)
	}
	// Deliberately without zone: with zone, the remote side takes the record name literally and
	// a token restriction to the relative name fails. Likewise without ttl — the remote side does
	// not know it and hard-codes 3600.
	target.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, action.method(), target.String(), nil)
	if err != nil {
		return nil, c.redact(fmt.Errorf("cannot build request for DDNS action %s: %w",
			action, c.stripRequestURL(err)))
	}
	if c.authMode == AuthModeBasic {
		req.SetBasicAuth(basicAuthUser, c.token)
	}
	return req, nil
}

// callResult collects the telemetry a completed call yields.
type callResult struct {
	action     Action
	record     string
	statusCode int // 0 means: no response received
	elapsed    time.Duration
	outcome    Outcome
	body       string
	err        error
}

// report records metrics, span status and log lines of a completed call. The full URL is
// deliberately never logged — in query mode it carries the token.
func (c *Client) report(ctx context.Context, span trace.Span, r callResult) {
	// A 404 on delete is the target state in domain terms, not an error. The error value is
	// kept — the caller uses it to distinguish —, but metric, span and log line must not report
	// it as an error: the solver logs the same case as success, and someone would alert on
	// outcome="error".
	expected := errors.Is(r.err, ErrRecordNotFound)

	label := r.outcome.String()
	switch {
	case expected:
		label = outcomeNotFound
	case r.err != nil:
		label = outcomeError
	}

	attrs := metric.WithAttributes(
		attribute.String(attrAction, string(r.action)),
		attribute.String(attrOutcome, label),
	)
	c.requests.Add(ctx, 1, attrs)
	c.requestDuration.Record(ctx, r.elapsed.Seconds(), attrs)

	if r.statusCode != 0 {
		span.SetAttributes(attribute.Int(attrStatusCode, r.statusCode))
	}

	// Prefix ddns_, because the caller may attach a logger that already carries action and
	// record — for the solver these are present/cleanup and the same record name. Without
	// distinct names, two equally named fields with different meanings would end up in the same
	// line, and a JSON processor would arbitrarily keep one of them.
	args := []any{
		"host", c.host,
		"ddns_action", r.action,
		"ddns_record", r.record,
		"status", r.statusCode,
		"duration_ms", r.elapsed.Milliseconds(),
		"outcome", label,
	}
	switch {
	case expected:
		c.log.InfoContext(ctx, "DDNS record was already removed, target state reached", args...)
	case r.err != nil:
		// Only the error class: RecordError puts the text into the span as exception.message,
		// but the remote side's response body names record names there. The full message is
		// in the log line below.
		span.RecordError(errorClass(r.err))
		span.SetStatus(codes.Error, "DDNS call failed")
		// The only log line for this failure: solver.go does not log the same case again,
		// since host and elapsed time are additionally available here.
		c.log.ErrorContext(ctx, "DDNS call failed", append(args, "err", r.err)...)
	default:
		c.log.InfoContext(ctx, "DDNS call completed", args...)
	}

	if r.body != "" {
		c.log.DebugContext(ctx, "DDNS API response body",
			"host", c.host, "ddns_action", r.action, "status", r.statusCode, "body", r.body)
	}
}

// redact replaces the token value in the message of err with [REDACTED]. Necessary because a
// *url.Error carries the full URL and thus, in query mode, the token on every timeout. Since a
// token consists of [0-9a-f] only, its URL-encoded form is identical to the raw one — a simple
// text replacement is sufficient.
func (c *Client) redact(err error) error {
	if err == nil {
		return nil
	}
	msg := c.redactString(err.Error())
	if msg == err.Error() {
		return err
	}
	return &redactedError{msg: msg, err: err}
}

// redactString replaces every occurrence of the token in s with [REDACTED]. Only the token is
// replaced: the rest of the response body ("Permission denied for record ...") is the most
// valuable diagnostic source and is kept.
func (c *Client) redactString(s string) string {
	return strings.ReplaceAll(s, c.token, RedactedPlaceholder)
}

// evaluateResponse evaluates status and response body according to the documented response
// matrix of the DDNS API.
func evaluateResponse(action Action, statusCode int, body string) (Outcome, error) {
	switch {
	case statusCode == http.StatusNotFound && action == ActionDelete:
		// Delete is not idempotent; a second call yields 404. The caller treats that as
		// success on CleanUp.
		return OutcomeChanged, &APIError{Action: action, StatusCode: statusCode, Body: body}
	case isSuccessStatus(statusCode) && hasErrorPrefix(body):
		// noUpdateRequired() explicitly answers with 200: the target state is reached. Applies
		// to both actions — for delete, the branch in the module is currently dead code, but a
		// patched version must not lead to hanging challenges.
		return OutcomeUnchanged, nil
	case isSuccessStatus(statusCode):
		return OutcomeChanged, nil
	default:
		return OutcomeChanged, &APIError{Action: action, StatusCode: statusCode, Body: body}
	}
}

// isSuccessStatus checks for 2xx.
func isSuccessStatus(statusCode int) bool {
	return statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices
}

// hasErrorPrefix checks for the "ERROR:" prefix and tolerates leading whitespace.
func hasErrorPrefix(body string) bool {
	return strings.HasPrefix(strings.TrimLeftFunc(body, unicode.IsSpace), errorBodyPrefix)
}

// truncateBody truncates the response body for error messages and log lines. The cut happens
// on rune boundaries so that no half character is emitted.
func truncateBody(body string) string {
	trimmed := strings.TrimSpace(body)
	// A UTF-8 string never has more runes than bytes. The common case — a short response of
	// the remote side — thus gets by without a rune slice.
	if len(trimmed) <= maxBodySnippetLength {
		return trimmed
	}

	runes := []rune(trimmed)
	if len(runes) <= maxBodySnippetLength {
		return trimmed
	}
	return string(runes[:maxBodySnippetLength]) + "..."
}

// ValidateEndpoint checks a base URL by the same rule the client applies itself. Exported so
// that startup and issuer configuration do not keep their own copy of the rule.
func ValidateEndpoint(raw string, allowInsecure bool) error {
	_, err := parseEndpoint(raw, allowInsecure)

	return err
}

// parseEndpoint validates the base URL.
func parseEndpoint(raw string, allowInsecure bool) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: endpoint must not be empty", ErrInvalidEndpoint)
	}

	endpoint, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%w %q: cannot be parsed: %w", ErrInvalidEndpoint, trimmed, err)
	}

	switch endpoint.Scheme {
	case "https":
	case "http":
		if !allowInsecure {
			return nil, fmt.Errorf("%w: %q; plain text only with explicit opt-in",
				ErrInsecureEndpoint, trimmed)
		}
	case "":
		return nil, fmt.Errorf("%w %q: no scheme given, expected https://host",
			ErrInvalidEndpoint, trimmed)
	default:
		return nil, fmt.Errorf("%w %q: unsupported scheme %q, expected https",
			ErrInvalidEndpoint, trimmed, endpoint.Scheme)
	}

	if endpoint.Host == "" {
		return nil, fmt.Errorf("%w %q: no host given", ErrInvalidEndpoint, trimmed)
	}
	// User info would end up in the startup log in plain text; newRequest silently drops
	// query/fragment anyway — both point to a configuration error rather than an intended endpoint.
	if endpoint.User != nil {
		return nil, fmt.Errorf("%w %q: user info in the URL is not allowed", ErrInvalidEndpoint, trimmed)
	}
	if endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, fmt.Errorf("%w %q: query or fragment in the URL is not allowed",
			ErrInvalidEndpoint, trimmed)
	}
	return endpoint, nil
}

// IsValidToken reports whether token consists only of characters the remote side takes over
// unchanged. Exported so that secret resolution can impose the same requirement without keeping
// the pattern a second time — and report the format error there with secret name and key
// instead of experiencing it later as a 401 from the remote side.
func IsValidToken(token string) bool {
	return tokenPattern.MatchString(token)
}

// normalizeToken removes surrounding whitespace (kubectl create secret --from-file appends a
// \n) and checks the format. The remote side silently strips deviating characters and then
// reports 401 — a configuration error would thus appear as an authentication error.
func normalizeToken(raw string) (string, error) {
	token := strings.TrimSpace(raw)
	if token == "" {
		return "", fmt.Errorf("%w: token must not be empty", ErrInvalidToken)
	}
	if !IsValidToken(token) {
		// The token value does not belong in the message.
		return "", fmt.Errorf(
			"%w: token has an invalid format: only digits and lowercase letters a-f are allowed",
			ErrInvalidToken)
	}
	return token, nil
}

// normalizeAuthMode resolves the auth mode; empty means AuthModeBasic.
func normalizeAuthMode(mode AuthMode) (AuthMode, error) {
	switch mode {
	case "", AuthModeBasic:
		return AuthModeBasic, nil
	case AuthModeQuery:
		return AuthModeQuery, nil
	default:
		return "", fmt.Errorf("%w: %q, allowed are %q and %q",
			ErrInvalidAuthMode, string(mode), string(AuthModeBasic), string(AuthModeQuery))
	}
}

// validateRecord checks the record name. A trailing dot is a programming error of the caller:
// the remote side expects the FQDN without it.
func validateRecord(record string) error {
	if record == "" {
		return fmt.Errorf("%w: record name must not be empty", ErrInvalidRecord)
	}
	if strings.HasSuffix(record, ".") {
		return fmt.Errorf("%w: record name %q must not have a trailing dot", ErrInvalidRecord, record)
	}
	return nil
}

// validateValue checks the record value. It is sent unchanged, in particular without
// surrounding quotes. The length is measured in bytes, because the remote side checks with
// PHP strlen.
func validateValue(value string) error {
	if value == "" {
		return fmt.Errorf("%w: value must not be empty", ErrInvalidValue)
	}
	if len(value) > maxTXTValueLength {
		return fmt.Errorf("%w: %d characters exceed the maximum of %d",
			ErrInvalidValue, len(value), maxTXTValueLength)
	}
	return nil
}
