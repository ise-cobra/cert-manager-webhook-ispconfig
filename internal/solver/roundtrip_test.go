package solver

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	whapi "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/ispconfig"
	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/ispconfig/ddnstest"
)

// wrongToken has the format the remote side requires, but belongs to no record — the
// response is therefore 401. Synthetic value, like testToken.
const wrongToken = "0badc0ffee"

// roundTrip wires the solver with the **real** ispconfig.Client against a stateful fake
// remote side. No stub in the chain: newClient stays untouched, only the Kubernetes
// clientset is a fake.
//
// The purpose is the gap that neither the stub tests in solver_test.go nor the conformance
// suite in e2e/ close: the stub has no state and therefore cannot tell whether CleanUp really
// removes only its own value, and e2e/ only runs with `-tags e2e` plus etcd and kube-apiserver
// binaries.
type roundTrip struct {
	solver *Solver
	store  *ddnstest.RecordStore
	ddns   *ddnstest.Server
	logs   *bytes.Buffer
}

// newRoundTrip starts the fake remote side and returns a ready-to-use solver. The clientset
// is set directly, as in the other tests of this package — Initialize would require a
// reachable API server.
func newRoundTrip(t *testing.T, secret *corev1.Secret) *roundTrip {
	t.Helper()

	store := ddnstest.NewRecordStore()
	ddns := ddnstest.NewServer(t, store, testToken)
	logs := &bytes.Buffer{}

	// AllowInsecureEndpoint because the fake runs as HTTP — see ddnstest.Server for the rationale.
	s := New(Defaults{
		Endpoint:              ddns.Endpoint(),
		HTTPTimeout:           10 * time.Second,
		AllowInsecureEndpoint: true,
	}, slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	s.clientset = fake.NewClientset(secret)

	return &roundTrip{solver: s, store: store, ddns: ddns, logs: logs}
}

// values returns the TXT values currently stored under the challenge record.
func (r *roundTrip) values() []string {
	return r.store.Lookup(testRecord)
}

// roundTripChallenge builds a ChallengeRequest without endpoint in the config block — it comes
// from the defaults and thus from the fake. The record name is the same for all; they differ
// only by key.
func roundTripChallenge(key, authMode string) *whapi.ChallengeRequest {
	ch := validChallenge()
	ch.Key = key
	ch.Config = rawConfig(
		`{"tokenSecretRef": {"name": "` + testSecret + `"}, "tokenAuthMode": "` + authMode + `"}`)

	return ch
}

// TestRoundTripWildcardAndApexShareRecordName is the core use case of the service: a wildcard
// certificate creates two challenges with the same record name and different values, and
// CleanUp may remove only its own value.
func TestRoundTripWildcardAndApexShareRecordName(t *testing.T) {
	t.Parallel()

	rt := newRoundTrip(t, tokenSecret())

	apex := roundTripChallenge("apex-key-1", "basic")
	wildcard := roundTripChallenge("wildcard-key-2", "basic")
	wildcard.DNSName = "*.example.com"

	require.NoError(t, rt.solver.Present(apex))
	require.NoError(t, rt.solver.Present(wildcard))
	require.Equal(t, []string{"apex-key-1", "wildcard-key-2"}, rt.values(),
		"both values must exist under the same name at the same time")

	// The decisive step: only the value of the cleaned-up challenge disappears.
	require.NoError(t, rt.solver.CleanUp(apex))
	assert.Equal(t, []string{"wildcard-key-2"}, rt.values(),
		"CleanUp of one challenge must not remove the other")

	require.NoError(t, rt.solver.CleanUp(wildcard))
	assert.Empty(t, rt.values())

	// Repeated CleanUp: the remote side answers with 404, but the desired state is
	// reached. An error would leave the challenge stuck permanently.
	require.NoError(t, rt.solver.CleanUp(wildcard))
	assert.Empty(t, rt.values())
	assert.Contains(t, rt.logs.String(), "TXT record no longer exists")
}

// TestRoundTripPresentIsIdempotent covers the retry case: cert-manager calls Present again
// after a timeout.
func TestRoundTripPresentIsIdempotent(t *testing.T) {
	t.Parallel()

	rt := newRoundTrip(t, tokenSecret())
	ch := roundTripChallenge(testKey, "basic")

	require.NoError(t, rt.solver.Present(ch))
	require.NoError(t, rt.solver.Present(ch))

	assert.Equal(t, []string{testKey}, rt.values(), "the second Present must not create a duplicate")
	assert.Contains(t, rt.logs.String(), "TXT record already in the desired state")
}

// TestRoundTripAuthModes runs both token transport modes through the success case once. In
// query mode the token is part of the request URL — the log lines must still not contain
// it.
func TestRoundTripAuthModes(t *testing.T) {
	t.Parallel()

	for _, authMode := range []string{"basic", "query"} {
		t.Run(authMode, func(t *testing.T) {
			t.Parallel()

			rt := newRoundTrip(t, tokenSecret())
			ch := roundTripChallenge(testKey, authMode)

			require.NoError(t, rt.solver.Present(ch))
			require.Equal(t, []string{testKey}, rt.values())

			require.NoError(t, rt.solver.CleanUp(ch))
			assert.Empty(t, rt.values())

			assert.NotContains(t, rt.logs.String(), testToken)
		})
	}
}

// TestRoundTripSendsExpectedParameters pins down what actually goes over the wire.
func TestRoundTripSendsExpectedParameters(t *testing.T) {
	t.Parallel()

	rt := newRoundTrip(t, tokenSecret())
	ch := roundTripChallenge(testKey, "basic")

	require.NoError(t, rt.solver.Present(ch))
	require.NoError(t, rt.solver.CleanUp(ch))

	// Record has no trailing dot although ResolvedFQDN (testFQDN) has one, and zone stays
	// empty — with zone the remote side takes the name literally and the token restriction
	// to the relative name fails. The HTTP method is set redundantly to action, so that a
	// dropped action parameter does not turn into a forbidden TXT update.
	assert.Equal(t, []ddnstest.Request{
		{Method: http.MethodPost, Action: "add", Type: "TXT", Record: testRecord, Data: testKey},
		{Method: http.MethodDelete, Action: "delete", Type: "TXT", Record: testRecord, Data: testKey},
	}, rt.ddns.Requests())
}

// TestRoundTripWrongTokenIsNotLeaked checks the 401 path in query mode: there the token is
// part of the URL and thus potentially of every transport error.
func TestRoundTripWrongTokenIsNotLeaked(t *testing.T) {
	t.Parallel()

	rt := newRoundTrip(t, newSecret(testSecret, map[string][]byte{"token": []byte(wrongToken)}))

	err := rt.solver.Present(roundTripChallenge(testKey, "query"))

	require.ErrorIs(t, err, ispconfig.ErrUnauthorized)
	assert.NotContains(t, err.Error(), wrongToken)
	assert.NotContains(t, rt.logs.String(), wrongToken)
	assert.Empty(t, rt.values())
}

// TestFakeRejectsTokenInRequestBody guards the fidelity of the test double: the module reads
// `$_GET['token']`, a query-only source. A fake reading the token from r.Form would also
// accept a form body — a hardening that moves the token from the URL into the
// body would have passed here and failed with 401 in production.
func TestFakeRejectsTokenInRequestBody(t *testing.T) {
	t.Parallel()

	ddns := ddnstest.NewServer(t, ddnstest.NewRecordStore(), testToken)

	body := url.Values{
		"action": {"add"},
		"type":   {"TXT"},
		"record": {testRecord},
		"data":   {testKey},
		"token":  {testToken},
	}
	resp, err := http.Post(ddns.Endpoint()+"/ddns/update.php",
		"application/x-www-form-urlencoded", strings.NewReader(body.Encode()))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, resp.Body.Close()) })

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"a token in the body is no token for the remote side")
}

// TestRoundTripLimitRecordsRejectsSubdomain reproduces the limit documented in the README: a
// token with `limit_records = _acme-challenge` only allows the record directly below the zone.
// A challenge for a subdomain yields the relative name `_acme-challenge.www` and thus 403.
func TestRoundTripLimitRecordsRejectsSubdomain(t *testing.T) {
	t.Parallel()

	store := ddnstest.NewRecordStore()
	ddns := ddnstest.NewServer(t, store, testToken,
		ddnstest.WithLimitRecords("example.com", "_acme-challenge"))

	logs := &bytes.Buffer{}
	s := New(Defaults{
		Endpoint:              ddns.Endpoint(),
		HTTPTimeout:           10 * time.Second,
		AllowInsecureEndpoint: true,
	}, slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	s.clientset = fake.NewClientset(tokenSecret())

	// Directly below the zone: allowed.
	apex := roundTripChallenge(testKey, "basic")
	require.NoError(t, s.Present(apex))

	// One level deeper: the relative name is not in limit_records.
	sub := roundTripChallenge(testKey, "basic")
	sub.ResolvedFQDN = "_acme-challenge.www.example.com."
	sub.DNSName = "www.example.com"

	err := s.Present(sub)
	require.ErrorIs(t, err, ispconfig.ErrForbidden)
	assert.Contains(t, err.Error(), "_acme-challenge.www.example.com",
		"the message names the rejected record — the only diagnosis for this case")
}
