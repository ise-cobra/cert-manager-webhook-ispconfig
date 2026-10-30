//go:build e2e

package e2e

import (
	"log/slog"
	"testing"
	"time"

	acmetest "github.com/cert-manager/cert-manager/test/acme"

	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/ispconfig/ddnstest"
	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/solver"
)

const (
	// testZone is the zone for which the fake DNS server answers authoritatively.
	testZone = "example.com."
	// testResolvedFQDN is the record name that cert-manager resolves for a DNS01 challenge.
	// The suite requires a trailing dot (validate() in fixture.go).
	testResolvedFQDN = "_acme-challenge.example.com."
	// testDNSName is the domain in the ChallengeRequest.
	testDNSName = "example.com"

	// testSecretName must match the Secret in testdata/ispconfig-solver/secret.yaml; the suite
	// creates it in the test namespace via kubectl apply.
	//nolint:gosec // G101 false positive: the value is the name of a Secret, not a credential.
	testSecretName = "ispconfig-ddns-token"
	testSecretKey  = "token"
	// testToken is a synthetic token that exists only in this test. It must appear verbatim
	// in secret.yaml. Never enter a real token.
	testToken = "deadbeefcafe1234"

	// manifestPath contains secret.yaml (applied via kubectl) and config.json (skipped by the
	// suite when applying).
	manifestPath = "testdata/ispconfig-solver"
)

// solverConfig mirrors the issuer's config block, see providerConfig in
// internal/solver/config.go. The struct is deliberately duplicated instead of imported:
// providerConfig is unexported, and decoding in the solver is strict — a naming drift between
// contract and implementation thus surfaces immediately as a test failure.
type solverConfig struct {
	Endpoint       string            `json:"endpoint"`
	TokenSecretRef secretKeySelector `json:"tokenSecretRef"`
	HTTPTimeout    string            `json:"httpTimeout"`
	TokenAuthMode  string            `json:"tokenAuthMode"`
}

type secretKeySelector struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// TestRunsSuite runs the cert-manager conformance suite against the ISPConfig solver.
//
// Instead of a real ISPConfig installation, the solver runs against a double fake: an
// httptest server speaks the DDNS semantics of /ddns/update.php, a UDP name server answers the
// suite's TXT queries. Both work on the same ddnstest.RecordStore — the fake DDNS writes, the
// fake DNS reads. The suite thus actually checks that the solver created or removed the
// record, not merely that Present returned without error.
//
// A run against a real ISPConfig server would not be reproducible and would require a real
// token and a real zone.
func TestRunsSuite(t *testing.T) {
	store := ddnstest.NewRecordStore()
	ddns := ddnstest.NewServer(t, store, testToken)
	nameserver := newFakeDNS(t, store, testZone)

	// AllowInsecureEndpoint because the fake DDNS runs as HTTP — see ddnstest.Server for the
	// reasoning. Endpoint is additionally set as default here so that the solver would keep
	// working without endpoint in the config block.
	s := solver.New(solver.Defaults{
		Endpoint:              ddns.Endpoint(),
		HTTPTimeout:           10 * time.Second,
		AllowInsecureEndpoint: true,
	}, slog.New(slog.DiscardHandler))

	fixture := acmetest.NewFixture(s,
		// Zone and FQDN must match: the fake DNS only answers within the zone.
		acmetest.SetResolvedZone(testZone),
		acmetest.SetResolvedFQDN(testResolvedFQDN),
		acmetest.SetDNSName(testDNSName),

		// SetConfig instead of config.json: the address of the httptest server is only known at
		// runtime. applyDefaults in fixture.go only reads config.json while jsonConfig == nil —
		// so SetConfig wins. The file is kept as documentation of the field names.
		acmetest.SetConfig(solverConfig{
			Endpoint:       ddns.Endpoint(),
			TokenSecretRef: secretKeySelector{Name: testSecretName, Key: testSecretKey},
			HTTPTimeout:    "10s",
			TokenAuthMode:  "basic",
		}),
		// Still required for secret.yaml: setupNamespace applies all .json/.yaml/.yml files from
		// the directory via kubectl and skips config.json.
		acmetest.SetManifestPath(manifestPath),

		// The fake name server is the single source of truth for the self-check.
		acmetest.SetDNSServer(nameserver.server()),
		// Without this, the suite would first determine the zone's authoritative NS and query
		// them — but they do not point to 127.0.0.1.
		acmetest.SetUseAuthoritative(false),

		// Mandatory: without strict mode RunExtended skips
		// TestExtendedDeletingOneRecordRetainsOthers — exactly the wildcard case (apex and
		// *.example.com share one record name with two TXT values).
		acmetest.SetStrict(true),
		// The solver has no ambient credentials: the token comes exclusively from the Secret.
		acmetest.SetAllowAmbientCredentials(false),

		// The fake propagates immediately; the defaults (3 s interval, 2 min limit) would only
		// slow the run down. The limit stays large enough to outlast starting and restarting
		// the control plane.
		acmetest.SetPollInterval(200*time.Millisecond),
		acmetest.SetPropagationLimit(30*time.Second),
	)

	// RunConformance runs Basic and Extended and calls setup() three times in the process —
	// the control plane starts three times, Initialize is called three times. The solver is
	// idempotent accordingly.
	fixture.RunConformance(t)
}
