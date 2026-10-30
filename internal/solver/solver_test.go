package solver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	whapi "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	restclient "k8s.io/client-go/rest"

	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/ispconfig"
)

const (
	testFQDN   = "_acme-challenge.example.com."
	testRecord = "_acme-challenge.example.com"
	testKey    = "abc123"
)

// errClient is an arbitrary transport error of the DDNS client.
var errClient = errors.New("DDNS endpoint unreachable")

// stubCall records a call of the DDNS client.
type stubCall struct {
	action challengeAction
	record string
	value  string
}

// stubClient replaces the DDNS client in tests and counts every call.
type stubClient struct {
	mu      sync.Mutex
	calls   []stubCall
	outcome ispconfig.Outcome
	err     error
}

// AddTXTRecord records the call and returns the preset result.
func (c *stubClient) AddTXTRecord(_ context.Context, record, value string) (ispconfig.Outcome, error) {
	return c.note(actionPresent, record, value)
}

// DeleteTXTRecord records the call and returns the preset result.
func (c *stubClient) DeleteTXTRecord(_ context.Context, record, value string) (ispconfig.Outcome, error) {
	return c.note(actionCleanUp, record, value)
}

// note records the call.
func (c *stubClient) note(action challengeAction, record, value string) (ispconfig.Outcome, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, stubCall{action: action, record: record, value: value})

	return c.outcome, c.err
}

// recorded returns a copy of the recorded calls.
func (c *stubClient) recorded() []stubCall {
	c.mu.Lock()
	defer c.mu.Unlock()

	return slices.Clone(c.calls)
}

// harness builds a solver with a fake clientset and a stub client.
type harness struct {
	solver *Solver
	client *stubClient
	logs   *bytes.Buffer

	mu      sync.Mutex
	configs []ispconfig.Config
	newErr  error
}

// newHarness returns an initialized solver whose DDNS client is a stub.
// Without objects the fake clientset contains the standard token secret.
func newHarness(t *testing.T, objects ...runtime.Object) *harness {
	t.Helper()

	if objects == nil {
		objects = []runtime.Object{tokenSecret()}
	}

	h := &harness{client: &stubClient{}, logs: &bytes.Buffer{}}
	h.solver = New(testDefaults(), slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	h.solver.clientset = fake.NewClientset(objects...)
	h.solver.newClient = func(cfg ispconfig.Config) (ddnsClient, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.configs = append(h.configs, cfg)
		if h.newErr != nil {
			return nil, h.newErr
		}

		return h.client, nil
	}

	return h
}

// clientConfigs returns a copy of the configurations passed to newClient.
func (h *harness) clientConfigs() []ispconfig.Config {
	h.mu.Lock()
	defer h.mu.Unlock()

	return slices.Clone(h.configs)
}

// validChallenge is a ChallengeRequest the solver can process.
func validChallenge() *whapi.ChallengeRequest {
	return &whapi.ChallengeRequest{
		UID:               "11111111-2222-3333-4444-555555555555",
		Action:            whapi.ChallengeActionPresent,
		Type:              challengeTypeDNS01,
		DNSName:           "example.com",
		Key:               testKey,
		ResourceNamespace: testNamespace,
		ResolvedFQDN:      testFQDN,
		ResolvedZone:      "example.com.",
		Config:            rawConfig(`{"tokenSecretRef": {"name": "` + testSecret + `"}}`),
	}
}

func TestSolverName(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "ispconfig", New(Defaults{}, discardLogger()).Name())
	assert.Equal(t, SolverName, New(Defaults{}, discardLogger()).Name())
}

func TestPresent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mutate    func(*whapi.ChallengeRequest)
		outcome   ispconfig.Outcome
		clientErr error
		objects   []runtime.Object
		wantErr   []string
		wantCalls []stubCall
	}{
		{
			name:      "record is created",
			outcome:   ispconfig.OutcomeChanged,
			wantCalls: []stubCall{{action: actionPresent, record: testRecord, value: testKey}},
		},
		{
			name:      "identical record already exists",
			outcome:   ispconfig.OutcomeUnchanged,
			wantCalls: []stubCall{{action: actionPresent, record: testRecord, value: testKey}},
		},
		{
			name:      "empty challenge type is accepted",
			mutate:    func(ch *whapi.ChallengeRequest) { ch.Type = "" },
			outcome:   ispconfig.OutcomeChanged,
			wantCalls: []stubCall{{action: actionPresent, record: testRecord, value: testKey}},
		},
		{
			name:      "FQDN without trailing dot",
			mutate:    func(ch *whapi.ChallengeRequest) { ch.ResolvedFQDN = testRecord },
			outcome:   ispconfig.OutcomeChanged,
			wantCalls: []stubCall{{action: actionPresent, record: testRecord, value: testKey}},
		},
		{
			name:      "error of the DDNS API is passed through",
			clientErr: errClient,
			wantErr:   []string{"present", testRecord, errClient.Error()},
			wantCalls: []stubCall{{action: actionPresent, record: testRecord, value: testKey}},
		},
		{
			name:      "404 on create is an error",
			clientErr: fmt.Errorf("HTTP 404: %w", ispconfig.ErrRecordNotFound),
			wantErr:   []string{"present", testRecord},
			wantCalls: []stubCall{{action: actionPresent, record: testRecord, value: testKey}},
		},
		{
			name:    "unsupported challenge type",
			mutate:  func(ch *whapi.ChallengeRequest) { ch.Type = "http-01" },
			wantErr: []string{"http-01", "dns-01"},
		},
		{
			name:    "empty ResolvedFQDN",
			mutate:  func(ch *whapi.ChallengeRequest) { ch.ResolvedFQDN = "" },
			wantErr: []string{"ResolvedFQDN"},
		},
		{
			// A single TrimSuffix removes only one dot: an FQDN of only dots must not yield an
			// empty record name that passes the check and only fails in the client.
			name:    "ResolvedFQDN only dots",
			mutate:  func(ch *whapi.ChallengeRequest) { ch.ResolvedFQDN = "..." },
			wantErr: []string{"yields no record name"},
		},
		{
			name:    "empty key",
			mutate:  func(ch *whapi.ChallengeRequest) { ch.Key = "" },
			wantErr: []string{"Key is missing"},
		},
		{
			name:    "missing config block",
			mutate:  func(ch *whapi.ChallengeRequest) { ch.Config = nil },
			wantErr: []string{"tokenSecretRef"},
		},
		{
			name: "AllowAmbientCredentials does not replace tokenSecretRef",
			mutate: func(ch *whapi.ChallengeRequest) {
				ch.AllowAmbientCredentials = true
				ch.Config = rawConfig(`{"endpoint": "https://ddns.example.net"}`)
			},
			wantErr: []string{"tokenSecretRef.name"},
		},
		{
			name:    "secret missing",
			objects: []runtime.Object{newSecret("other-secret", map[string][]byte{"token": []byte(testToken)})},
			wantErr: []string{testNamespace, testSecret},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, tt.objects...)
			h.client.outcome = tt.outcome
			h.client.err = tt.clientErr

			ch := validChallenge()
			if tt.mutate != nil {
				tt.mutate(ch)
			}

			err := h.solver.Present(ch)

			if len(tt.wantErr) > 0 {
				require.Error(t, err)
				for _, fragment := range tt.wantErr {
					assert.Contains(t, err.Error(), fragment)
				}
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tt.wantCalls, h.client.recorded())
		})
	}
}

func TestCleanUp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mutate    func(*whapi.ChallengeRequest)
		outcome   ispconfig.Outcome
		clientErr error
		wantErr   []string
		wantCalls []stubCall
		wantLog   string
	}{
		{
			name:      "record is deleted specifically",
			outcome:   ispconfig.OutcomeChanged,
			wantCalls: []stubCall{{action: actionCleanUp, record: testRecord, value: testKey}},
		},
		{
			name:      "record no longer exists counts as success",
			clientErr: fmt.Errorf("HTTP 404: %w", ispconfig.ErrRecordNotFound),
			wantCalls: []stubCall{{action: actionCleanUp, record: testRecord, value: testKey}},
			wantLog:   `"level":"INFO","msg":"TXT record no longer exists`,
		},
		{
			name:      "unchanged counts as success",
			outcome:   ispconfig.OutcomeUnchanged,
			wantCalls: []stubCall{{action: actionCleanUp, record: testRecord, value: testKey}},
			wantLog:   `"level":"INFO","msg":"TXT record already in the desired state`,
		},
		{
			name:      "other error is passed through",
			clientErr: ispconfig.ErrForbidden,
			wantErr:   []string{"cleanup", testRecord, ispconfig.ErrForbidden.Error()},
			wantCalls: []stubCall{{action: actionCleanUp, record: testRecord, value: testKey}},
		},
		{
			name:    "unsupported challenge type",
			mutate:  func(ch *whapi.ChallengeRequest) { ch.Type = "http-01" },
			wantErr: []string{"http-01"},
		},
		{
			name:    "empty ResolvedFQDN",
			mutate:  func(ch *whapi.ChallengeRequest) { ch.ResolvedFQDN = "" },
			wantErr: []string{"ResolvedFQDN"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t)
			h.client.outcome = tt.outcome
			h.client.err = tt.clientErr

			ch := validChallenge()
			ch.Action = whapi.ChallengeActionCleanUp
			if tt.mutate != nil {
				tt.mutate(ch)
			}

			err := h.solver.CleanUp(ch)

			if len(tt.wantErr) > 0 {
				require.Error(t, err)
				for _, fragment := range tt.wantErr {
					assert.Contains(t, err.Error(), fragment)
				}
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tt.wantCalls, h.client.recorded())
			if tt.wantLog != "" {
				assert.Contains(t, h.logs.String(), tt.wantLog)
			}
		})
	}
}

func TestPresentPassesConfigToClient(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.solver.defaults.AllowInsecureEndpoint = true

	ch := validChallenge()
	ch.Config = rawConfig(`{
		"endpoint": "https://ddns.example.net",
		"tokenSecretRef": {"name": "` + testSecret + `", "key": "token"},
		"httpTimeout": "45s",
		"tokenAuthMode": "query"
	}`)

	require.NoError(t, h.solver.Present(ch))

	configs := h.clientConfigs()
	require.Len(t, configs, 1)
	assert.Equal(t, "https://ddns.example.net", configs[0].Endpoint)
	assert.Equal(t, testToken, configs[0].Token)
	assert.Equal(t, ispconfig.AuthModeQuery, configs[0].AuthMode)
	assert.Equal(t, 45*time.Second, configs[0].Timeout)
	assert.True(t, configs[0].AllowInsecureEndpoint)
	// The client must inherit the logger of the challenge, otherwise its lines lack the
	// correlation fields.
	assert.NotNil(t, configs[0].Logger)
}

func TestPresentClientCreationFails(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.newErr = errors.New("endpoint unusable")

	err := h.solver.Present(validChallenge())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "create DDNS client")
	assert.Empty(t, h.client.recorded())
}

func TestPresentWildcardAndApexShareRecordName(t *testing.T) {
	t.Parallel()

	h := newHarness(t)

	apex := validChallenge()
	apex.DNSName = "example.com"
	apex.Key = "apex-key-1"

	wildcard := validChallenge()
	wildcard.DNSName = "*.example.com"
	wildcard.Key = "wildcard-key-2"

	require.NoError(t, h.solver.Present(apex))
	require.NoError(t, h.solver.Present(wildcard))

	calls := h.client.recorded()
	require.Len(t, calls, 2)
	assert.Equal(t, testRecord, calls[0].record)
	assert.Equal(t, testRecord, calls[1].record)
	assert.Equal(t, "apex-key-1", calls[0].value)
	assert.Equal(t, "wildcard-key-2", calls[1].value)
}

func TestHandleWithoutChallengeRequest(t *testing.T) {
	t.Parallel()

	h := newHarness(t)

	require.ErrorIs(t, h.solver.Present(nil), ErrInvalidChallenge)
	require.ErrorIs(t, h.solver.CleanUp(nil), ErrInvalidChallenge)
	assert.Empty(t, h.client.recorded())
}

func TestPresentBeforeInitialize(t *testing.T) {
	t.Parallel()

	s := New(testDefaults(), discardLogger())

	err := s.Present(validChallenge())

	require.ErrorIs(t, err, ErrNotInitialized)
}

func TestInitialize(t *testing.T) {
	t.Parallel()

	t.Run("without client configuration", func(t *testing.T) {
		t.Parallel()

		err := New(testDefaults(), discardLogger()).Initialize(nil, nil)

		require.ErrorIs(t, err, ErrConfig)
	})

	t.Run("can be called repeatedly", func(t *testing.T) {
		t.Parallel()

		s := New(testDefaults(), discardLogger())
		cfg := &restclient.Config{Host: "https://127.0.0.1:6443"}

		require.NoError(t, s.Initialize(cfg, nil))
		require.NoError(t, s.Initialize(cfg, nil))
		require.NoError(t, s.Initialize(cfg, nil))

		client, err := s.kubeClient()
		require.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("unusable client configuration", func(t *testing.T) {
		t.Parallel()

		// QPS without burst is a self-contradictory configuration.
		err := New(testDefaults(), discardLogger()).Initialize(&restclient.Config{Host: "https://127.0.0.1:6443", QPS: 10}, nil)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "create Kubernetes clientset")
	})
}

func TestPresentConcurrent(t *testing.T) {
	t.Parallel()

	const parallel = 25

	h := newHarness(t)

	var wg sync.WaitGroup
	errs := make([]error, parallel)

	for i := range parallel {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch := validChallenge()
			ch.Key = fmt.Sprintf("key-%02d", i)
			errs[i] = h.solver.Present(ch)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		require.NoErrorf(t, err, "call %d", i)
	}
	assert.Len(t, h.client.recorded(), parallel)
}

func TestErrorsAndLogsNeverContainToken(t *testing.T) {
	t.Parallel()

	const uppercaseToken = "DEADBEEFCAFE1234"

	tests := []struct {
		name    string
		objects []runtime.Object
		mutate  func(*whapi.ChallengeRequest)
		prepare func(*harness)
	}{
		{
			name:    "error of the DDNS client",
			prepare: func(h *harness) { h.client.err = errClient },
		},
		{
			name:    "client cannot be created",
			prepare: func(h *harness) { h.newErr = errors.New("endpoint unusable") },
		},
		{
			name:   "unknown field in the configuration",
			mutate: func(ch *whapi.ChallengeRequest) { ch.Config = rawConfig(`{"tokan": "x"}`) },
		},
		{
			name:    "token with uppercase letters",
			objects: []runtime.Object{newSecret(testSecret, map[string][]byte{"token": []byte(uppercaseToken)})},
		},
		{
			name:    "token of whitespace only",
			objects: []runtime.Object{newSecret(testSecret, map[string][]byte{"token": []byte("   ")})},
		},
		{
			name:    "key missing in secret",
			objects: []runtime.Object{newSecret(testSecret, map[string][]byte{"other": []byte(testToken)})},
		},
		{
			name:    "secret missing",
			objects: []runtime.Object{newSecret("other-secret", map[string][]byte{"token": []byte(testToken)})},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, tt.objects...)
			if tt.prepare != nil {
				tt.prepare(h)
			}

			ch := validChallenge()
			if tt.mutate != nil {
				tt.mutate(ch)
			}

			err := h.solver.Present(ch)
			require.Error(t, err)

			assert.NotContains(t, err.Error(), testToken)
			assert.NotContains(t, err.Error(), uppercaseToken)
			assert.NotContains(t, h.logs.String(), testToken)
			assert.NotContains(t, h.logs.String(), uppercaseToken)
		})
	}
}

func TestSuccessfulRunLogsNoToken(t *testing.T) {
	t.Parallel()

	h := newHarness(t)

	require.NoError(t, h.solver.Present(validChallenge()))
	require.NoError(t, h.solver.CleanUp(validChallenge()))

	logs := h.logs.String()
	assert.NotContains(t, logs, testToken)
	assert.Contains(t, logs, testRecord)
	assert.Contains(t, logs, `"action":"present"`)
	assert.Contains(t, logs, `"action":"cleanup"`)
}

func TestNewDDNSClient(t *testing.T) {
	t.Parallel()

	t.Run("valid configuration", func(t *testing.T) {
		t.Parallel()

		client, err := newDDNSClient(ispconfig.Config{
			Endpoint: "https://ddns.example.net",
			Token:    testToken,
			AuthMode: ispconfig.AuthModeBasic,
			Timeout:  30 * time.Second,
		})

		require.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("error of the client is passed on", func(t *testing.T) {
		t.Parallel()

		client, err := newDDNSClient(ispconfig.Config{})

		require.Error(t, err)
		assert.Nil(t, client)
	})
}

func TestSolverWithoutLoggerUsesDefault(t *testing.T) {
	t.Parallel()

	// New() already sets the logger itself; the fallback in log() only applies when a solver
	// is built as a struct literal.
	s := &Solver{}

	assert.Same(t, slog.Default(), s.log())
}
