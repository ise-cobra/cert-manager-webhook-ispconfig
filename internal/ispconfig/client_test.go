package ispconfig

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

const (
	// testToken is chosen to be distinctive so that a leak in a message stands out.
	testToken  = "deadbeefcafe1234"
	testRecord = "_acme-challenge.example.com"
	testValue  = "abc123"
)

// discardLogger keeps the test output free of log lines.
func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// capturedRequest records what the test server received.
type capturedRequest struct {
	method     string
	path       string
	query      url.Values
	authHeader string
	basicUser  string
	basicPass  string
	basicOK    bool
	cookie     string
}

// captureHandler answers every call with status and body and pushes the request into the
// given channel.
func captureHandler(requests chan<- capturedRequest, status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		requests <- capturedRequest{
			method:     r.Method,
			path:       r.URL.Path,
			query:      r.URL.Query(),
			authHeader: r.Header.Get("Authorization"),
			basicUser:  user,
			basicPass:  pass,
			basicOK:    ok,
			cookie:     r.Header.Get("Cookie"),
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

// newTestClient starts a test server with handler and returns a client pointing to it.
// mutate may adjust the configuration before creation.
func newTestClient(t *testing.T, handler http.Handler, mutate func(*Config)) (*Client, *httptest.Server) {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	cfg := Config{
		Endpoint:              srv.URL,
		Token:                 testToken,
		AllowInsecureEndpoint: true,
		Logger:                discardLogger(),
	}
	if mutate != nil {
		mutate(&cfg)
	}

	client, err := New(cfg)
	require.NoError(t, err)
	return client, srv
}

func TestNewValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		cfg         Config
		wantErr     error
		wantMessage string
	}{
		{name: "https is valid", cfg: Config{Endpoint: "https://ispconfig.example.com", Token: testToken}},
		{name: "base URL with path", cfg: Config{Endpoint: "https://host/ispconfig", Token: testToken}},
		{
			name: "http with opt-in",
			cfg:  Config{Endpoint: "http://localhost:8080", Token: testToken, AllowInsecureEndpoint: true},
		},
		{name: "query mode", cfg: Config{Endpoint: "https://host", Token: testToken, AuthMode: AuthModeQuery}},
		{name: "token with whitespace", cfg: Config{Endpoint: "https://host", Token: "\n" + testToken + "\n "}},
		{
			name:    "empty endpoint",
			cfg:     Config{Endpoint: "", Token: testToken},
			wantErr: ErrInvalidEndpoint,
		},
		{
			name:    "http without opt-in",
			cfg:     Config{Endpoint: "http://host", Token: testToken},
			wantErr: ErrInsecureEndpoint,
		},
		{
			name:    "foreign scheme",
			cfg:     Config{Endpoint: "ftp://host", Token: testToken},
			wantErr: ErrInvalidEndpoint,
		},
		{
			name:    "endpoint without host",
			cfg:     Config{Endpoint: "https://", Token: testToken},
			wantErr: ErrInvalidEndpoint,
		},
		{
			name:    "endpoint not parsable",
			cfg:     Config{Endpoint: "https://host\x7f/", Token: testToken},
			wantErr: ErrInvalidEndpoint,
		},
		{
			name:    "empty token",
			cfg:     Config{Endpoint: "https://host", Token: ""},
			wantErr: ErrInvalidToken,
		},
		{
			name:    "token only whitespace",
			cfg:     Config{Endpoint: "https://host", Token: "  \n"},
			wantErr: ErrInvalidToken,
		},
		{
			name:    "token with uppercase letters",
			cfg:     Config{Endpoint: "https://host", Token: "DEADBEEF"},
			wantErr: ErrInvalidToken,
		},
		{
			name:    "token with special characters",
			cfg:     Config{Endpoint: "https://host", Token: "dead-beef!"},
			wantErr: ErrInvalidToken,
		},
		{
			name:    "token with letters outside a-f",
			cfg:     Config{Endpoint: "https://host", Token: "deadbeefzz"},
			wantErr: ErrInvalidToken,
		},
		{
			name:    "unknown auth mode",
			cfg:     Config{Endpoint: "https://host", Token: testToken, AuthMode: AuthMode("bearer")},
			wantErr: ErrInvalidAuthMode,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client, err := New(tc.cfg)
			if tc.wantErr == nil {
				require.NoError(t, err)
				require.NotNil(t, client)
				return
			}

			require.Error(t, err)
			assert.ErrorIs(t, err, tc.wantErr)
			assert.Nil(t, client)
			// No error may reveal the token value.
			if token := strings.TrimSpace(tc.cfg.Token); token != "" {
				assert.NotContains(t, err.Error(), token)
			}
		})
	}
}

func TestNewTokenErrorHidesValue(t *testing.T) {
	t.Parallel()

	_, err := New(Config{Endpoint: "https://host", Token: "DEADBEEFCAFE1234"})
	require.ErrorIs(t, err, ErrInvalidToken)
	assert.NotContains(t, err.Error(), "DEADBEEFCAFE1234")
	assert.Contains(t, err.Error(), "digits and lowercase letters a-f")
}

func TestNewDefaults(t *testing.T) {
	t.Parallel()

	client, err := New(Config{Endpoint: "https://ispconfig.example.com", Token: testToken})
	require.NoError(t, err)

	assert.Equal(t, AuthModeBasic, client.authMode, "empty auth mode means basic auth")
	assert.Equal(t, defaultTimeout, client.httpClient.Timeout)
	assert.Nil(t, client.httpClient.Jar, "the client must not store cookies")
	assert.Equal(t, "ispconfig.example.com", client.host)
	assert.Equal(t, "https://ispconfig.example.com/ddns/update.php", client.updateURL.String())

	transport, ok := client.httpClient.Transport.(*http.Transport)
	require.True(t, ok, "the client uses the shared, derived transport")
	require.NotNil(t, transport.TLSClientConfig)
	assert.Equal(t, uint16(tls.VersionTLS12), transport.TLSClientConfig.MinVersion)
	// Inherited from the cloned default transport: without Proxy, HTTPS_PROXY/NO_PROXY would be
	// ignored, without idle timeout connections would stay open indefinitely.
	assert.NotNil(t, transport.Proxy, "the transport must honor the proxy environment")
	assert.Positive(t, transport.IdleConnTimeout, "idle connections need a timeout")
}

func TestNewTimeoutOverride(t *testing.T) {
	t.Parallel()

	client, err := New(Config{Endpoint: "https://host", Token: testToken, Timeout: 5 * time.Second})
	require.NoError(t, err)
	assert.Equal(t, 5*time.Second, client.httpClient.Timeout)
}

func TestAddTXTRecordRequest(t *testing.T) {
	t.Parallel()

	requests := make(chan capturedRequest, 1)
	client, _ := newTestClient(t,
		captureHandler(requests, http.StatusOK,
			"Scheduled update to 'abc123' of record _acme-challenge.example.com. Schedule runs in 42 seconds. Record TTL: 3600."),
		nil)

	outcome, err := client.AddTXTRecord(t.Context(), testRecord, testValue)
	require.NoError(t, err)
	assert.Equal(t, OutcomeChanged, outcome)

	got := <-requests
	assert.Equal(t, http.MethodPost, got.method, "add is sent as POST")
	assert.Equal(t, "/ddns/update.php", got.path)
	assert.Equal(t, "add", got.query.Get("action"))
	assert.Equal(t, "TXT", got.query.Get("type"))
	assert.Equal(t, testRecord, got.query.Get("record"))
	assert.Equal(t, testValue, got.query.Get("data"))
	assert.False(t, got.query.Has("zone"), "zone must not be sent")
	assert.False(t, got.query.Has("ttl"), "the remote side does not know ttl")
	assert.False(t, got.query.Has("token"), "in basic mode the token is not in the query")
	assert.True(t, got.basicOK, "the Authorization header is missing")
	assert.Equal(t, basicAuthUser, got.basicUser)
	assert.Equal(t, testToken, got.basicPass)
}

func TestDeleteTXTRecordRequest(t *testing.T) {
	t.Parallel()

	requests := make(chan capturedRequest, 1)
	client, _ := newTestClient(t,
		captureHandler(requests, http.StatusOK,
			"Scheduled delete of record _acme-challenge.example.com. Schedule runs in 42 seconds. Record TTL: 3600."),
		nil)

	outcome, err := client.DeleteTXTRecord(t.Context(), testRecord, testValue)
	require.NoError(t, err)
	assert.Equal(t, OutcomeChanged, outcome)

	got := <-requests
	assert.Equal(t, http.MethodDelete, got.method, "delete is sent as DELETE")
	assert.Equal(t, "/ddns/update.php", got.path)
	assert.Equal(t, "delete", got.query.Get("action"))
	assert.Equal(t, "TXT", got.query.Get("type"))
	assert.Equal(t, testRecord, got.query.Get("record"))
	assert.Equal(t, testValue, got.query.Get("data"))
	assert.False(t, got.query.Has("zone"))
	assert.False(t, got.query.Has("ttl"))
}

func TestQueryAuthMode(t *testing.T) {
	t.Parallel()

	requests := make(chan capturedRequest, 1)
	client, _ := newTestClient(t, captureHandler(requests, http.StatusOK, "Scheduled update to 'abc123'."),
		func(cfg *Config) { cfg.AuthMode = AuthModeQuery })

	_, err := client.AddTXTRecord(t.Context(), testRecord, testValue)
	require.NoError(t, err)

	got := <-requests
	assert.Equal(t, testToken, got.query.Get("token"), "in query mode the token is in the query")
	assert.Empty(t, got.authHeader, "in query mode no Authorization header is sent")
}

func TestEndpointWithPathIsPreserved(t *testing.T) {
	t.Parallel()

	requests := make(chan capturedRequest, 1)
	client, srv := newTestClient(t, captureHandler(requests, http.StatusOK, "Scheduled update to 'abc123'."), nil)

	// The path component of the base URL must not be dropped.
	withPath, err := New(Config{
		Endpoint:              srv.URL + "/ispconfig",
		Token:                 testToken,
		AllowInsecureEndpoint: true,
		Logger:                discardLogger(),
	})
	require.NoError(t, err)
	require.NotNil(t, client)

	_, err = withPath.AddTXTRecord(t.Context(), testRecord, testValue)
	require.NoError(t, err)

	got := <-requests
	assert.Equal(t, "/ispconfig/ddns/update.php", got.path)
}

func TestResponseHandling(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		action      Action
		status      int
		body        string
		wantOutcome Outcome
		wantErr     error
		wantInMsg   []string
	}{
		{
			name:        "add successful",
			action:      ActionAdd,
			status:      http.StatusOK,
			body:        "Scheduled update to 'abc123' of record _acme-challenge.example.com. Schedule runs in 42 seconds. Record TTL: 3600.\n",
			wantOutcome: OutcomeChanged,
		},
		{
			name:        "add already present",
			action:      ActionAdd,
			status:      http.StatusOK,
			body:        "ERROR: abc123 is already set in _acme-challenge.example.com.\n",
			wantOutcome: OutcomeUnchanged,
		},
		{
			name:        "delete successful",
			action:      ActionDelete,
			status:      http.StatusOK,
			body:        "Scheduled delete of record _acme-challenge.example.com. Schedule runs in 42 seconds. Record TTL: 3600.\n",
			wantOutcome: OutcomeChanged,
		},
		{
			name:        "delete not required",
			action:      ActionDelete,
			status:      http.StatusOK,
			body:        "ERROR: _acme-challenge.example.com does not exit.\n",
			wantOutcome: OutcomeUnchanged,
		},
		{
			name:      "delete on missing record",
			action:    ActionDelete,
			status:    http.StatusNotFound,
			body:      "Could not find record '_acme-challenge.example.com' of type 'TXT' in zone 'example.com.'",
			wantErr:   ErrRecordNotFound,
			wantInMsg: []string{"404", "Could not find record"},
		},
		{
			name:      "invalid token",
			action:    ActionAdd,
			status:    http.StatusUnauthorized,
			body:      "Missing or invalid token.",
			wantErr:   ErrUnauthorized,
			wantInMsg: []string{"401", "Missing or invalid token."},
		},
		{
			name:      "missing permission",
			action:    ActionAdd,
			status:    http.StatusForbidden,
			body:      "Permission denied for record type TXT",
			wantErr:   ErrForbidden,
			wantInMsg: []string{"403", "Permission denied for record type TXT"},
		},
		{
			name:      "missing input",
			action:    ActionAdd,
			status:    http.StatusBadRequest,
			body:      "Invalid Data: maximum 255 characters",
			wantErr:   ErrUnexpectedStatus,
			wantInMsg: []string{"400", "Invalid Data: maximum 255 characters"},
		},
		{
			name:      "too many requests",
			action:    ActionAdd,
			status:    http.StatusTooManyRequests,
			body:      "Too many login attempts.",
			wantErr:   ErrRateLimited,
			wantInMsg: []string{"429"},
		},
		{
			name:      "maintenance",
			action:    ActionAdd,
			status:    http.StatusInternalServerError,
			body:      "This ISPConfig installation is currently under maintenance.",
			wantErr:   ErrUnexpectedStatus,
			wantInMsg: []string{"500", "under maintenance"},
		},
		{
			name:      "server error with empty body",
			action:    ActionAdd,
			status:    http.StatusInternalServerError,
			body:      "",
			wantErr:   ErrUnexpectedStatus,
			wantInMsg: []string{"500", "empty response body"},
		},
		{
			name:      "add on unknown zone",
			action:    ActionAdd,
			status:    http.StatusNotFound,
			body:      "Could not find zone 'example.com'",
			wantErr:   ErrUnexpectedStatus,
			wantInMsg: []string{"404", "Could not find zone"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			requests := make(chan capturedRequest, 1)
			client, _ := newTestClient(t, captureHandler(requests, tc.status, tc.body), nil)

			var (
				outcome Outcome
				err     error
			)
			if tc.action == ActionAdd {
				outcome, err = client.AddTXTRecord(t.Context(), testRecord, testValue)
			} else {
				outcome, err = client.DeleteTXTRecord(t.Context(), testRecord, testValue)
			}

			if tc.wantErr == nil {
				require.NoError(t, err)
				assert.Equal(t, tc.wantOutcome, outcome)
				return
			}

			require.Error(t, err)
			assert.ErrorIs(t, err, tc.wantErr)
			for _, want := range tc.wantInMsg {
				assert.Contains(t, err.Error(), want)
			}

			var apiErr *APIError
			require.ErrorAs(t, err, &apiErr)
			assert.Equal(t, tc.status, apiErr.StatusCode)
			assert.Equal(t, tc.action, apiErr.Action)
		})
	}
}

func TestResponseBodyIsTruncatedInError(t *testing.T) {
	t.Parallel()

	// Much longer than the snippet, but below the read cap.
	longBody := strings.Repeat("x", 4000)
	requests := make(chan capturedRequest, 1)
	client, _ := newTestClient(t, captureHandler(requests, http.StatusInternalServerError, longBody), nil)

	_, err := client.AddTXTRecord(t.Context(), testRecord, testValue)
	require.Error(t, err)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, strings.Repeat("x", maxBodySnippetLength)+"...", apiErr.Body)
	assert.NotContains(t, err.Error(), strings.Repeat("x", maxBodySnippetLength+1))
}

func TestValueValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   string
		wantErr error
	}{
		{name: "empty value", value: "", wantErr: ErrInvalidValue},
		{name: "255 characters are allowed", value: strings.Repeat("a", maxTXTValueLength)},
		{name: "256 characters are too long", value: strings.Repeat("a", maxTXTValueLength+1), wantErr: ErrInvalidValue},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			requests := make(chan capturedRequest, 1)
			client, _ := newTestClient(t, captureHandler(requests, http.StatusOK, "Scheduled update to '...'."), nil)

			_, err := client.AddTXTRecord(t.Context(), testRecord, tc.value)
			if tc.wantErr == nil {
				require.NoError(t, err)
				assert.Equal(t, tc.value, (<-requests).query.Get("data"), "the value is sent unchanged")
				return
			}

			require.ErrorIs(t, err, tc.wantErr)
			assert.Empty(t, requests, "invalid input must not trigger a request")
		})
	}
}

func TestValueIsSentWithoutQuotes(t *testing.T) {
	t.Parallel()

	requests := make(chan capturedRequest, 1)
	client, _ := newTestClient(t, captureHandler(requests, http.StatusOK, "Scheduled update to '...'."), nil)

	value := "gfj9Xq...Rg85nM"
	_, err := client.AddTXTRecord(t.Context(), testRecord, value)
	require.NoError(t, err)
	assert.Equal(t, value, (<-requests).query.Get("data"))
}

func TestRecordValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		record  string
		wantErr error
	}{
		{name: "without trailing dot", record: testRecord},
		{name: "empty record", record: "", wantErr: ErrInvalidRecord},
		{name: "trailing dot", record: testRecord + ".", wantErr: ErrInvalidRecord},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			requests := make(chan capturedRequest, 1)
			client, _ := newTestClient(t, captureHandler(requests, http.StatusOK, "Scheduled update to '...'."), nil)

			_, err := client.AddTXTRecord(t.Context(), tc.record, testValue)
			if tc.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tc.wantErr)
			assert.Empty(t, requests, "invalid input must not trigger a request")
		})
	}
}

func TestTimeoutAborts(t *testing.T) {
	t.Parallel()

	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-block
	}))
	// Release the handler first, then close the server — Close waits for open requests.
	defer srv.Close()
	defer close(block)

	client, err := New(Config{
		Endpoint:              srv.URL,
		Token:                 testToken,
		AllowInsecureEndpoint: true,
		Timeout:               time.Millisecond,
		Logger:                discardLogger(),
	})
	require.NoError(t, err)

	_, err = client.AddTXTRecord(t.Context(), testRecord, testValue)
	require.Error(t, err)

	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	assert.True(t, netErr.Timeout(), "expected a timeout error, got: %v", err)
}

func TestTimeoutDoesNotLeakToken(t *testing.T) {
	t.Parallel()

	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-block
	}))
	defer srv.Close()
	defer close(block)

	client, err := New(Config{
		Endpoint:              srv.URL,
		Token:                 testToken,
		AuthMode:              AuthModeQuery,
		AllowInsecureEndpoint: true,
		Timeout:               time.Millisecond,
		Logger:                discardLogger(),
	})
	require.NoError(t, err)

	_, err = client.AddTXTRecord(t.Context(), testRecord, testValue)
	require.Error(t, err)
	assertNoRequestURL(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded, "the cause stays inspectable")
}

func TestTransportErrorDoesNotLeakToken(t *testing.T) {
	t.Parallel()

	// The server is closed immediately: connecting fails, and net/http puts the full URL —
	// including the token in query mode — into a *url.Error.
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	endpoint := srv.URL
	srv.Close()

	client, err := New(Config{
		Endpoint:              endpoint,
		Token:                 testToken,
		AuthMode:              AuthModeQuery,
		AllowInsecureEndpoint: true,
		Logger:                discardLogger(),
	})
	require.NoError(t, err)

	_, err = client.AddTXTRecord(t.Context(), testRecord, testValue)
	require.Error(t, err)
	assertNoRequestURL(t, err)
}

func TestTransportErrorInBasicModeKeepsOriginalError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	endpoint := srv.URL
	srv.Close()

	client, err := New(Config{
		Endpoint:              endpoint,
		Token:                 testToken,
		AllowInsecureEndpoint: true,
		Logger:                discardLogger(),
	})
	require.NoError(t, err)

	_, err = client.DeleteTXTRecord(t.Context(), testRecord, testValue)
	require.Error(t, err)
	assertNoRequestURL(t, err)

	// The cause stays inspectable for the caller — only the *url.Error with its URL field is
	// removed from the chain.
	var netErr net.Error
	assert.ErrorAs(t, err, &netErr, "the network error stays inspectable")
}

// assertNoRequestURL checks the guarantee that neither token nor request URL appear in the
// message, and that errors.As hands out no *url.Error whose URL field would carry both.
func assertNoRequestURL(t *testing.T, err error) {
	t.Helper()

	assert.NotContains(t, err.Error(), testToken, "the token value must not appear in the message")
	assert.NotContains(t, err.Error(), ddnsPath, "the request URL must not appear in the message")
	assert.NotContains(t, err.Error(), "?", "no query string in the message")

	var urlErr *url.Error
	assert.NotErrorAs(t, err, &urlErr, "a *url.Error would hand out the URL despite the redacted message")
}

func TestContextCancelAborts(t *testing.T) {
	t.Parallel()

	reached := make(chan struct{})
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		close(reached)
		<-block
	}))
	defer srv.Close()
	defer close(block)

	client, err := New(Config{
		Endpoint:              srv.URL,
		Token:                 testToken,
		AllowInsecureEndpoint: true,
		Logger:                discardLogger(),
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		<-reached
		cancel()
	}()

	_, err = client.AddTXTRecord(ctx, testRecord, testValue)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestNoRetryOnServerError(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	srv := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Something went wrong."))
	})
	client, _ := newTestClient(t, srv, nil)

	_, err := client.AddTXTRecord(t.Context(), testRecord, testValue)
	require.Error(t, err)
	assert.Equal(t, int64(1), calls.Load(), "the client does not retry a failed call")
}

func TestRedirectIsNotFollowed(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	})
	client, _ := newTestClient(t, handler, nil)

	_, err := client.AddTXTRecord(t.Context(), testRecord, testValue)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnexpectedStatus)
	assert.Contains(t, err.Error(), "302")
	assert.Equal(t, int64(1), calls.Load(), "a redirect is not followed")
}

func TestCookiesAreNotReturned(t *testing.T) {
	t.Parallel()

	requests := make(chan capturedRequest, 2)
	handler := func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name: "ISPCSESS", Value: "abcdef",
			HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
		})
		captureHandler(requests, http.StatusOK, "Scheduled update to '...'.")(w, r)
	}
	client, _ := newTestClient(t, http.HandlerFunc(handler), nil)

	_, err := client.AddTXTRecord(t.Context(), testRecord, testValue)
	require.NoError(t, err)
	_, err = client.AddTXTRecord(t.Context(), testRecord, testValue)
	require.NoError(t, err)

	assert.Empty(t, (<-requests).cookie)
	assert.Empty(t, (<-requests).cookie, "the second call must not send back a session cookie")
}

func TestEvaluateResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		action      Action
		status      int
		body        string
		wantOutcome Outcome
		wantErr     error
	}{
		{
			name: "404 on delete", action: ActionDelete, status: http.StatusNotFound,
			body: "Could not find record '...'", wantErr: ErrRecordNotFound,
		},
		{
			name: "404 on add", action: ActionAdd, status: http.StatusNotFound,
			body: "Could not find zone '...'", wantErr: ErrUnexpectedStatus,
		},
		{
			name: "200 with ERROR prefix", action: ActionAdd, status: http.StatusOK,
			body: "ERROR: abc is already set in x.", wantOutcome: OutcomeUnchanged,
		},
		{
			name: "200 with ERROR prefix after whitespace", action: ActionAdd, status: http.StatusOK,
			body: "\n\t  ERROR: abc is already set in x.", wantOutcome: OutcomeUnchanged,
		},
		{
			name: "200 with ERROR in the middle of the text", action: ActionAdd, status: http.StatusOK,
			body: "Scheduled update to 'ERROR: nope'.", wantOutcome: OutcomeChanged,
		},
		{
			name: "200 with success text", action: ActionAdd, status: http.StatusOK,
			body: "Scheduled update to '...'.", wantOutcome: OutcomeChanged,
		},
		{
			name: "204 counts as success", action: ActionDelete, status: http.StatusNoContent,
			body: "", wantOutcome: OutcomeChanged,
		},
		{
			name: "empty body on 200", action: ActionAdd, status: http.StatusOK,
			body: "", wantOutcome: OutcomeChanged,
		},
		{
			name: "301 is not a success", action: ActionAdd, status: http.StatusMovedPermanently,
			body: "moved", wantErr: ErrUnexpectedStatus,
		},
		{name: "401", action: ActionAdd, status: http.StatusUnauthorized, body: "x", wantErr: ErrUnauthorized},
		{name: "403", action: ActionAdd, status: http.StatusForbidden, body: "x", wantErr: ErrForbidden},
		{name: "400", action: ActionAdd, status: http.StatusBadRequest, body: "x", wantErr: ErrUnexpectedStatus},
		{name: "429", action: ActionAdd, status: http.StatusTooManyRequests, body: "x", wantErr: ErrRateLimited},
		{name: "500", action: ActionAdd, status: http.StatusInternalServerError, body: "x", wantErr: ErrUnexpectedStatus},
		{
			name: "500 with empty body", action: ActionAdd, status: http.StatusInternalServerError,
			body: "", wantErr: ErrUnexpectedStatus,
		},
		{
			name: "401 on delete", action: ActionDelete, status: http.StatusUnauthorized,
			body: "Missing or invalid token.", wantErr: ErrUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			outcome, err := evaluateResponse(tc.action, tc.status, tc.body)
			if tc.wantErr == nil {
				require.NoError(t, err)
				assert.Equal(t, tc.wantOutcome, outcome)
				return
			}
			require.Error(t, err)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestTruncateBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "empty", body: "", want: ""},
		{name: "only whitespace", body: "  \n\t", want: ""},
		{name: "whitespace is removed", body: "  Scheduled update.\n", want: "Scheduled update."},
		{
			name: "limit length stays complete",
			body: strings.Repeat("a", maxBodySnippetLength),
			want: strings.Repeat("a", maxBodySnippetLength),
		},
		{
			name: "one character too long is truncated",
			body: strings.Repeat("a", maxBodySnippetLength+1),
			want: strings.Repeat("a", maxBodySnippetLength) + "...",
		},
		{
			name: "multi-byte characters are not cut",
			body: strings.Repeat("é", maxBodySnippetLength+10),
			want: strings.Repeat("é", maxBodySnippetLength) + "...",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, truncateBody(tc.body))
		})
	}
}

func TestOutcomeString(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "changed", OutcomeChanged.String())
	assert.Equal(t, "unchanged", OutcomeUnchanged.String())
	assert.Equal(t, "unknown", Outcome(42).String())
}

func TestActionMethod(t *testing.T) {
	t.Parallel()

	assert.Equal(t, http.MethodPost, ActionAdd.method())
	assert.Equal(t, http.MethodDelete, ActionDelete.method())
}

func TestConfigLogValueRedactsToken(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	cfg := Config{
		Endpoint: "https://ispconfig.example.com",
		Token:    testToken,
		AuthMode: AuthModeQuery,
		Timeout:  30 * time.Second,
	}
	logger.Info("configuration", "config", cfg)

	line := buf.String()
	assert.NotContains(t, line, testToken, "the token must not appear in the log line")
	assert.Contains(t, line, RedactedPlaceholder)
	assert.Contains(t, line, "ispconfig.example.com")
}

func TestLogLinesOmitFullURL(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	requests := make(chan capturedRequest, 1)
	client, srv := newTestClient(t, captureHandler(requests, http.StatusOK, "Scheduled update to '...'."),
		func(cfg *Config) {
			cfg.AuthMode = AuthModeQuery
			cfg.Logger = logger
		})

	_, err := client.AddTXTRecord(t.Context(), testRecord, testValue)
	require.NoError(t, err)

	line := buf.String()
	assert.NotContains(t, line, testToken)
	assert.NotContains(t, line, srv.URL+"/ddns/update.php", "the full URL does not belong in the log")
	assert.Contains(t, line, "ddns_action=add")
	assert.Contains(t, line, testRecord)
	assert.Contains(t, line, "DDNS API response body", "the response body is logged at debug")
}

// countingBody yields up to remaining bytes and counts how many of them were read.
type countingBody struct {
	remaining int
	read      int
}

func (b *countingBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		return 0, io.EOF
	}
	n := min(len(p), b.remaining)
	for i := range n {
		p[i] = 'x'
	}
	b.remaining -= n
	b.read += n
	return n, nil
}

func (b *countingBody) Close() error { return nil }

// stubRoundTripper returns a fixed response without involving a server.
type stubRoundTripper struct {
	status int
	body   io.ReadCloser
}

func (rt stubRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: rt.status,
		Status:     http.StatusText(rt.status),
		Body:       rt.body,
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// telemetryHarness registers fresh OTel providers for traces and metrics and restores the
// previous ones in t.Cleanup. The global providers apply process-wide: tests using this helper
// must not use t.Parallel(). The client must be created AFTER the call, otherwise tracer and
// metric instruments are attached to the no-op provider.
func telemetryHarness(t *testing.T) (*tracetest.SpanRecorder, *sdkmetric.ManualReader) {
	t.Helper()

	recorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

	prevTracerProvider := otel.GetTracerProvider()
	prevMeterProvider := otel.GetMeterProvider()
	otel.SetTracerProvider(tracerProvider)
	otel.SetMeterProvider(meterProvider)
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTracerProvider)
		otel.SetMeterProvider(prevMeterProvider)
	})

	return recorder, reader
}

// forEachDataPoint calls fn for every data point of the collected metrics.
func forEachDataPoint(t *testing.T, rm metricdata.ResourceMetrics, fn func(name string, attrs attribute.Set)) {
	t.Helper()

	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			switch data := m.Data.(type) {
			case metricdata.Sum[int64]:
				for _, point := range data.DataPoints {
					fn(m.Name, point.Attributes)
				}
			case metricdata.Histogram[float64]:
				for _, point := range data.DataPoints {
					fn(m.Name, point.Attributes)
				}
			default:
				t.Fatalf("unexpected metric type %T for %s", m.Data, m.Name)
			}
		}
	}
}

// assertNoSensitiveValue ensures that a telemetry value contains neither token nor record name
// nor record value.
func assertNoSensitiveValue(t *testing.T, value string) {
	t.Helper()

	assert.NotContains(t, value, testToken, "no token in telemetry attributes")
	assert.NotContains(t, value, testRecord, "no record name in telemetry attributes")
	assert.NotContains(t, value, testValue, "no record value in telemetry attributes")
}

// assertOutcome checks the outcome attribute of all data points.
func assertOutcome(t *testing.T, reader *sdkmetric.ManualReader, want string) {
	t.Helper()

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &rm))

	points := 0
	forEachDataPoint(t, rm, func(_ string, attrs attribute.Set) {
		points++
		value, ok := attrs.Value(attrOutcome)
		require.True(t, ok, "the outcome attribute is missing")
		assert.Equal(t, want, value.AsString())
	})
	assert.Equal(t, 2, points, "counter and histogram yield one data point each")
}

func TestNewTransportClonesDefaultTransport(t *testing.T) {
	t.Parallel()

	transport := newTransport()
	assert.NotNil(t, transport.Proxy, "must be inherited from http.DefaultTransport")
	assert.Positive(t, transport.IdleConnTimeout, "must be inherited from http.DefaultTransport")
	require.NotNil(t, transport.TLSClientConfig)
	assert.Equal(t, uint16(tls.VersionTLS12), transport.TLSClientConfig.MinVersion)
}

func TestErrorBodyRedactsToken(t *testing.T) {
	t.Parallel()

	// A reverse proxy mirrors the request URI in its error page; in query mode the token thus
	// appears in the response body — and from there in the APIError, the log and the span.
	const diagnostic = "Permission denied for record _acme-challenge"
	body := "The requested URL /ddns/update.php?token=" + testToken + " was rejected. " + diagnostic

	for _, mode := range []AuthMode{AuthModeQuery, AuthModeBasic} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			requests := make(chan capturedRequest, 1)
			client, _ := newTestClient(t, captureHandler(requests, http.StatusForbidden, body),
				func(cfg *Config) {
					cfg.AuthMode = mode
					cfg.Logger = logger
				})

			_, err := client.AddTXTRecord(t.Context(), testRecord, testValue)
			require.ErrorIs(t, err, ErrForbidden)
			assert.NotContains(t, err.Error(), testToken, "the response body must not carry the token")
			assert.Contains(t, err.Error(), RedactedPlaceholder)
			assert.Contains(t, err.Error(), diagnostic, "the remaining diagnostic text is kept")

			var apiErr *APIError
			require.ErrorAs(t, err, &apiErr)
			assert.NotContains(t, apiErr.Body, testToken)

			logged := buf.String()
			assert.NotContains(t, logged, testToken, "warn and debug fields do not carry the token either")
			assert.Contains(t, logged, RedactedPlaceholder)
			assert.Contains(t, logged, diagnostic)
		})
	}
}

func TestResponseReadIsCapped(t *testing.T) {
	t.Parallel()

	// The read cap is not observable from the outside — the test server writes its body
	// regardless of how much the client reads. Hence white-box: a counting body at the
	// transport measures how many bytes the client actually touches.
	body := &countingBody{remaining: 20000}
	client, err := New(Config{Endpoint: "https://ispconfig.example.com", Token: testToken, Logger: discardLogger()})
	require.NoError(t, err)
	client.httpClient.Transport = stubRoundTripper{status: http.StatusInternalServerError, body: body}

	_, err = client.AddTXTRecord(t.Context(), testRecord, testValue)
	require.Error(t, err)
	assert.Equal(t, maxResponseBytes, body.read, "the client reads at most maxResponseBytes")

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, strings.Repeat("x", maxBodySnippetLength)+"...", apiErr.Body)
}

// TestSpanErrorEventOmitsResponseBody covers that span.RecordError exports only the error
// class. On 403, the remote side's response body names the record name, which would end up in
// the tracing backend via exception.message.
func TestSpanErrorEventOmitsResponseBody(t *testing.T) {
	// No t.Parallel(): telemetryHarness sets process-wide providers.
	recorder, _ := telemetryHarness(t)

	body := "Permission denied for record " + testRecord
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(body))
	}), nil)

	_, err := client.AddTXTRecord(t.Context(), testRecord, testValue)
	require.ErrorIs(t, err, ErrForbidden)
	assert.Contains(t, err.Error(), testRecord, "the error returned to cert-manager stays diagnosable")

	spans := recorder.Ended()
	require.Len(t, spans, 1)

	events := spans[0].Events()
	require.NotEmpty(t, events, "RecordError leaves an event")
	for _, event := range events {
		for _, attr := range event.Attributes {
			assertNoSensitiveValue(t, attr.Value.String())
		}
	}
}

// TestTruncatedResponseCannotLeakSplitToken pins the boundary that protects query mode:
// io.LimitReader cuts at a byte boundary and can split the token, after which the text
// replacement in redactString no longer finds it. The guarantee rests solely on
// maxBodySnippetLength (512) being far below maxResponseBytes (8192) — the cut area reaches no
// output. If the ratio is reversed, this test fails.
func TestTruncatedResponseCannotLeakSplitToken(t *testing.T) {
	t.Parallel()

	const keptPrefixLen = 12
	prefix := strings.Repeat("x", maxResponseBytes-keptPrefixLen)

	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		// An error page that mirrors the request URI. The token starts such that exactly
		// keptPrefixLen of its characters are still within the read limit.
		_, _ = w.Write([]byte(prefix + testToken + strings.Repeat("y", maxResponseBytes)))
	}), func(cfg *Config) {
		cfg.AuthMode = AuthModeQuery
	})

	_, err := client.AddTXTRecord(t.Context(), testRecord, testValue)
	require.Error(t, err)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.NotContains(t, apiErr.Body, testToken[:keptPrefixLen],
		"not even a truncated token prefix may appear in the response body")
	assert.NotContains(t, err.Error(), testToken[:keptPrefixLen])
}

func TestSpanAndMetricAttributesOmitSensitiveData(t *testing.T) {
	// No t.Parallel(): telemetryHarness sets process-wide providers.
	recorder, reader := telemetryHarness(t)

	requests := make(chan capturedRequest, 1)
	client, _ := newTestClient(t,
		captureHandler(requests, http.StatusOK, "Scheduled update to 'abc123' of record _acme-challenge.example.com."),
		nil)

	_, err := client.AddTXTRecord(t.Context(), testRecord, testValue)
	require.NoError(t, err)

	spans := recorder.Ended()
	require.Len(t, spans, 1)
	assert.Equal(t, "ispconfig.ddns.add", spans[0].Name())

	spanKeys := make([]string, 0, len(spans[0].Attributes()))
	for _, attr := range spans[0].Attributes() {
		spanKeys = append(spanKeys, string(attr.Key))
		assertNoSensitiveValue(t, attr.Value.String())
	}
	assert.ElementsMatch(t, []string{attrAction, attrStatusCode}, spanKeys,
		"the span carries only action and HTTP status")

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &rm))

	seen := map[string]int{}
	forEachDataPoint(t, rm, func(name string, attrs attribute.Set) {
		seen[name]++
		metricKeys := make([]string, 0, attrs.Len())
		for _, attr := range attrs.ToSlice() {
			metricKeys = append(metricKeys, string(attr.Key))
			assertNoSensitiveValue(t, attr.Value.String())
		}
		assert.ElementsMatch(t, []string{attrAction, attrOutcome}, metricKeys,
			"the metric carries only action and outcome")
	})
	assert.Equal(t, 1, seen["ispconfig.ddns.requests"])
	assert.Equal(t, 1, seen["ispconfig.ddns.request.duration"])
}

func TestReportingDistinguishesExpectedFromRealError(t *testing.T) {
	// No t.Parallel(): telemetryHarness sets process-wide providers.
	tests := []struct {
		name        string
		status      int
		body        string
		wantOutcome string
		realError   bool
	}{
		{
			name:        "404 on delete is the target state",
			status:      http.StatusNotFound,
			body:        "Could not find record '_acme-challenge' of type 'TXT' in zone 'example.com'",
			wantOutcome: outcomeNotFound,
		},
		{
			name:        "403 stays a real error",
			status:      http.StatusForbidden,
			body:        "Permission denied for record _acme-challenge",
			wantOutcome: outcomeError,
			realError:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// No t.Parallel(): see above.
			recorder, reader := telemetryHarness(t)

			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			requests := make(chan capturedRequest, 1)
			client, _ := newTestClient(t, captureHandler(requests, tc.status, tc.body),
				func(cfg *Config) { cfg.Logger = logger })

			_, err := client.DeleteTXTRecord(t.Context(), testRecord, testValue)
			require.Error(t, err, "the error value stays the return value in both cases")

			spans := recorder.Ended()
			require.Len(t, spans, 1)
			logged := buf.String()

			if tc.realError {
				assert.Contains(t, logged, `"level":"ERROR"`)
				assert.Equal(t, codes.Error, spans[0].Status().Code)
				assert.NotEmpty(t, spans[0].Events(), "RecordError leaves an event")
			} else {
				require.ErrorIs(t, err, ErrRecordNotFound, "the solver still distinguishes by sentinel")
				assert.NotContains(t, logged, `"level":"ERROR"`, "the success case produces no ERROR line")
				assert.Contains(t, logged, "target state reached")
				assert.NotEqual(t, codes.Error, spans[0].Status().Code, "the span stays ok")
				assert.Empty(t, spans[0].Events(), "RecordError is omitted")
			}
			assertOutcome(t, reader, tc.wantOutcome)
		})
	}
}

// TestClientsShareTransport proves that two clients use the same transport and thus the same
// connection pool. The solver creates a new client per challenge — with one transport per
// client, every challenge would pay for a full TLS handshake, and the then unused connections
// would linger until IdleConnTimeout.
func TestClientsShareTransport(t *testing.T) {
	t.Parallel()

	first, err := New(Config{Endpoint: "https://ispconfig.example.com", Token: testToken, Logger: discardLogger()})
	require.NoError(t, err)
	second, err := New(Config{Endpoint: "https://other.example.net", Token: testToken, Logger: discardLogger()})
	require.NoError(t, err)

	assert.Same(t, first.httpClient.Transport, second.httpClient.Transport,
		"all clients share one transport, otherwise each has an empty connection pool")
	assert.NotSame(t, first.httpClient, second.httpClient,
		"timeout and CheckRedirect stay per client")
}
