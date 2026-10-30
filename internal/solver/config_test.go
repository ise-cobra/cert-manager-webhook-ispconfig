package solver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/ispconfig"
)

// rawConfig wraps a JSON text as the config block of an issuer.
func rawConfig(s string) *apiextensionsv1.JSON {
	return &apiextensionsv1.JSON{Raw: []byte(s)}
}

// testDefaults are the default values as the service sets them at startup.
func testDefaults() Defaults {
	return Defaults{
		Endpoint:    "https://ispconfig.example.com",
		HTTPTimeout: 30 * time.Second,
	}
}

func TestParseConfig(t *testing.T) {
	t.Parallel()

	insecureDefaults := testDefaults()
	insecureDefaults.AllowInsecureEndpoint = true

	tests := []struct {
		name     string
		raw      *apiextensionsv1.JSON
		defaults Defaults
		want     challengeConfig
		wantErr  []string
		// wantIs is checked in addition to ErrConfig for errors from internal/ispconfig, so
		// the test does not depend on the wording of another package.
		wantIs error
	}{
		{
			name: "complete configuration",
			raw: rawConfig(`{
				"endpoint": "https://ddns.example.net",
				"tokenSecretRef": {"name": "ispconfig-ddns-token", "key": "ddns-token"},
				"httpTimeout": "45s",
				"tokenAuthMode": "query"
			}`),
			defaults: testDefaults(),
			want: challengeConfig{
				endpoint:       "https://ddns.example.net",
				tokenSecretRef: secretKeySelector{Name: "ispconfig-ddns-token", Key: "ddns-token"},
				httpTimeout:    45 * time.Second,
				tokenAuthMode:  ispconfig.AuthModeQuery,
			},
		},
		{
			name:     "unknown field is named",
			raw:      rawConfig(`{"tokenSecretRef": {"name": "s"}, "endpointt": "https://x.example"}`),
			defaults: testDefaults(),
			wantErr:  []string{"unknown field", "endpointt"},
		},
		{
			name:     "no config block",
			raw:      nil,
			defaults: testDefaults(),
			wantErr:  []string{"tokenSecretRef"},
		},
		{
			name:     "empty config block",
			raw:      rawConfig(``),
			defaults: testDefaults(),
			wantErr:  []string{"tokenSecretRef"},
		},
		{
			name:     "not a JSON object",
			raw:      rawConfig(`["nope"]`),
			defaults: testDefaults(),
			wantErr:  []string{"cannot parse config block"},
		},
		{
			name:     "default endpoint, default timeout, default key, default auth mode",
			raw:      rawConfig(`{"tokenSecretRef": {"name": "ispconfig-ddns-token"}}`),
			defaults: testDefaults(),
			want: challengeConfig{
				endpoint:       "https://ispconfig.example.com",
				tokenSecretRef: secretKeySelector{Name: "ispconfig-ddns-token", Key: "token"},
				httpTimeout:    30 * time.Second,
				tokenAuthMode:  ispconfig.AuthModeBasic,
			},
		},
		{
			name:     "endpoint overrides default",
			raw:      rawConfig(`{"endpoint": "https://ddns.example.net", "tokenSecretRef": {"name": "s"}}`),
			defaults: testDefaults(),
			want: challengeConfig{
				endpoint:       "https://ddns.example.net",
				tokenSecretRef: secretKeySelector{Name: "s", Key: "token"},
				httpTimeout:    30 * time.Second,
				tokenAuthMode:  ispconfig.AuthModeBasic,
			},
		},
		{
			name:     "http is rejected",
			raw:      rawConfig(`{"endpoint": "http://ddns.example.net", "tokenSecretRef": {"name": "s"}}`),
			defaults: testDefaults(),
			wantErr:  []string{"http://ddns.example.net"},
			wantIs:   ispconfig.ErrInsecureEndpoint,
		},
		{
			name:     "http with explicit permission",
			raw:      rawConfig(`{"endpoint": "http://ddns.example.net", "tokenSecretRef": {"name": "s"}}`),
			defaults: insecureDefaults,
			want: challengeConfig{
				endpoint:       "http://ddns.example.net",
				tokenSecretRef: secretKeySelector{Name: "s", Key: "token"},
				httpTimeout:    30 * time.Second,
				tokenAuthMode:  ispconfig.AuthModeBasic,
			},
		},
		{
			name:     "unsupported scheme",
			raw:      rawConfig(`{"endpoint": "ftp://ddns.example.net", "tokenSecretRef": {"name": "s"}}`),
			defaults: testDefaults(),
			wantErr:  []string{"ftp", "https"},
			wantIs:   ispconfig.ErrInvalidEndpoint,
		},
		{
			name:     "endpoint without scheme",
			raw:      rawConfig(`{"endpoint": "ispconfig.example.com", "tokenSecretRef": {"name": "s"}}`),
			defaults: testDefaults(),
			wantErr:  []string{"ispconfig.example.com"},
			wantIs:   ispconfig.ErrInvalidEndpoint,
		},
		{
			name:     "endpoint without host",
			raw:      rawConfig(`{"endpoint": "https://", "tokenSecretRef": {"name": "s"}}`),
			defaults: testDefaults(),
			wantErr:  []string{"https://"},
			wantIs:   ispconfig.ErrInvalidEndpoint,
		},
		{
			name:     "endpoint is not a valid URL",
			raw:      rawConfig(`{"endpoint": "https://ddns example.net", "tokenSecretRef": {"name": "s"}}`),
			defaults: testDefaults(),
			wantErr:  []string{"https://ddns example.net"},
			wantIs:   ispconfig.ErrInvalidEndpoint,
		},
		{
			// Without an upper bound the time budget of a challenge (httpTimeout +
			// secretResolveTimeout) would overflow and turn negative for a value close to
			// MaxInt64 — the context would then expire immediately.
			name:     "httpTimeout above the upper bound",
			raw:      rawConfig(`{"httpTimeout": "2562047h47m16s", "tokenSecretRef": {"name": "s"}}`),
			defaults: testDefaults(),
			wantErr:  []string{"upper bound"},
		},
		{
			name:     "httpTimeout just above the upper bound",
			raw:      rawConfig(`{"httpTimeout": "51s", "tokenSecretRef": {"name": "s"}}`),
			defaults: testDefaults(),
			wantErr:  []string{"upper bound"},
		},
		{
			name:     "no endpoint and no default",
			raw:      rawConfig(`{"tokenSecretRef": {"name": "s"}}`),
			defaults: Defaults{HTTPTimeout: 30 * time.Second},
			wantErr:  []string{"no endpoint given"},
		},
		{
			name:     "timeout overrides default",
			raw:      rawConfig(`{"tokenSecretRef": {"name": "s"}, "httpTimeout": "45s"}`),
			defaults: testDefaults(),
			want: challengeConfig{
				endpoint:       "https://ispconfig.example.com",
				tokenSecretRef: secretKeySelector{Name: "s", Key: "token"},
				httpTimeout:    45 * time.Second,
				tokenAuthMode:  ispconfig.AuthModeBasic,
			},
		},
		{
			name:     "invalid duration",
			raw:      rawConfig(`{"tokenSecretRef": {"name": "s"}, "httpTimeout": "45 seconds"}`),
			defaults: testDefaults(),
			wantErr:  []string{"httpTimeout", "45 seconds"},
		},
		{
			name:     "negative duration",
			raw:      rawConfig(`{"tokenSecretRef": {"name": "s"}, "httpTimeout": "-5s"}`),
			defaults: testDefaults(),
			wantErr:  []string{"must be positive"},
		},
		{
			name:     "zero duration",
			raw:      rawConfig(`{"tokenSecretRef": {"name": "s"}, "httpTimeout": "0s"}`),
			defaults: testDefaults(),
			wantErr:  []string{"must be positive"},
		},
		{
			name:     "no timeout and no default",
			raw:      rawConfig(`{"tokenSecretRef": {"name": "s"}}`),
			defaults: Defaults{Endpoint: "https://ispconfig.example.com"},
			wantErr:  []string{"must be positive"},
		},
		{
			name:     "tokenAuthMode basic explicitly",
			raw:      rawConfig(`{"tokenSecretRef": {"name": "s"}, "tokenAuthMode": "basic"}`),
			defaults: testDefaults(),
			want: challengeConfig{
				endpoint:       "https://ispconfig.example.com",
				tokenSecretRef: secretKeySelector{Name: "s", Key: "token"},
				httpTimeout:    30 * time.Second,
				tokenAuthMode:  ispconfig.AuthModeBasic,
			},
		},
		{
			name:     "unknown tokenAuthMode names the allowed values",
			raw:      rawConfig(`{"tokenSecretRef": {"name": "s"}, "tokenAuthMode": "header"}`),
			defaults: testDefaults(),
			wantErr:  []string{"header", "basic", "query"},
		},
		{
			name:     "tokenSecretRef without name",
			raw:      rawConfig(`{"tokenSecretRef": {"key": "token"}}`),
			defaults: testDefaults(),
			wantErr:  []string{"tokenSecretRef.name"},
		},
		{
			name:     "tokenSecretRef missing entirely",
			raw:      rawConfig(`{"endpoint": "https://ddns.example.net"}`),
			defaults: testDefaults(),
			wantErr:  []string{"tokenSecretRef.name"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseConfig(tt.raw, tt.defaults)

			if len(tt.wantErr) > 0 {
				require.Error(t, err)
				require.ErrorIs(t, err, ErrConfig)
				if tt.wantIs != nil {
					require.ErrorIs(t, err, tt.wantIs)
				}
				for _, fragment := range tt.wantErr {
					assert.Contains(t, err.Error(), fragment)
				}

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
