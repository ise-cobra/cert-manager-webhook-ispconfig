package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/common/observability"
	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/solver"
)

// writeKeyPair writes a self-signed certificate together with the matching key as PEM files
// and returns their paths. Real material, because validate also checks via
// tls.LoadX509KeyPair that the two files belong together.
func writeKeyPair(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cert-manager-webhook-ispconfig"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	dir := t.TempDir()
	certFile = filepath.Join(dir, "tls.crt")
	keyFile = filepath.Join(dir, "tls.key")
	require.NoError(t, os.WriteFile(certFile,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))

	return certFile, keyFile
}

// validConfig returns a startable configuration with real TLS material.
func validConfig(t *testing.T) Config {
	t.Helper()

	certFile, keyFile := writeKeyPair(t)

	return Config{
		GroupName:       "acme.example.com",
		SecurePort:      8443,
		TLSCertFile:     certFile,
		TLSKeyFile:      keyFile,
		Endpoint:        "https://ispconfig.example.com",
		HTTPTimeout:     30 * time.Second,
		OTelSampleRatio: 1.0,
	}
}

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(t *testing.T, cfg *Config)
		wantErr error
	}{
		{
			name:   "valid configuration",
			mutate: func(*testing.T, *Config) {},
		},
		{
			name:    "group name empty",
			mutate:  func(_ *testing.T, cfg *Config) { cfg.GroupName = "" },
			wantErr: ErrGroupNameRequired,
		},
		{
			name:    "group name whitespace only",
			mutate:  func(_ *testing.T, cfg *Config) { cfg.GroupName = "   " },
			wantErr: ErrGroupNameRequired,
		},
		{
			name:    "certificate file not configured",
			mutate:  func(_ *testing.T, cfg *Config) { cfg.TLSCertFile = "" },
			wantErr: ErrTLSMaterialRequired,
		},
		{
			name:    "key file not configured",
			mutate:  func(_ *testing.T, cfg *Config) { cfg.TLSKeyFile = "" },
			wantErr: ErrTLSMaterialRequired,
		},
		{
			name: "certificate file unreadable",
			mutate: func(t *testing.T, cfg *Config) {
				t.Helper()
				cfg.TLSCertFile = filepath.Join(t.TempDir(), "missing.crt")
			},
			wantErr: ErrTLSMaterialUnreadable,
		},
		{
			name: "key file unreadable",
			mutate: func(t *testing.T, cfg *Config) {
				t.Helper()
				cfg.TLSKeyFile = filepath.Join(t.TempDir(), "missing.key")
			},
			wantErr: ErrTLSMaterialUnreadable,
		},
		{
			// The most common operator mistake: the two flags are swapped. Only the pairing
			// check of tls.LoadX509KeyPair detects this at startup.
			name: "certificate and key swapped",
			mutate: func(_ *testing.T, cfg *Config) {
				cfg.TLSCertFile, cfg.TLSKeyFile = cfg.TLSKeyFile, cfg.TLSCertFile
			},
			wantErr: ErrTLSMaterialUnreadable,
		},
		{
			// Without this check, a key that does not belong to the certificate would surface
			// only in the apiserver stack — with a message naming neither flag nor path.
			name: "key does not belong to certificate",
			mutate: func(t *testing.T, cfg *Config) {
				t.Helper()
				_, foreignKey := writeKeyPair(t)
				cfg.TLSKeyFile = foreignKey
			},
			wantErr: ErrTLSMaterialUnreadable,
		},
		{
			name:    "port 0",
			mutate:  func(_ *testing.T, cfg *Config) { cfg.SecurePort = 0 },
			wantErr: ErrSecurePortOutOfRange,
		},
		{
			name:    "port negative",
			mutate:  func(_ *testing.T, cfg *Config) { cfg.SecurePort = -1 },
			wantErr: ErrSecurePortOutOfRange,
		},
		{
			name:    "port too large",
			mutate:  func(_ *testing.T, cfg *Config) { cfg.SecurePort = 65536 },
			wantErr: ErrSecurePortOutOfRange,
		},
		{
			name:   "port at upper bound",
			mutate: func(_ *testing.T, cfg *Config) { cfg.SecurePort = 65535 },
		},
		{
			name:    "timeout 0",
			mutate:  func(_ *testing.T, cfg *Config) { cfg.HTTPTimeout = 0 },
			wantErr: ErrHTTPTimeoutInvalid,
		},
		{
			name:    "timeout negative",
			mutate:  func(_ *testing.T, cfg *Config) { cfg.HTTPTimeout = -time.Second },
			wantErr: ErrHTTPTimeoutInvalid,
		},
		{
			// Without this check the pod becomes ready, but every challenge without its own
			// issuer httpTimeout fails immediately at solver.MaxHTTPTimeout.
			name:    "timeout above upper bound",
			mutate:  func(_ *testing.T, cfg *Config) { cfg.HTTPTimeout = solver.MaxHTTPTimeout + time.Second },
			wantErr: ErrHTTPTimeoutInvalid,
		},
		{
			name:   "timeout at upper bound",
			mutate: func(_ *testing.T, cfg *Config) { cfg.HTTPTimeout = solver.MaxHTTPTimeout },
		},
		{
			name:    "endpoint empty",
			mutate:  func(_ *testing.T, cfg *Config) { cfg.Endpoint = "" },
			wantErr: ErrInvalidEndpoint,
		},
		{
			name:    "endpoint not parseable",
			mutate:  func(_ *testing.T, cfg *Config) { cfg.Endpoint = "https://%zz" },
			wantErr: ErrInvalidEndpoint,
		},
		{
			name:    "endpoint without host",
			mutate:  func(_ *testing.T, cfg *Config) { cfg.Endpoint = "https:///ddns" },
			wantErr: ErrInvalidEndpoint,
		},
		{
			name:    "endpoint without scheme",
			mutate:  func(_ *testing.T, cfg *Config) { cfg.Endpoint = "ispconfig.example.com" },
			wantErr: ErrInvalidEndpoint,
		},
		{
			name:    "endpoint with foreign scheme",
			mutate:  func(_ *testing.T, cfg *Config) { cfg.Endpoint = "ftp://ispconfig.example.com" },
			wantErr: ErrInvalidEndpoint,
		},
		{
			name:    "http endpoint without permission",
			mutate:  func(_ *testing.T, cfg *Config) { cfg.Endpoint = "http://localhost:8080" },
			wantErr: ErrInsecureEndpoint,
		},
		{
			name: "http endpoint with permission",
			mutate: func(_ *testing.T, cfg *Config) {
				cfg.Endpoint = "http://localhost:8080"
				cfg.AllowInsecureEndpoint = true
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := validConfig(t)
			tt.mutate(t, &cfg)

			err := cfg.validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

// TestNewServerOptions pins the field paths in RecommendedOptions that the programmatic wiring
// relies on. A cert-manager update that renames them thus fails in the test instead of in
// production.
func TestNewServerOptions(t *testing.T) {
	t.Parallel()

	cfg := validConfig(t)

	opts := newServerOptions(cfg, slog.New(slog.DiscardHandler))

	assert.Equal(t, cfg.GroupName, opts.SolverGroup)
	require.Len(t, opts.Solvers, 1)
	assert.Equal(t, solver.SolverName, opts.Solvers[0].Name())

	secureServing := opts.RecommendedOptions.SecureServing
	assert.Equal(t, cfg.SecurePort, secureServing.BindPort)
	assert.Equal(t, cfg.TLSCertFile, secureServing.ServerCert.CertKey.CertFile)
	assert.Equal(t, cfg.TLSKeyFile, secureServing.ServerCert.CertKey.KeyFile)
	assert.Equal(t, minTLSVersion, secureServing.MinTLSVersion)

	// Validate applies the logging options and would run into a nil dereference without them.
	assert.NotNil(t, opts.Logging)
	// A solver webhook has neither its own storage nor admission plugins.
	assert.Nil(t, opts.RecommendedOptions.Etcd)
	assert.Nil(t, opts.RecommendedOptions.Admission)
	assert.False(t, opts.RecommendedOptions.Features.EnablePriorityAndFairness)
}

// TestNewServerOptionsDoesNotSelfSign checks that MaybeDefaultWithSelfSignedCerts — called by
// Config() — does not replace the configured paths.
func TestNewServerOptionsDoesNotSelfSign(t *testing.T) {
	t.Parallel()

	cfg := validConfig(t)
	opts := newServerOptions(cfg, slog.New(slog.DiscardHandler))

	require.NoError(t, opts.RecommendedOptions.SecureServing.MaybeDefaultWithSelfSignedCerts(
		"localhost", nil, nil))

	assert.Equal(t, cfg.TLSCertFile, opts.RecommendedOptions.SecureServing.ServerCert.CertKey.CertFile)
	assert.Equal(t, cfg.TLSKeyFile, opts.RecommendedOptions.SecureServing.ServerCert.CertKey.KeyFile)
}

func TestRunRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	cfg := validConfig(t)
	cfg.GroupName = ""

	err := Run(t.Context(), cfg, slog.New(slog.DiscardHandler))

	assert.ErrorIs(t, err, ErrGroupNameRequired)
}

// TestRunReportsBrokenTelemetry checks that an unusable telemetry configuration aborts startup
// instead of letting the service continue without telemetry.
func TestRunReportsBrokenTelemetry(t *testing.T) {
	t.Parallel()

	cfg := validConfig(t)
	cfg.OTelEndpoint = "otel-collector:4317"
	cfg.OTelSampleRatio = 2

	err := Run(t.Context(), cfg, slog.New(slog.DiscardHandler))

	assert.ErrorIs(t, err, observability.ErrSampleRatioOutOfRange)
}

// TestConfigValidateErrorNamesPath ensures that the operator can tell from the log inside the
// container which mount is missing.
func TestConfigValidateErrorNamesPath(t *testing.T) {
	t.Parallel()

	cfg := validConfig(t)
	cfg.TLSCertFile = filepath.Join(t.TempDir(), "missing.crt")

	err := cfg.validate()

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTLSMaterialUnreadable)
	assert.Contains(t, err.Error(), cfg.TLSCertFile)
	assert.Contains(t, err.Error(), "--tls-cert-file")
}

// TestConfigValidateMissingCertIsNotSelfSigned documents that the error message must make
// clear that the webhook cannot serve without a certificate.
func TestConfigValidateMissingCertIsNotSelfSigned(t *testing.T) {
	t.Parallel()

	cfg := validConfig(t)
	cfg.TLSCertFile = ""
	cfg.TLSKeyFile = ""

	err := cfg.validate()

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTLSMaterialRequired)
	assert.Contains(t, err.Error(), "cannot serve without a serving certificate")
}
