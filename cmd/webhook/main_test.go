package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"

	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/app"
	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/common/logging"
)

// envVarNames are all environment variables of the interface contract.
var envVarNames = []string{
	"GROUP_NAME",
	"SECURE_PORT",
	"TLS_CERT_FILE",
	"TLS_PRIVATE_KEY_FILE",
	"ISPCONFIG_ENDPOINT",
	"ISPCONFIG_HTTP_TIMEOUT",
	"ISPCONFIG_ALLOW_INSECURE_ENDPOINT",
	"LOG_LEVEL",
	"LOG_FORMAT",
	"OTEL_EXPORTER_OTLP_ENDPOINT",
	"OTEL_EXPORTER_OTLP_INSECURE",
	"OTEL_TRACES_SAMPLER_ARG",
}

// isolateEnv removes all contract environment variables for the duration of the test so that
// the developer machine's environment does not influence the result. t.Setenv remembers the
// original value and restores it afterwards; os.Unsetenv then removes the variable entirely —
// a variable set to empty counts as set for urfave/cli.
func isolateEnv(t *testing.T) {
	t.Helper()

	for _, name := range envVarNames {
		t.Setenv(name, "")
		require.NoError(t, os.Unsetenv(name))
	}
}

// runCommand runs the command with args and returns the resulting configuration.
// The service itself is not started.
func runCommand(t *testing.T, args ...string) (app.Config, error) {
	t.Helper()

	var captured app.Config
	cmd := newCommand(io.Discard, func(_ context.Context, cfg app.Config, logger *slog.Logger) error {
		assert.NotNil(t, logger)
		captured = cfg
		return nil
	})

	// Separate instead of "return captured, cmd.Run(...)": the Go spec only orders function
	// calls left to right, not the read of the variable that the call fills in.
	err := cmd.Run(t.Context(), args)

	return captured, err
}

func TestNewCommandDefaults(t *testing.T) {
	isolateEnv(t)

	cfg, err := runCommand(t, "webhook")

	require.NoError(t, err)
	// GroupName and Endpoint deliberately have no default: both are environment specific and
	// are set by the chart. app.validate refuses to start without them.
	assert.Equal(t, app.Config{
		SecurePort:      8443,
		HTTPTimeout:     30 * time.Second,
		OTelSampleRatio: 1.0,
	}, cfg)
}

func TestNewCommandEnvVars(t *testing.T) {
	tests := []struct {
		envName  string
		envValue string
		expect   func(t *testing.T, cfg app.Config)
	}{
		{"GROUP_NAME", "acme.example.com", func(t *testing.T, cfg app.Config) {
			assert.Equal(t, "acme.example.com", cfg.GroupName)
		}},
		{"SECURE_PORT", "9443", func(t *testing.T, cfg app.Config) {
			assert.Equal(t, 9443, cfg.SecurePort)
		}},
		{"TLS_CERT_FILE", "/tls/tls.crt", func(t *testing.T, cfg app.Config) {
			assert.Equal(t, "/tls/tls.crt", cfg.TLSCertFile)
		}},
		{"TLS_PRIVATE_KEY_FILE", "/tls/tls.key", func(t *testing.T, cfg app.Config) {
			assert.Equal(t, "/tls/tls.key", cfg.TLSKeyFile)
		}},
		{"ISPCONFIG_ENDPOINT", "https://ddns.example.com", func(t *testing.T, cfg app.Config) {
			assert.Equal(t, "https://ddns.example.com", cfg.Endpoint)
		}},
		{"ISPCONFIG_HTTP_TIMEOUT", "5s", func(t *testing.T, cfg app.Config) {
			assert.Equal(t, 5*time.Second, cfg.HTTPTimeout)
		}},
		{"ISPCONFIG_ALLOW_INSECURE_ENDPOINT", "true", func(t *testing.T, cfg app.Config) {
			assert.True(t, cfg.AllowInsecureEndpoint)
		}},
		{"OTEL_EXPORTER_OTLP_ENDPOINT", "otel-collector:4317", func(t *testing.T, cfg app.Config) {
			assert.Equal(t, "otel-collector:4317", cfg.OTelEndpoint)
		}},
		{"OTEL_EXPORTER_OTLP_INSECURE", "true", func(t *testing.T, cfg app.Config) {
			assert.True(t, cfg.OTelInsecure)
		}},
		{"OTEL_TRACES_SAMPLER_ARG", "0.25", func(t *testing.T, cfg app.Config) {
			assert.InDelta(t, 0.25, cfg.OTelSampleRatio, 1e-9)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.envName, func(t *testing.T) {
			isolateEnv(t)
			t.Setenv(tt.envName, tt.envValue)

			cfg, err := runCommand(t, "webhook")

			require.NoError(t, err)
			tt.expect(t, cfg)
		})
	}
}

// TestNewCommandLogFlagsFromEnvVars checks the two flags that do not end up in app.Config but
// build the logger.
func TestNewCommandLogFlagsFromEnvVars(t *testing.T) {
	isolateEnv(t)
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("LOG_FORMAT", "json")

	var out strings.Builder
	cmd := newCommand(&out, func(_ context.Context, _ app.Config, logger *slog.Logger) error {
		logger.Debug("test line")
		return nil
	})

	require.NoError(t, cmd.Run(t.Context(), []string{"webhook"}))
	assert.Contains(t, out.String(), `"msg":"test line"`)
}

func TestNewCommandFlagBeatsEnvVar(t *testing.T) {
	isolateEnv(t)
	t.Setenv("GROUP_NAME", "from-env")
	t.Setenv("SECURE_PORT", "9000")
	t.Setenv("ISPCONFIG_HTTP_TIMEOUT", "1s")

	cfg, err := runCommand(t, "webhook",
		"--group-name", "from-flag",
		"--secure-port", "9443",
		"--ispconfig-http-timeout", "45s",
	)

	require.NoError(t, err)
	assert.Equal(t, "from-flag", cfg.GroupName)
	assert.Equal(t, 9443, cfg.SecurePort)
	assert.Equal(t, 45*time.Second, cfg.HTTPTimeout)
}

// TestNewCommandWithoutCertificateAborts covers the required value: without TLS material the
// service refuses to start instead of silently self-signing a certificate.
func TestNewCommandWithoutCertificateAborts(t *testing.T) {
	isolateEnv(t)

	cmd := newCommand(io.Discard, app.Run)
	err := cmd.Run(t.Context(), []string{"webhook", "--group-name", "acme.example.com"})

	require.Error(t, err)
	assert.ErrorIs(t, err, app.ErrTLSMaterialRequired)
}

// TestNewCommandWithoutGroupNameAborts covers the spec scenario "group name missing" — both
// ways: flag not given at all and flag set to empty. The first case guards against a
// built-in default being added to the flag.
func TestNewCommandWithoutGroupNameAborts(t *testing.T) {
	for _, args := range [][]string{
		{"webhook"},
		{"webhook", "--group-name", ""},
		{"webhook", "--group-name", "   "},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			isolateEnv(t)

			cmd := newCommand(io.Discard, app.Run)
			err := cmd.Run(t.Context(), args)

			require.Error(t, err)
			assert.ErrorIs(t, err, app.ErrGroupNameRequired)
		})
	}
}

// TestEnvironmentSpecificFlagsHaveNoDefault pins that the two environment-specific required
// values carry no built-in value. A default would let a deployment missing the env var start
// healthy — for the endpoint, with real DDNS calls to an unconfigured address.
func TestEnvironmentSpecificFlagsHaveNoDefault(t *testing.T) {
	cmd := newCommand(io.Discard, app.Run)

	for _, name := range []string{flagGroupName, flagEndpoint} {
		flag := flagByName(t, cmd, name)

		documented, ok := flag.(cli.DocGenerationFlag)
		require.True(t, ok, "flag %q provides no documentation", name)
		assert.Empty(t, documented.GetDefaultText(), "flag %q must not carry a default", name)
	}
}

// flagByName looks up a flag on the command.
func flagByName(t *testing.T, cmd *cli.Command, name string) cli.Flag {
	t.Helper()

	for _, flag := range cmd.Flags {
		if slices.Contains(flag.Names(), name) {
			return flag
		}
	}

	t.Fatalf("flag %q is not defined", name)

	return nil
}

func TestNewCommandInvalidLogLevel(t *testing.T) {
	isolateEnv(t)

	_, err := runCommand(t, "webhook", "--log-level", "verbose")

	require.Error(t, err)
	assert.ErrorIs(t, err, logging.ErrInvalidLevel)
}

func TestNewCommandUnknownFlag(t *testing.T) {
	isolateEnv(t)

	_, err := runCommand(t, "webhook", "--ddns-token", "secret")

	require.Error(t, err)
}

// TestNewCommandHasNoTokenFlag covers the scenario "no secrets as flags": neither flag name nor
// env var nor default or usage text may take a DDNS token.
func TestNewCommandHasNoTokenFlag(t *testing.T) {
	cmd := newCommand(io.Discard, app.Run)

	for _, flag := range cmd.Flags {
		for _, name := range flag.Names() {
			assert.NotContains(t, strings.ToLower(name), "token",
				"flag %q must not take a token", name)
		}

		documented, ok := flag.(cli.DocGenerationFlag)
		require.True(t, ok, "flag %v does not implement cli.DocGenerationFlag", flag.Names())
		for _, envName := range documented.GetEnvVars() {
			assert.NotContains(t, strings.ToUpper(envName), "TOKEN",
				"env var %q must not take a token", envName)
		}
		assert.NotContains(t, strings.ToLower(documented.GetUsage()), "token",
			"usage of %v must not mention a token", flag.Names())
		assert.NotContains(t, strings.ToLower(documented.GetValue()), "token",
			"default of %v must not contain a token", flag.Names())
	}
}
