// Package app assembles the webhook service and starts the Kubernetes extension API server
// through which cert-manager solves DNS01 challenges.
//
// cert-manager's cobra entry point is deliberately bypassed: it registers 81 pflag flags
// without an env var source and calls os.Exit itself. Instead, the exported
// server.WebhookServerOptions are filled programmatically.
package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd/server"

	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/common/logging"
	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/common/observability"
	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/common/version"
	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/ispconfig"
	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/solver"
)

const (
	// serviceName names the service towards the OTLP collector.
	serviceName = "cert-manager-webhook-ispconfig"
	// telemetryShutdownTimeout bounds the export of the last telemetry data on shutdown.
	telemetryShutdownTimeout = 5 * time.Second
	// minTLSVersion sets the minimum TLS version of the serving port explicitly. The apiserver
	// default is the same, but not guaranteed.
	minTLSVersion = "VersionTLS12"
	// minPort and maxPort bound the serving port.
	minPort = 1
	maxPort = 65535
)

// Configuration errors that prevent startup. Callers check with errors.Is.
var (
	// ErrGroupNameRequired reports a missing name of the ACME solver API group.
	ErrGroupNameRequired = errors.New("missing group name")
	// ErrTLSMaterialRequired reports missing serving certificate or key settings.
	ErrTLSMaterialRequired = errors.New("TLS certificate and key are required")
	// ErrTLSMaterialUnreadable reports configured but unreadable TLS material.
	ErrTLSMaterialUnreadable = errors.New("TLS material is unreadable")
	// ErrSecurePortOutOfRange reports a serving port outside 1..65535.
	ErrSecurePortOutOfRange = errors.New("invalid serving port")
	// ErrHTTPTimeoutInvalid reports a non-positive or too large timeout for DDNS calls.
	ErrHTTPTimeoutInvalid = errors.New("invalid HTTP timeout")
	// ErrInvalidEndpoint reports an unusable base URL of the DDNS API. The same sentinel as in
	// the client: the rule is implemented there so that startup and challenge cannot drift
	// apart.
	ErrInvalidEndpoint = ispconfig.ErrInvalidEndpoint
	// ErrInsecureEndpoint reports an http endpoint without explicit permission.
	ErrInsecureEndpoint = ispconfig.ErrInsecureEndpoint
)

// Config bundles all operating parameters of the webhook. It maps one to one to the flags
// and environment variables of the command. A DDNS token is deliberately not included: it
// comes exclusively from the Kubernetes Secret referenced by the issuer.
type Config struct {
	// GroupName is the ACME solver API group served by the webhook.
	GroupName string
	// SecurePort is the TLS port of the extension API server.
	SecurePort int
	// TLSCertFile is the PEM file of the serving certificate.
	TLSCertFile string
	// TLSKeyFile is the PEM file of the private key.
	TLSKeyFile string
	// Endpoint is the default base URL of the DDNS API; the issuer can override it.
	Endpoint string
	// HTTPTimeout is the default timeout per DDNS call; the issuer can override it.
	HTTPTimeout time.Duration
	// AllowInsecureEndpoint allows http endpoints — for development only.
	AllowInsecureEndpoint bool
	// OTelEndpoint is the address of the OTLP/gRPC collector; empty disables telemetry.
	OTelEndpoint string
	// OTelInsecure sends telemetry without TLS.
	OTelInsecure bool
	// OTelSampleRatio is the fraction of sampled root traces.
	OTelSampleRatio float64
}

// Run validates the configuration, sets up telemetry and runs the extension API server until
// ctx is cancelled. The call blocks until then.
func Run(ctx context.Context, cfg Config, logger *slog.Logger) error {
	if err := cfg.validate(); err != nil {
		return err
	}

	shutdown, err := observability.Setup(ctx, observability.Config{
		Endpoint:       cfg.OTelEndpoint,
		Insecure:       cfg.OTelInsecure,
		ServiceName:    serviceName,
		ServiceVersion: version.Get().Version,
		SampleRatio:    cfg.OTelSampleRatio,
		Logger:         logger,
	})
	if err != nil {
		return fmt.Errorf("cannot set up telemetry: %w", err)
	}
	defer func() {
		// ctx is already cancelled during shutdown, hence a separate short context — otherwise
		// the export of the last spans aborts immediately.
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), telemetryShutdownTimeout)
		defer cancel()
		if shutdownErr := shutdown(shutdownCtx); shutdownErr != nil {
			logger.ErrorContext(shutdownCtx, "telemetry could not be shut down cleanly",
				"err", shutdownErr)
		}
	}()

	logger.InfoContext(ctx, "webhook starting", append(version.Attrs(),
		slog.String("group_name", cfg.GroupName),
		slog.String("solver_name", solver.SolverName),
		slog.Int("secure_port", cfg.SecurePort),
		slog.String("endpoint", cfg.Endpoint),
		slog.Duration("http_timeout", cfg.HTTPTimeout),
	)...)

	opts := newServerOptions(cfg, logger)

	if err := opts.Complete(); err != nil {
		return fmt.Errorf("complete server options: %w", err)
	}
	if err := opts.Validate(nil); err != nil {
		return fmt.Errorf("validate server options: %w", err)
	}
	// Validate applies the component-base logging configuration and thereby resets the klog
	// logger and the slog default. The bridge must be set again afterwards, otherwise the
	// Kubernetes libraries write in their own format.
	logging.Bridge(logger)

	logger.InfoContext(ctx, "starting extension API server",
		slog.Int("secure_port", cfg.SecurePort))

	if err := opts.RunWebhookServer(ctx); err != nil {
		return fmt.Errorf("run extension API server: %w", err)
	}

	logger.InfoContext(ctx, "webhook stopped")
	return nil
}

// newServerOptions builds the options of the extension API server programmatically. Etcd and
// Admission are already nil in them, and priority and fairness is disabled as well.
func newServerOptions(cfg Config, logger *slog.Logger) *server.WebhookServerOptions {
	opts := server.NewWebhookServerOptions(cfg.GroupName, solver.New(solver.Defaults{
		Endpoint:              cfg.Endpoint,
		HTTPTimeout:           cfg.HTTPTimeout,
		AllowInsecureEndpoint: cfg.AllowInsecureEndpoint,
	}, logger))

	// SecureServing is a *SecureServingOptionsWithLoopback; the fields come via the embedded
	// *SecureServingOptions. Configured certificate files prevent Config() from self-signing
	// via MaybeDefaultWithSelfSignedCerts.
	opts.RecommendedOptions.SecureServing.BindPort = cfg.SecurePort
	opts.RecommendedOptions.SecureServing.ServerCert.CertKey.CertFile = cfg.TLSCertFile
	opts.RecommendedOptions.SecureServing.ServerCert.CertKey.KeyFile = cfg.TLSKeyFile
	opts.RecommendedOptions.SecureServing.MinTLSVersion = minTLSVersion

	return opts
}

// validate checks the configuration completely before startup so that a misconfiguration
// does not only surface with the first challenge.
func (c Config) validate() error {
	if strings.TrimSpace(c.GroupName) == "" {
		return fmt.Errorf("%w: --group-name or GROUP_NAME must be set", ErrGroupNameRequired)
	}

	if c.TLSCertFile == "" || c.TLSKeyFile == "" {
		return fmt.Errorf("%w: --tls-cert-file and --tls-private-key-file must both be set; "+
			"the webhook cannot serve without a serving certificate, and it deliberately does "+
			"not self-sign one", ErrTLSMaterialRequired)
	}
	if err := checkTLSKeyPair(c.TLSCertFile, c.TLSKeyFile); err != nil {
		return err
	}

	// Anticipates SecureServingOptions.Validate, which runs via opts.Validate(nil) anyway.
	// Deliberately duplicated: this check runs before observability.Setup and names the flag.
	// Compare against the apiserver limit on every apiserver bump.
	if c.SecurePort < minPort || c.SecurePort > maxPort {
		return fmt.Errorf("%w: --secure-port %d is not within %d..%d",
			ErrSecurePortOutOfRange, c.SecurePort, minPort, maxPort)
	}

	if c.HTTPTimeout <= 0 {
		return fmt.Errorf("%w: --ispconfig-http-timeout is %s, must be greater than 0",
			ErrHTTPTimeoutInvalid, c.HTTPTimeout)
	}
	// Same check as in solver.resolveTimeout: without it the pod becomes ready, but every
	// challenge without its own issuer httpTimeout fails immediately at the upper bound.
	if c.HTTPTimeout > solver.MaxHTTPTimeout {
		return fmt.Errorf("%w: --ispconfig-http-timeout %s exceeds the upper bound %s",
			ErrHTTPTimeoutInvalid, c.HTTPTimeout, solver.MaxHTTPTimeout)
	}

	return c.validateEndpoint()
}

// validateEndpoint checks the base URL of the DDNS API with the client's rule. The error text
// adds the flag so that the startup message says which switch is missing.
func (c Config) validateEndpoint() error {
	if strings.TrimSpace(c.Endpoint) == "" {
		return fmt.Errorf("%w: --ispconfig-endpoint or ISPCONFIG_ENDPOINT must be set",
			ErrInvalidEndpoint)
	}

	if err := ispconfig.ValidateEndpoint(c.Endpoint, c.AllowInsecureEndpoint); err != nil {
		if errors.Is(err, ErrInsecureEndpoint) {
			return fmt.Errorf("%w; only allowed with --ispconfig-allow-insecure-endpoint", err)
		}

		return fmt.Errorf("%w (--ispconfig-endpoint)", err)
	}

	return nil
}

// checkTLSKeyPair ensures that certificate and key are readable and match — so this surfaces
// here, not only in the apiserver stack, whose message names neither flag nor path.
func checkTLSKeyPair(certFile, keyFile string) error {
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return fmt.Errorf("%w: --tls-cert-file %q and --tls-private-key-file %q: %w",
			ErrTLSMaterialUnreadable, certFile, keyFile, err)
	}

	return nil
}
