// Command webhook is the cert-manager DNS01 solver webhook for the ISPConfig DDNS token API.
//
// The wiring is deliberately thin: define flags, build the logger, delegate to internal/app.
//
// Version information is linked in at build time:
//
//	go build -trimpath -ldflags "\
//	  -X github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/common/version.Version=1.2.3 \
//	  -X github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/common/version.Commit=$(git rev-parse HEAD)" \
//	  ./cmd/webhook
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/app"
	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/common/logging"
	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/common/version"
)

// Flag names. Constants so that definition and lookup cannot drift apart.
const (
	flagGroupName             = "group-name"
	flagSecurePort            = "secure-port"
	flagTLSCertFile           = "tls-cert-file"
	flagTLSPrivateKeyFile     = "tls-private-key-file"
	flagEndpoint              = "ispconfig-endpoint"
	flagHTTPTimeout           = "ispconfig-http-timeout"
	flagAllowInsecureEndpoint = "ispconfig-allow-insecure-endpoint"
	flagLogLevel              = "log-level"
	flagLogFormat             = "log-format"
	flagOTelEndpoint          = "otel-endpoint"
	flagOTelInsecure          = "otel-insecure"
	flagOTelSampleRatio       = "otel-sample-ratio"
)

// Default values. None of them is a secret — the DDNS token comes exclusively from the
// Kubernetes Secret referenced by the issuer and therefore has neither a flag nor an env var.
const (
	defaultSecurePort      = 8443
	defaultHTTPTimeout     = 30 * time.Second
	defaultLogLevel        = "info"
	defaultLogFormat       = "auto"
	defaultOTelSampleRatio = 1.0
)

// runFunc starts the service. A parameter of newCommand so that the test can check the
// flag wiring without a running server.
type runFunc func(ctx context.Context, cfg app.Config, logger *slog.Logger) error

func main() {
	// SIGTERM comes from Kubernetes during a rolling update, SIGINT from the terminal.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := newCommand(os.Stderr, app.Run).Run(ctx, os.Args); err != nil {
		slog.Error("webhook terminated with an error", "err", err)
		os.Exit(1)
	}
}

// newCommand builds the command. logOut receives the log output, run executes the service.
func newCommand(logOut io.Writer, run runFunc) *cli.Command {
	return &cli.Command{
		Name:    "webhook",
		Usage:   "cert-manager DNS01 solver webhook for the ISPConfig DDNS token API",
		Version: version.Get().String(),
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name: flagGroupName,
				// No default: the spec scenario "group name missing" demands an abort, and a
				// built-in value would start a webhook that no issuer references.
				Usage:   "ACME solver API group served by the webhook (required)",
				Sources: cli.EnvVars("GROUP_NAME"),
			},
			&cli.IntFlag{
				Name:    flagSecurePort,
				Usage:   "TLS port of the extension API server",
				Value:   defaultSecurePort,
				Sources: cli.EnvVars("SECURE_PORT"),
			},
			&cli.StringFlag{
				Name:    flagTLSCertFile,
				Usage:   "PEM file of the serving certificate",
				Sources: cli.EnvVars("TLS_CERT_FILE"),
			},
			&cli.StringFlag{
				Name:    flagTLSPrivateKeyFile,
				Usage:   "PEM file of the private key",
				Sources: cli.EnvVars("TLS_PRIVATE_KEY_FILE"),
			},
			&cli.StringFlag{
				Name: flagEndpoint,
				// No default: a built-in host name would let a deployment without
				// ISPCONFIG_ENDPOINT start healthy and send real DDNS calls with a real token to
				// the built-in address. The chart sets the value.
				Usage:   "default base URL of the DDNS API, can be overridden per issuer (required)",
				Sources: cli.EnvVars("ISPCONFIG_ENDPOINT"),
			},
			&cli.DurationFlag{
				Name:    flagHTTPTimeout,
				Usage:   "default timeout per DDNS call; the issuer can override it",
				Value:   defaultHTTPTimeout,
				Sources: cli.EnvVars("ISPCONFIG_HTTP_TIMEOUT"),
			},
			&cli.BoolFlag{
				Name:    flagAllowInsecureEndpoint,
				Usage:   "allows http endpoints — for development only",
				Sources: cli.EnvVars("ISPCONFIG_ALLOW_INSECURE_ENDPOINT"),
			},
			&cli.StringFlag{
				Name:    flagLogLevel,
				Usage:   "log level: debug, info, warn or error",
				Value:   defaultLogLevel,
				Sources: cli.EnvVars("LOG_LEVEL"),
			},
			&cli.StringFlag{
				Name:    flagLogFormat,
				Usage:   "log format: auto, json or text",
				Value:   defaultLogFormat,
				Sources: cli.EnvVars("LOG_FORMAT"),
			},
			&cli.StringFlag{
				Name:    flagOTelEndpoint,
				Usage:   "OTLP/gRPC collector; empty disables telemetry",
				Sources: cli.EnvVars("OTEL_EXPORTER_OTLP_ENDPOINT"),
			},
			&cli.BoolFlag{
				Name:    flagOTelInsecure,
				Usage:   "send telemetry without TLS",
				Sources: cli.EnvVars("OTEL_EXPORTER_OTLP_INSECURE"),
			},
			&cli.FloatFlag{
				Name:    flagOTelSampleRatio,
				Usage:   "fraction of sampled root traces",
				Value:   defaultOTelSampleRatio,
				Sources: cli.EnvVars("OTEL_TRACES_SAMPLER_ARG"),
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			// The logger is created first so that configuration errors are already logged
			// structured and in the requested format.
			logger, err := logging.New(logOut, logging.Options{
				Level:  cmd.String(flagLogLevel),
				Format: cmd.String(flagLogFormat),
			})
			if err != nil {
				return fmt.Errorf("cannot build the logger: %w", err)
			}
			logging.Bridge(logger)

			return run(ctx, configFrom(cmd), logger)
		},
	}
}

// configFrom reads the resolved flag values into the service configuration.
func configFrom(cmd *cli.Command) app.Config {
	return app.Config{
		GroupName:             cmd.String(flagGroupName),
		SecurePort:            cmd.Int(flagSecurePort),
		TLSCertFile:           cmd.String(flagTLSCertFile),
		TLSKeyFile:            cmd.String(flagTLSPrivateKeyFile),
		Endpoint:              cmd.String(flagEndpoint),
		HTTPTimeout:           cmd.Duration(flagHTTPTimeout),
		AllowInsecureEndpoint: cmd.Bool(flagAllowInsecureEndpoint),
		OTelEndpoint:          cmd.String(flagOTelEndpoint),
		OTelInsecure:          cmd.Bool(flagOTelInsecure),
		OTelSampleRatio:       cmd.Float(flagOTelSampleRatio),
	}
}
