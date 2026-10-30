// Package observability sets up OpenTelemetry traces and metrics for the webhook.
//
// Without a configured OTLP endpoint the package stays completely inactive: neither exporters
// nor background goroutines are created, and the global providers remain untouched. The OTel
// API then provides no-op tracers and meters on its own, so that instrumented code keeps
// working unchanged.
package observability

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"
	"go.opentelemetry.io/otel/trace"
)

// scopeName is the instrumentation scope of all tracers and meters of this service.
const scopeName = "github.com/ise-cobra/cert-manager-webhook-ispconfig"

// Configuration errors of Setup.
var (
	// ErrServiceNameRequired is reported when export is active but no service name is given.
	ErrServiceNameRequired = errors.New("service name must not be empty")
	// ErrSampleRatioOutOfRange is reported when the sampling ratio is outside 0..1.
	ErrSampleRatioOutOfRange = errors.New("sample ratio must be between 0 and 1")
)

// Config describes the OTLP export. An empty Endpoint disables observability completely.
type Config struct {
	// Endpoint is the address of the OTLP/gRPC collector. Both notations are accepted:
	// "otel-collector:4317" and the URL form defined by the OTel standard
	// "http://otel-collector:4317".
	Endpoint string
	// Insecure disables TLS to the collector — for in-cluster connections only.
	Insecure bool
	// ServiceName fills the resource attribute service.name.
	ServiceName string
	// ServiceVersion fills the resource attribute service.version; empty means omit.
	ServiceVersion string
	// SampleRatio is the fraction of sampled root traces, allowed is 0..1. 0 means
	// "no root traces" — the same meaning as in the OTel standard, from which the value comes
	// via OTEL_TRACES_SAMPLER_ARG.
	SampleRatio float64
	// Logger receives the startup line and internal OTel errors; nil means
	// slog.Default(). Explicitly a field so that the package does not depend on another package
	// having called slog.SetDefault before.
	Logger *slog.Logger
}

// Setup registers tracer and meter providers for the OTLP/gRPC export and returns the
// matching shutdown function. If Config.Endpoint is empty, observability stays disabled:
// nothing is registered and the returned shutdown function does nothing. The configuration
// is only validated in the active case.
func Setup(ctx context.Context, cfg Config) (func(context.Context) error, error) {
	if cfg.Endpoint == "" {
		return func(context.Context) error { return nil }, nil
	}
	if cfg.ServiceName == "" {
		return nil, ErrServiceNameRequired
	}
	if cfg.SampleRatio < 0 || cfg.SampleRatio > 1 {
		return nil, fmt.Errorf("%w: %v", ErrSampleRatioOutOfRange, cfg.SampleRatio)
	}

	res, err := newResource(cfg)
	if err != nil {
		return nil, fmt.Errorf("create OTel resource: %w", err)
	}

	traceExporter, err := otlptracegrpc.New(ctx, grpcTraceOptions(cfg)...)
	if err != nil {
		return nil, fmt.Errorf("create trace exporter: %w", err)
	}

	metricExporter, err := otlpmetricgrpc.New(ctx, grpcMetricOptions(cfg)...)
	if err != nil {
		// The trace exporter created already would otherwise be leaked.
		return nil, errors.Join(
			fmt.Errorf("create metric exporter: %w", err),
			traceExporter.Shutdown(ctx),
		)
	}

	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(traceExporter),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRatio))),
	)
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter)),
	)

	otel.SetTracerProvider(tracerProvider)
	otel.SetMeterProvider(meterProvider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Internal OTel errors belong in the structured log, not unfiltered on stderr.
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		logger.Warn("OpenTelemetry reported an error", "err", err)
	}))

	logger.InfoContext(ctx, "observability enabled",
		"endpoint", cfg.Endpoint,
		"insecure", cfg.Insecure,
		"service_name", cfg.ServiceName,
		"sample_ratio", cfg.SampleRatio,
	)

	return func(shutdownCtx context.Context) error {
		return errors.Join(
			tracerProvider.Shutdown(shutdownCtx),
			meterProvider.Shutdown(shutdownCtx),
		)
	}, nil
}

// Tracer returns the tracer of this service. Without Setup it is a no-op.
func Tracer() trace.Tracer {
	return otel.Tracer(scopeName)
}

// Meter returns the meter of this service. Without Setup it is a no-op.
func Meter() metric.Meter {
	return otel.Meter(scopeName)
}

// newResource describes the service towards the collector. Attributes deliberately schemaless: a
// `resource.Merge` with a different semconv version would otherwise fail with "conflicting Schema
// URL" — `NewSchemaless` takes the schema URL of `resource.Default()` and decouples us from it,
// so an OTel SDK bump cannot silently disable telemetry.
func newResource(cfg Config) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{semconv.ServiceName(cfg.ServiceName)}
	if cfg.ServiceVersion != "" {
		attrs = append(attrs, semconv.ServiceVersion(cfg.ServiceVersion))
	}
	return resource.Merge(resource.Default(), resource.NewSchemaless(attrs...))
}

// hasScheme detects the URL form of an endpoint: OTEL_EXPORTER_OTLP_ENDPOINT prescribes a full
// URL, but WithEndpoint expects "host:port" without scheme — both forms are therefore
// accepted, otherwise a wrong gRPC target only shows up as a missing trace.
func hasScheme(endpoint string) bool {
	return strings.Contains(endpoint, "://")
}

func grpcTraceOptions(cfg Config) []otlptracegrpc.Option {
	var opts []otlptracegrpc.Option
	if hasScheme(cfg.Endpoint) {
		opts = append(opts, otlptracegrpc.WithEndpointURL(cfg.Endpoint))
	} else {
		opts = append(opts, otlptracegrpc.WithEndpoint(cfg.Endpoint))
	}
	// After the endpoint option so that the flag can force clear text even for https://; an
	// http:// URL is clear text regardless of the flag.
	if cfg.Insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	return opts
}

func grpcMetricOptions(cfg Config) []otlpmetricgrpc.Option {
	var opts []otlpmetricgrpc.Option
	if hasScheme(cfg.Endpoint) {
		opts = append(opts, otlpmetricgrpc.WithEndpointURL(cfg.Endpoint))
	} else {
		opts = append(opts, otlpmetricgrpc.WithEndpoint(cfg.Endpoint))
	}
	if cfg.Insecure {
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	}
	return opts
}
