package observability

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
)

// The tests run without t.Parallel() as soon as they read the global OTel providers: Setup
// registers them process-wide, and the delegation mechanism of the OTel API cannot be reset
// — a "restore" would keep the old SDK provider as delegate.
//
// Every assertion is therefore phrased against a snapshot taken immediately before the call
// instead of against the state of a fresh process. This makes the file independent of the
// source order and lets it survive `go test -shuffle=on`.

func TestSetupWithoutEndpoint(t *testing.T) {
	tracerProviderBefore := otel.GetTracerProvider()
	meterProviderBefore := otel.GetMeterProvider()

	shutdown, err := Setup(context.Background(), Config{ServiceName: "webhook-test"})

	require.NoError(t, err)
	require.NotNil(t, shutdown)
	assert.NoError(t, shutdown(context.Background()))

	// Without an endpoint nothing may have been registered — that is the package's promise.
	// Deliberately no assertion about the span that Tracer() then returns: whether it is a no-op
	// depends on whether someone set a provider earlier in the process, and is thus not a
	// property of this call. TestTracerAndMeterWithoutSetup covers the no-op case.
	assert.Same(t, tracerProviderBefore, otel.GetTracerProvider())
	assert.Same(t, meterProviderBefore, otel.GetMeterProvider())
}

func TestSetupWithoutEndpointIgnoresConfig(t *testing.T) {
	// Disabled observability is not validated — even an incomplete Config is fine.
	shutdown, err := Setup(context.Background(), Config{SampleRatio: 42})

	require.NoError(t, err)
	require.NotNil(t, shutdown)
	assert.NoError(t, shutdown(context.Background()))
}

func TestTracerAndMeterWithoutSetup(t *testing.T) {
	// Instruments must be usable without Setup and must not panic.
	tracer := Tracer()
	require.NotNil(t, tracer)
	ctx, span := tracer.Start(context.Background(), "without-setup")
	t.Cleanup(func() { span.End() })
	span.AddEvent("event")

	meter := Meter()
	require.NotNil(t, meter)
	counter, err := meter.Int64Counter("test.calls")
	require.NoError(t, err)
	counter.Add(ctx, 1)

	histogram, err := meter.Float64Histogram("test.duration")
	require.NoError(t, err)
	histogram.Record(ctx, 0.5)
}

func TestSetupValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     Config
		wantErr error
	}{
		{
			name:    "service name missing",
			cfg:     Config{Endpoint: "127.0.0.1:4317", Insecure: true},
			wantErr: ErrServiceNameRequired,
		},
		{
			name:    "sample ratio above 1",
			cfg:     Config{Endpoint: "127.0.0.1:4317", Insecure: true, ServiceName: "webhook-test", SampleRatio: 1.5},
			wantErr: ErrSampleRatioOutOfRange,
		},
		{
			// A negative value would otherwise silently have become full sampling.
			name:    "sample ratio below 0",
			cfg:     Config{Endpoint: "127.0.0.1:4317", Insecure: true, ServiceName: "webhook-test", SampleRatio: -0.5},
			wantErr: ErrSampleRatioOutOfRange,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			shutdown, err := Setup(context.Background(), tt.cfg)

			require.ErrorIs(t, err, tt.wantErr)
			assert.Nil(t, shutdown)
		})
	}
}

func TestSetupWithEndpoint(t *testing.T) {
	// A listener that accepts connections but never answers: otlp*grpc connects lazily,
	// so Setup must not fail, and the shutdown export runs into the timeout.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, listener.Close())
	})

	tracerProviderBefore := otel.GetTracerProvider()
	meterProviderBefore := otel.GetMeterProvider()

	shutdown, err := Setup(context.Background(), Config{
		Endpoint:       listener.Addr().String(),
		Insecure:       true,
		ServiceName:    "webhook-test",
		ServiceVersion: "1.4.2",
		// Full sampling so that the span below is reliably sampled and actually exported on
		// shutdown.
		SampleRatio: 1,
	})

	require.NoError(t, err)
	require.NotNil(t, shutdown)

	// With an endpoint both providers must have been replaced. The comparison runs against
	// the values from before Setup — comparing tracer against meter provider would always
	// be true because of the different types and would check nothing.
	assert.NotSame(t, tracerProviderBefore, otel.GetTracerProvider())
	assert.NotSame(t, meterProviderBefore, otel.GetMeterProvider())

	_, span := Tracer().Start(context.Background(), "with-setup")
	assert.True(t, span.SpanContext().IsValid())
	span.End()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// The collector never answers, so exactly a timeout is expected — no other error.
	require.ErrorIs(t, shutdown(shutdownCtx), context.DeadlineExceeded)
}

// TestSampleRatioZeroSamplesNothing proves that 0 means "no root traces" and does not
// silently become full sampling. The chart values document 0.0 to 1.0, and the value comes
// via OTEL_TRACES_SAMPLER_ARG from the OTel standard — where 0 likewise means "sample
// nothing". Reinterpreting it would be the exact opposite of the operator's intent.
func TestSampleRatioZeroSamplesNothing(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, listener.Close())
	})

	shutdown, err := Setup(context.Background(), Config{
		Endpoint:    listener.Addr().String(),
		Insecure:    true,
		ServiceName: "webhook-test",
		SampleRatio: 0,
	})
	require.NoError(t, err)
	require.NotNil(t, shutdown)
	t.Cleanup(func() {
		// Otherwise the provider's batch processor would linger for the rest of the test binary.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_ = shutdown(shutdownCtx)
	})

	_, span := Tracer().Start(context.Background(), "without-sampling")
	t.Cleanup(func() { span.End() })

	assert.False(t, span.IsRecording(), "no root span may be recorded with sample ratio 0")
}

// TestEndpointInURLFormIsAccepted covers the notation that the OTel standard prescribes for
// OTEL_EXPORTER_OTLP_ENDPOINT. WithEndpoint would take the whole URL as gRPC target; the
// exporter connects lazily, so the error would only show up as a missing trace.
func TestEndpointInURLFormIsAccepted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		endpoint string
		want     bool
	}{
		{endpoint: "otel-collector:4317", want: false},
		{endpoint: "127.0.0.1:4317", want: false},
		{endpoint: "http://otel-collector:4317", want: true},
		{endpoint: "https://otel-collector:4317", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, hasScheme(tt.endpoint))
			cfg := Config{Endpoint: tt.endpoint}
			assert.Len(t, grpcTraceOptions(cfg), 1)
			assert.Len(t, grpcMetricOptions(cfg), 1)
		})
	}
}
