package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/klog/v2"
)

func TestParseLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  slog.Level
	}{
		{name: "empty means info", input: "", want: slog.LevelInfo},
		{name: "debug", input: "debug", want: slog.LevelDebug},
		{name: "info", input: "info", want: slog.LevelInfo},
		{name: "warn", input: "warn", want: slog.LevelWarn},
		{name: "error", input: "error", want: slog.LevelError},
		{name: "mixed case", input: "DeBuG", want: slog.LevelDebug},
		{name: "upper case", input: "ERROR", want: slog.LevelError},
		{name: "surrounding whitespace", input: "  warn  ", want: slog.LevelWarn},
		// Offset notation of the standard library — comes with slog.Level.UnmarshalText.
		{name: "offset upwards", input: "info+4", want: slog.LevelInfo + 4},
		{name: "offset downwards", input: "debug-2", want: slog.LevelDebug - 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseLevel(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseLevelInvalid(t *testing.T) {
	t.Parallel()

	_, err := ParseLevel("trace")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidLevel)
	assert.Contains(t, err.Error(), "trace", "error text must name the invalid value")
	assert.Contains(t, err.Error(), "debug, info, warn, error", "error text must name the allowed values")
}

func TestParseFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  format
	}{
		{name: "empty means auto", input: "", want: formatAuto},
		{name: "auto", input: "auto", want: formatAuto},
		{name: "json", input: "json", want: formatJSON},
		{name: "text", input: "text", want: formatText},
		{name: "mixed case", input: "JsOn", want: formatJSON},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseFormat(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseFormatInvalid(t *testing.T) {
	t.Parallel()

	_, err := parseFormat("logfmt")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidFormat)
	assert.Contains(t, err.Error(), "logfmt")
	assert.Contains(t, err.Error(), "auto, json, text")
}

func TestNewInvalidOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		opts    Options
		wantErr error
	}{
		{name: "invalid level", opts: Options{Level: "verbose"}, wantErr: ErrInvalidLevel},
		{name: "invalid format", opts: Options{Format: "xml"}, wantErr: ErrInvalidFormat},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger, err := New(&bytes.Buffer{}, tt.opts)
			require.ErrorIs(t, err, tt.wantErr)
			assert.Nil(t, logger)
		})
	}
}

func TestNewJSONFormat(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger, err := New(&buf, Options{Level: "info", Format: "json"})
	require.NoError(t, err)

	logger.Info("webhook started", "port", 443)

	entry := decodeFirstLine(t, buf.String())
	assert.Equal(t, "webhook started", entry["msg"])
	assert.Equal(t, "INFO", entry["level"])
	assert.EqualValues(t, 443, entry["port"])
	assert.NotContains(t, entry, "source", "AddSource is off outside of debug")
}

func TestNewJSONFormatDebugWithSource(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger, err := New(&buf, Options{Level: "debug", Format: "json"})
	require.NoError(t, err)

	logger.Debug("details")

	entry := decodeFirstLine(t, buf.String())
	assert.Equal(t, "DEBUG", entry["level"])
	assert.Contains(t, entry, "source", "AddSource is on at debug")
}

func TestNewLevelFilter(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger, err := New(&buf, Options{Level: "warn", Format: "json"})
	require.NoError(t, err)

	logger.Info("suppressed")
	assert.Empty(t, buf.String(), "info must not appear at level warn")

	logger.Warn("visible")
	assert.Contains(t, buf.String(), "visible")
}

func TestNewTextFormat(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger, err := New(&buf, Options{Format: "text"})
	require.NoError(t, err)

	logger.Info("text output", "record", "_acme-challenge.example.com")

	out := buf.String()
	assert.Contains(t, out, "text output")
	assert.Contains(t, out, "_acme-challenge.example.com")

	var entry map[string]any
	require.Error(t, json.Unmarshal([]byte(firstLine(out)), &entry), "text format must not be JSON")
}

func TestNewAutoYieldsJSON(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger, err := New(&buf, Options{Format: "auto"})
	require.NoError(t, err)

	logger.Info("auto is json")

	entry := decodeFirstLine(t, buf.String())
	assert.Equal(t, "auto is json", entry["msg"])
}

// TestBridge modifies global state (klog, slog default) and therefore does not run in parallel.
func TestBridge(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() {
		slog.SetDefault(previous)
		klog.ClearLogger()
	})

	var buf bytes.Buffer
	logger, err := New(&buf, Options{Format: "json"})
	require.NoError(t, err)

	Bridge(logger)
	assert.Same(t, logger, slog.Default(), "Bridge sets the slog default")

	klog.InfoS("Kubernetes library reporting", "origin", "test")
	klog.Flush()

	entry := decodeFirstLine(t, buf.String())
	assert.Equal(t, "Kubernetes library reporting", entry["msg"])
	assert.Equal(t, "test", entry["origin"])
}

// TestBridgeReachesContextualLogger covers the path used by client-go and apiserver:
// klog.Background and klog.FromContext. Without ContextualLogger(true) klog returns its own
// logger there, whose V level depends on klog's -v (default 0) — the line would be dropped
// despite --log-level=debug. Modifies global state, not parallel.
func TestBridgeReachesContextualLogger(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() {
		slog.SetDefault(previous)
		klog.ClearLogger()
	})

	var buf bytes.Buffer
	logger, err := New(&buf, Options{Level: "debug", Format: "json"})
	require.NoError(t, err)

	Bridge(logger)

	klog.FromContext(context.Background()).V(3).Info("library reporting details", "origin", "context")
	klog.Flush()

	entry := decodeFirstLine(t, buf.String())
	assert.Equal(t, "library reporting details", entry["msg"])
	assert.Equal(t, "context", entry["origin"])
}

// decodeFirstLine decodes the first log line as a JSON object.
func decodeFirstLine(t *testing.T, out string) map[string]any {
	t.Helper()

	require.NotEmpty(t, out, "no log output received")

	var entry map[string]any
	require.NoError(t, json.Unmarshal([]byte(firstLine(out)), &entry))

	return entry
}

// firstLine returns the first line of the output.
func firstLine(out string) string {
	line, _, _ := strings.Cut(out, "\n")
	return line
}
