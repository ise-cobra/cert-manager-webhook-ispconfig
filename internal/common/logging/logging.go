// Package logging builds the webhook's slog logger and connects the klog/logr-based
// Kubernetes libraries to the same output stream.
package logging

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"k8s.io/klog/v2"
)

// ErrInvalidLevel reports an unknown log level.
var ErrInvalidLevel = errors.New("invalid log level")

// ErrInvalidFormat reports an unknown log format.
var ErrInvalidFormat = errors.New("invalid log format")

// Options controls level and output format of the logger. Empty fields mean
// level "info" and format "auto".
type Options struct {
	// Level is one of debug, info, warn, error (case-insensitive).
	Level string
	// Format is one of auto, json, text (case-insensitive). "auto" means "json" — the chart
	// enforces json anyway; "text" remains for running locally via `go run`.
	Format string
}

// format is the resolved output format.
type format int

const (
	formatAuto format = iota
	formatJSON
	formatText
)

// New creates a logger that writes to w. The logger is not set globally — that is up to the
// caller (see Bridge).
func New(w io.Writer, opts Options) (*slog.Logger, error) {
	level, err := ParseLevel(opts.Level)
	if err != nil {
		return nil, err
	}

	outputFormat, err := parseFormat(opts.Format)
	if err != nil {
		return nil, err
	}

	// Source locations cost runtime and bloat the lines, hence only at debug level.
	addSource := level == slog.LevelDebug

	var handler slog.Handler
	handlerOpts := &slog.HandlerOptions{Level: level, AddSource: addSource}
	if outputFormat == formatText {
		handler = slog.NewTextHandler(w, handlerOpts)
	} else {
		handler = slog.NewJSONHandler(w, handlerOpts)
	}

	return slog.New(handler), nil
}

// ParseLevel resolves the level name. Exported because the command has to check the flag
// before the logger is built.
//
// Resolution uses slog.Level.UnmarshalText instead of a custom switch: the standard library
// knows the same four names in upper and lower case and additionally the offset notation
// ("info+4", "debug-2"), which allows a finer threshold.
func ParseLevel(s string) (slog.Level, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return slog.LevelInfo, nil
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(trimmed)); err != nil {
		return 0, fmt.Errorf("%w %q, allowed: debug, info, warn, error", ErrInvalidLevel, s)
	}

	return level, nil
}

// parseFormat resolves the format name.
func parseFormat(s string) (format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return formatAuto, nil
	case "json":
		return formatJSON, nil
	case "text":
		return formatText, nil
	default:
		return 0, fmt.Errorf("%w %q, allowed: auto, json, text", ErrInvalidFormat, s)
	}
}

// Bridge redirects the logs of the Kubernetes libraries to l. cert-manager, apiserver and
// client-go log via klog or logr; without this bridge two different formats end up in the
// same stream. In addition, l becomes the slog default so that code without its own logger
// writes in the same format.
//
// klog.SetSlogLogger also registers l as the contextual logger, so that klog.Background and
// klog.FromContext — used by client-go and apiserver — return the same handler. klog.SetLogger
// alone does not do that: the libraries would keep writing via klogr, whose V level depends
// on klog's own -v (default 0), and --log-level=debug would have no effect on them.
//
// Not thread-safe, therefore call only at startup.
func Bridge(l *slog.Logger) {
	klog.SetSlogLogger(l)
	slog.SetDefault(l)
}
