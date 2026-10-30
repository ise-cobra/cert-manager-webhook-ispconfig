// Package version provides the version information of the binary embedded at build time.
package version

import (
	"fmt"
	"log/slog"
	"runtime/debug"
)

// Placeholders as long as no values were set via -ldflags.
const (
	unknownValue = "unknown"
	devVersion   = "dev"
)

// Values are set at release time via
// `-ldflags "-X github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/common/version.Version=1.2.3"`
// (and Commit likewise). Exported because the build sets these symbols by name.
var (
	Version = devVersion
	Commit  = unknownValue
)

// Info bundles the version information of a build.
type Info struct {
	// Version is the release version, "dev" in a development build.
	Version string
	// Commit is the Git revision hash of the build.
	Commit string
}

// Get returns the version information of the running binary. If the values set via -ldflags
// are missing, they are filled from the toolchain's build info so that a
// `go install` build also shows meaningful information.
func Get() Info {
	info := Info{Version: Version, Commit: Commit}
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}
	return withBuildInfo(info, buildInfo)
}

// String returns a single-line, human-readable summary.
func (i Info) String() string {
	return fmt.Sprintf("%s (commit %s)", i.Version, i.Commit)
}

// Attrs returns the version information as slog attributes for the startup log line:
//
//	slog.Info("webhook starting", version.Attrs()...)
func Attrs() []any {
	info := Get()
	return []any{
		slog.String("version", info.Version),
		slog.String("commit", info.Commit),
	}
}

// withBuildInfo fills the placeholders from the build info. Only relevant without an
// -ldflags build — a release build is always the more accurate source.
func withBuildInfo(info Info, buildInfo *debug.BuildInfo) Info {
	if info.Version != devVersion {
		return info
	}
	if moduleVersion := buildInfo.Main.Version; moduleVersion != "" && moduleVersion != "(devel)" {
		info.Version = moduleVersion
	}
	for _, setting := range buildInfo.Settings {
		if setting.Value == "" {
			continue
		}
		if setting.Key == "vcs.revision" && info.Commit == unknownValue {
			info.Commit = setting.Value
		}
	}
	return info
}
