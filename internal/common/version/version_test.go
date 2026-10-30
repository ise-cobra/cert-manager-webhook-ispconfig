package version

import (
	"log/slog"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setBuildVars overrides the package variables set via -ldflags for the duration of the test.
func setBuildVars(t *testing.T, newVersion, newCommit string) {
	t.Helper()
	oldVersion, oldCommit := Version, Commit
	t.Cleanup(func() {
		Version, Commit = oldVersion, oldCommit
	})
	Version, Commit = newVersion, newCommit
}

func TestDefaults(t *testing.T) {
	assert.Equal(t, devVersion, Version)
	assert.Equal(t, unknownValue, Commit)
}

func TestGetWithLdflagsValues(t *testing.T) {
	setBuildVars(t, "1.4.2", "0badc0de")

	info := Get()

	assert.Equal(t, Info{Version: "1.4.2", Commit: "0badc0de"}, info)
}

func TestGetWithoutLdflagsValues(t *testing.T) {
	// Without -ldflags at least the default remains; build info may only replace it.
	info := Get()

	assert.NotEmpty(t, info.Version)
	assert.NotEmpty(t, info.Commit)
}

func TestWithBuildInfo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		info      Info
		buildInfo *debug.BuildInfo
		want      Info
	}{
		{
			name: "module version and VCS info fill the defaults",
			info: Info{Version: devVersion, Commit: unknownValue},
			buildInfo: &debug.BuildInfo{
				Main: debug.Module{Version: "v0.3.1"},
				Settings: []debug.BuildSetting{
					{Key: "vcs.revision", Value: "abc1234"},
				},
			},
			want: Info{Version: "v0.3.1", Commit: "abc1234"},
		},
		{
			name: "(devel) is not a usable module version",
			info: Info{Version: devVersion, Commit: unknownValue},
			buildInfo: &debug.BuildInfo{
				Main:     debug.Module{Version: "(devel)"},
				Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "deadbeef"}},
			},
			want: Info{Version: devVersion, Commit: "deadbeef"},
		},
		{
			name:      "empty module version and missing VCS info change nothing",
			info:      Info{Version: devVersion, Commit: unknownValue},
			buildInfo: &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: ""}}},
			want:      Info{Version: devVersion, Commit: unknownValue},
		},
		{
			name: "ldflags values take precedence over build info",
			info: Info{Version: "2.0.0", Commit: "cafebabe"},
			buildInfo: &debug.BuildInfo{
				Main:     debug.Module{Version: "v9.9.9"},
				Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "ffffffff"}},
			},
			want: Info{Version: "2.0.0", Commit: "cafebabe"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, withBuildInfo(tt.info, tt.buildInfo))
		})
	}
}

func TestInfoString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		info Info
		want string
	}{
		{
			name: "complete information",
			info: Info{Version: "1.4.2", Commit: "0badc0de"},
			want: "1.4.2 (commit 0badc0de)",
		},
		{
			name: "defaults",
			info: Info{Version: devVersion, Commit: unknownValue},
			want: "dev (commit unknown)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, tt.info.String())
		})
	}
}

func TestAttrs(t *testing.T) {
	setBuildVars(t, "1.4.2", "0badc0de")

	attrs := Attrs()

	require.Len(t, attrs, 2)
	assert.Equal(t, []any{
		slog.String("version", "1.4.2"),
		slog.String("commit", "0badc0de"),
	}, attrs)
}
