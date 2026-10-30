package solver

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/ispconfig"
)

// discardLogger keeps the test output free of log lines.
func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

const (
	// testToken is chosen to be distinctive, so that a leak in errors and logs stands out.
	testToken     = "deadbeefcafe1234"
	testNamespace = "cert-manager"
	// testSecret is the name of a secret, not its content.
	testSecret = "ispconfig-ddns-token" //nolint:gosec // G101: secret name, not a credential
)

// newSecret builds a secret for the fake clientset.
func newSecret(name string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: name},
		Data:       data,
	}
}

// tokenSecret is the standard secret with a valid token.
func tokenSecret() *corev1.Secret {
	return newSecret(testSecret, map[string][]byte{"token": []byte(testToken)})
}

func TestResolveToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		objects      []runtime.Object
		namespace    string
		ref          secretKeySelector
		want         string
		wantErr      []string
		wantErrIsCfg bool
		forbidden    []string
	}{
		{
			name:      "token is resolved",
			objects:   []runtime.Object{tokenSecret()},
			namespace: testNamespace,
			ref:       secretKeySelector{Name: testSecret, Key: "token"},
			want:      testToken,
		},
		{
			name:      "different key",
			objects:   []runtime.Object{newSecret(testSecret, map[string][]byte{"ddns": []byte("abc123")})},
			namespace: testNamespace,
			ref:       secretKeySelector{Name: testSecret, Key: "ddns"},
			want:      "abc123",
		},
		{
			name:      "trailing newline is removed",
			objects:   []runtime.Object{newSecret(testSecret, map[string][]byte{"token": []byte(testToken + "\n")})},
			namespace: testNamespace,
			ref:       secretKeySelector{Name: testSecret, Key: "token"},
			want:      testToken,
		},
		{
			name:         "secret of another namespace is not read",
			objects:      []runtime.Object{tokenSecret()},
			namespace:    "other-namespace",
			ref:          secretKeySelector{Name: testSecret, Key: "token"},
			wantErr:      []string{"other-namespace", testSecret},
			wantErrIsCfg: true,
		},
		{
			name:      "secret missing, message names namespace and name",
			objects:   nil,
			namespace: testNamespace,
			ref:       secretKeySelector{Name: testSecret, Key: "token"},
			// NotFound is misconfiguration, not a transient outage.
			wantErr:      []string{testNamespace, testSecret},
			wantErrIsCfg: true,
		},
		{
			name:      "key missing, message names available keys",
			objects:   []runtime.Object{newSecret(testSecret, map[string][]byte{"username": []byte("a"), "ddns": []byte("b")})},
			namespace: testNamespace,
			ref:       secretKeySelector{Name: testSecret, Key: "token"},
			wantErr:   []string{`key "token" is missing`, "ddns", "username"},

			wantErrIsCfg: true,
		},
		{
			name:         "secret without data",
			objects:      []runtime.Object{newSecret(testSecret, nil)},
			namespace:    testNamespace,
			ref:          secretKeySelector{Name: testSecret, Key: "token"},
			wantErr:      []string{"available: none"},
			wantErrIsCfg: true,
		},
		{
			name:         "empty token",
			objects:      []runtime.Object{newSecret(testSecret, map[string][]byte{"token": {}})},
			namespace:    testNamespace,
			ref:          secretKeySelector{Name: testSecret, Key: "token"},
			wantErr:      []string{"is empty"},
			wantErrIsCfg: true,
		},
		{
			name:         "token of whitespace only",
			objects:      []runtime.Object{newSecret(testSecret, map[string][]byte{"token": []byte("  \n\t ")})},
			namespace:    testNamespace,
			ref:          secretKeySelector{Name: testSecret, Key: "token"},
			wantErr:      []string{"is empty"},
			wantErrIsCfg: true,
		},
		{
			name:         "uppercase letters are rejected without naming the value",
			objects:      []runtime.Object{newSecret(testSecret, map[string][]byte{"token": []byte("DEADBEEFCAFE1234")})},
			namespace:    testNamespace,
			ref:          secretKeySelector{Name: testSecret, Key: "token"},
			wantErr:      []string{"invalid format", "a-f"},
			wantErrIsCfg: true,
			forbidden:    []string{"DEADBEEFCAFE1234"},
		},
		{
			name:         "special characters are rejected without naming the value",
			objects:      []runtime.Object{newSecret(testSecret, map[string][]byte{"token": []byte("dead-beef:cafe")})},
			namespace:    testNamespace,
			ref:          secretKeySelector{Name: testSecret, Key: "token"},
			wantErr:      []string{"invalid format"},
			wantErrIsCfg: true,
			forbidden:    []string{"dead-beef:cafe"},
		},
		{
			name:         "non-hex letters are rejected",
			objects:      []runtime.Object{newSecret(testSecret, map[string][]byte{"token": []byte("zzzz9999")})},
			namespace:    testNamespace,
			ref:          secretKeySelector{Name: testSecret, Key: "token"},
			wantErr:      []string{"invalid format"},
			wantErrIsCfg: true,
			forbidden:    []string{"zzzz9999"},
		},
		{
			name:         "without ResourceNamespace",
			objects:      []runtime.Object{tokenSecret()},
			namespace:    "",
			ref:          secretKeySelector{Name: testSecret, Key: "token"},
			wantErr:      []string{"ResourceNamespace"},
			wantErrIsCfg: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := fake.NewClientset(tt.objects...)

			got, err := resolveToken(context.Background(), client, tt.namespace, tt.ref)

			if len(tt.wantErr) > 0 {
				require.Error(t, err)
				if tt.wantErrIsCfg {
					require.ErrorIs(t, err, ErrConfig)
				}
				for _, fragment := range tt.wantErr {
					assert.Contains(t, err.Error(), fragment)
				}
				for _, fragment := range tt.forbidden {
					assert.NotContains(t, err.Error(), fragment)
				}
				assert.Empty(t, got.value)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got.value)
		})
	}
}

func TestTokenIsRedacted(t *testing.T) {
	t.Parallel()

	tok := token{value: testToken}

	assert.Equal(t, ispconfig.RedactedPlaceholder, tok.String())
	assert.Equal(t, ispconfig.RedactedPlaceholder, tok.LogValue().String())

	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("test line", slog.Any("token", tok))

	assert.Contains(t, buf.String(), ispconfig.RedactedPlaceholder)
	assert.NotContains(t, buf.String(), testToken)
}
