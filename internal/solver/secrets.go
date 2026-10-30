package solver

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/ispconfig"
)

// secretResolveTimeout bounds the access to the Kubernetes API. A Get in the
// own cluster is answered in milliseconds; the bound prevents a hanging API
// server from consuming the time budget of the DDNS call.
const secretResolveTimeout = 5 * time.Second

// token holds the resolved DDNS token and masks it in every output.
type token struct {
	value string
}

// LogValue masks the token in slog output.
func (t token) LogValue() slog.Value {
	return slog.StringValue(ispconfig.RedactedPlaceholder)
}

// String masks the token in fmt output — second line of defense in case the
// value is accidentally formatted into an error message.
func (t token) String() string {
	return ispconfig.RedactedPlaceholder
}

// resolveToken reads the DDNS token from the referenced secret in the namespace of the
// challenge and checks it against the format the remote side accepts.
func resolveToken(
	ctx context.Context,
	client kubernetes.Interface,
	namespace string,
	ref secretKeySelector,
) (token, error) {
	if namespace == "" {
		return token{}, fmt.Errorf("%w: ChallengeRequest without ResourceNamespace, cannot locate secret %q",
			ErrConfig, ref.Name)
	}

	// Own time budget for the API call, so that the chain does not depend on the
	// context of the DDNS call.
	ctx, cancel := context.WithTimeout(ctx, secretResolveTimeout)
	defer cancel()

	secret, err := client.CoreV1().Secrets(namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		// NotFound and Forbidden are misconfiguration, not a transient outage: a typo
		// in the name or a secret in the wrong namespace does not fix itself. Without
		// ErrConfig the most common misconfiguration of all would be classified as a
		// retryable infrastructure error — unlike every other branch of this
		// function.
		if apierrors.IsNotFound(err) || apierrors.IsForbidden(err) {
			return token{}, fmt.Errorf("%w: cannot read Kubernetes secret %q in namespace %q: %w",
				ErrConfig, ref.Name, namespace, err)
		}

		return token{}, fmt.Errorf("cannot read Kubernetes secret %q in namespace %q: %w", ref.Name, namespace, err)
	}

	raw, ok := secret.Data[ref.Key]
	if !ok {
		// Key names are not secrets and the decisive diagnostic aid for a typo in
		// tokenSecretRef.key.
		return token{}, fmt.Errorf("%w: key %q is missing in secret %q (namespace %q), available: %s",
			ErrConfig, ref.Key, ref.Name, namespace, availableKeys(secret.Data))
	}

	// kubectl create secret --from-file regularly appends a \n.
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return token{}, fmt.Errorf("%w: token in secret %q (namespace %q) under key %q is empty",
			ErrConfig, ref.Name, namespace, ref.Key)
	}

	// The remote side silently filters out other characters
	// (preg_replace("/[^0-9^a-f]/", "", $token)) and then answers with 401. Without
	// this upfront check a configuration error would appear as an
	// authentication error. The value itself must not end up in the message.
	if !ispconfig.IsValidToken(value) {
		return token{}, fmt.Errorf(
			"%w: token in secret %q (namespace %q) under key %q has an invalid format — "+
				"only digits and the lowercase letters a-f are allowed (%d characters read)",
			ErrConfig, ref.Name, namespace, ref.Key, len(value))
	}

	return token{value: value}, nil
}

// availableKeys lists the existing key names in sorted order.
func availableKeys(data map[string][]byte) string {
	if len(data) == 0 {
		return "none"
	}

	return strings.Join(slices.Sorted(maps.Keys(data)), ", ")
}
