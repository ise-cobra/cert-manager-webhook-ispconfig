package solver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/ise-cobra/cert-manager-webhook-ispconfig/internal/ispconfig"
)

const (
	// defaultTokenKey is the key in the secret when tokenSecretRef specifies none.
	defaultTokenKey = "token"
	// MaxHTTPTimeout caps the httpTimeout an issuer can set; it stays below the kube-apiserver
	// request timeout of 60s. Exported so that internal/app checks the same value.
	MaxHTTPTimeout = 50 * time.Second
)

// Defaults carries the default values configured at service startup. The
// parser relies exclusively on these and knows no constants of its own, so
// that the same solver package can receive different defaults per deployment.
type Defaults struct {
	// Endpoint is the base URL of the DDNS API when the issuer specifies none.
	Endpoint string
	// HTTPTimeout is the upper bound of a DDNS call when the issuer specifies none.
	HTTPTimeout time.Duration
	// AllowInsecureEndpoint permits http:// endpoints — for development only.
	AllowInsecureEndpoint bool
}

// providerConfig is the config block of the issuer's DNS01 webhook configuration.
type providerConfig struct {
	Endpoint       string            `json:"endpoint"`
	TokenSecretRef secretKeySelector `json:"tokenSecretRef"`
	HTTPTimeout    string            `json:"httpTimeout"`
	TokenAuthMode  string            `json:"tokenAuthMode"`
}

// secretKeySelector references a key in a Kubernetes secret.
type secretKeySelector struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// challengeConfig is the validated configuration of a single challenge,
// completed with defaults.
type challengeConfig struct {
	endpoint       string
	tokenSecretRef secretKeySelector
	httpTimeout    time.Duration
	tokenAuthMode  ispconfig.AuthMode
}

// parseConfig reads the config block of the issuer, fills missing fields from
// defaults and validates the result.
func parseConfig(raw *apiextensionsv1.JSON, defaults Defaults) (challengeConfig, error) {
	if raw == nil || len(raw.Raw) == 0 {
		return challengeConfig{}, fmt.Errorf(
			"%w: no config block given, tokenSecretRef is required", ErrConfig)
	}

	var provided providerConfig
	dec := json.NewDecoder(bytes.NewReader(raw.Raw))
	// An unknown field is an error: a typo would otherwise silently fall back to the
	// default. json.Unmarshal alone ignores unknown fields.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&provided); err != nil {
		return challengeConfig{}, fmt.Errorf("%w: cannot parse config block: %w", ErrConfig, err)
	}

	endpoint, err := resolveEndpoint(provided.Endpoint, defaults)
	if err != nil {
		return challengeConfig{}, err
	}

	timeout, err := resolveTimeout(provided.HTTPTimeout, defaults.HTTPTimeout)
	if err != nil {
		return challengeConfig{}, err
	}

	authMode, err := resolveAuthMode(provided.TokenAuthMode)
	if err != nil {
		return challengeConfig{}, err
	}

	ref, err := resolveSecretRef(provided.TokenSecretRef)
	if err != nil {
		return challengeConfig{}, err
	}

	return challengeConfig{
		endpoint:       endpoint,
		tokenSecretRef: ref,
		httpTimeout:    timeout,
		tokenAuthMode:  authMode,
	}, nil
}

// resolveEndpoint chooses between the issuer value and the default and checks the scheme.
func resolveEndpoint(provided string, defaults Defaults) (string, error) {
	endpoint := strings.TrimSpace(provided)
	if endpoint == "" {
		endpoint = strings.TrimSpace(defaults.Endpoint)
	}
	if endpoint == "" {
		return "", fmt.Errorf("%w: no endpoint given and no default configured", ErrConfig)
	}

	// Checked with the client's rule, not with a copy of its own: the endpoint from the
	// issuer passes through ispconfig.New anyway, and two implementations would
	// drift apart.
	if err := ispconfig.ValidateEndpoint(endpoint, defaults.AllowInsecureEndpoint); err != nil {
		return "", fmt.Errorf("%w: %w", ErrConfig, err)
	}

	return endpoint, nil
}

// resolveTimeout chooses between the issuer value and the default and checks the duration.
func resolveTimeout(provided string, fallback time.Duration) (time.Duration, error) {
	timeout := fallback
	if trimmed := strings.TrimSpace(provided); trimmed != "" {
		parsed, err := time.ParseDuration(trimmed)
		if err != nil {
			return 0, fmt.Errorf("%w: httpTimeout %q is not a valid duration: %w", ErrConfig, trimmed, err)
		}
		timeout = parsed
	}
	if timeout <= 0 {
		return 0, fmt.Errorf("%w: httpTimeout must be positive, is %s", ErrConfig, timeout)
	}
	// Rationale for the upper bound at MaxHTTPTimeout.
	if timeout > MaxHTTPTimeout {
		return 0, fmt.Errorf("%w: httpTimeout %s exceeds the upper bound %s",
			ErrConfig, timeout, MaxHTTPTimeout)
	}

	return timeout, nil
}

// resolveAuthMode resolves the transport mode of the token. The default is
// basic auth, so that the token does not appear in the URL.
func resolveAuthMode(provided string) (ispconfig.AuthMode, error) {
	switch strings.TrimSpace(provided) {
	case "":
		return ispconfig.AuthModeBasic, nil
	case string(ispconfig.AuthModeBasic):
		return ispconfig.AuthModeBasic, nil
	case string(ispconfig.AuthModeQuery):
		return ispconfig.AuthModeQuery, nil
	default:
		return "", fmt.Errorf("%w: tokenAuthMode %q is unknown, allowed are %q and %q",
			ErrConfig, provided, ispconfig.AuthModeBasic, ispconfig.AuthModeQuery)
	}
}

// resolveSecretRef checks the secret reference and sets the default key.
func resolveSecretRef(ref secretKeySelector) (secretKeySelector, error) {
	ref.Name = strings.TrimSpace(ref.Name)
	ref.Key = strings.TrimSpace(ref.Key)

	if ref.Name == "" {
		// There are no ambient credentials: without a secret no token can be resolved.
		return secretKeySelector{}, fmt.Errorf(
			"%w: tokenSecretRef.name is missing, the DDNS token can only be obtained from a secret", ErrConfig)
	}
	if ref.Key == "" {
		ref.Key = defaultTokenKey
	}

	return ref, nil
}
