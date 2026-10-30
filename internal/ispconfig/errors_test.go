package ispconfig

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIErrorMessage(t *testing.T) {
	t.Parallel()

	withBody := &APIError{Action: ActionAdd, StatusCode: http.StatusForbidden, Body: "Permission denied for record type TXT"}
	assert.Equal(t,
		"DDNS action add failed: HTTP 403: Permission denied for record type TXT",
		withBody.Error())

	withoutBody := &APIError{Action: ActionDelete, StatusCode: http.StatusInternalServerError}
	assert.Equal(t, "DDNS action delete failed: HTTP 500 (empty response body)", withoutBody.Error())
}

func TestAPIErrorUnwrap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		err    *APIError
		want   error
		notIs  error
		status int
	}{
		{
			name:  "404 on delete is a missing record",
			err:   &APIError{Action: ActionDelete, StatusCode: http.StatusNotFound},
			want:  ErrRecordNotFound,
			notIs: ErrUnexpectedStatus,
		},
		{
			name:  "404 on add means an unknown zone",
			err:   &APIError{Action: ActionAdd, StatusCode: http.StatusNotFound},
			want:  ErrUnexpectedStatus,
			notIs: ErrRecordNotFound,
		},
		{
			name: "401",
			err:  &APIError{Action: ActionAdd, StatusCode: http.StatusUnauthorized},
			want: ErrUnauthorized,
		},
		{
			name: "403",
			err:  &APIError{Action: ActionAdd, StatusCode: http.StatusForbidden},
			want: ErrForbidden,
		},
		{
			name: "429",
			err:  &APIError{Action: ActionAdd, StatusCode: http.StatusTooManyRequests},
			want: ErrRateLimited,
		},
		{
			name: "400",
			err:  &APIError{Action: ActionAdd, StatusCode: http.StatusBadRequest},
			want: ErrUnexpectedStatus,
		},
		{
			name: "500",
			err:  &APIError{Action: ActionAdd, StatusCode: http.StatusInternalServerError},
			want: ErrUnexpectedStatus,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.ErrorIs(t, tc.err, tc.want)
			if tc.notIs != nil {
				assert.NotErrorIs(t, tc.err, tc.notIs)
			}

			// The sentinel stays recognizable through an additional wrapping layer.
			wrapped := errors.Join(errors.New("context"), tc.err)
			assert.ErrorIs(t, wrapped, tc.want)

			var apiErr *APIError
			require.ErrorAs(t, wrapped, &apiErr)
			assert.Equal(t, tc.err.StatusCode, apiErr.StatusCode)
		})
	}
}

func TestRedactedError(t *testing.T) {
	t.Parallel()

	client, err := New(Config{Endpoint: "https://host", Token: "deadbeef"})
	require.NoError(t, err)

	inner := errors.New("Get \"https://host/ddns/update.php?token=deadbeef\": timeout")
	redacted := client.redact(inner)

	assert.NotContains(t, redacted.Error(), "deadbeef")
	assert.Contains(t, redacted.Error(), RedactedPlaceholder)
	assert.ErrorIs(t, redacted, inner, "the original error stays inspectable")

	// Without a match the error stays unchanged.
	clean := errors.New("no URL contained")
	assert.Same(t, clean, client.redact(clean))
	assert.NoError(t, client.redact(nil))
}

// endpointWithUserinfo builds the URL at runtime so that secret scanners, which flag every URL
// with user info in the source, do not report a false positive.
func endpointWithUserinfo() string {
	u := url.URL{Scheme: "https", User: url.User("user"), Host: "host"}
	return u.String()
}

// TestValidateEndpoint covers the exported validator that app and solver call instead of keeping
// their own copies of the rule.
func TestValidateEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		raw           string
		allowInsecure bool
		wantErr       error
	}{
		{name: "https", raw: "https://ispconfig.example.com"},
		{name: "https with path", raw: "https://host/ispconfig"},
		{name: "http with opt-in", raw: "http://localhost:8080", allowInsecure: true},
		{name: "empty", raw: "  ", wantErr: ErrInvalidEndpoint},
		{name: "http without opt-in", raw: "http://host", wantErr: ErrInsecureEndpoint},
		{name: "without scheme", raw: "ispconfig.example.com", wantErr: ErrInvalidEndpoint},
		{name: "foreign scheme", raw: "ftp://host", wantErr: ErrInvalidEndpoint},
		{name: "without host", raw: "https://", wantErr: ErrInvalidEndpoint},
		{name: "not parsable", raw: "https://host\x7f/", wantErr: ErrInvalidEndpoint},
		// Via function instead of a string literal, see endpointWithUserinfo.
		{name: "with user info", raw: endpointWithUserinfo(), wantErr: ErrInvalidEndpoint},
		{name: "with query", raw: "https://host?foo=bar", wantErr: ErrInvalidEndpoint},
		{name: "with fragment", raw: "https://host#frag", wantErr: ErrInvalidEndpoint},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateEndpoint(tt.raw, tt.allowInsecure)
			if tt.wantErr == nil {
				assert.NoError(t, err)

				return
			}
			require.Error(t, err)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

// TestErrorClass pins what span.RecordError exports: the error class, never the full message
// with record name or response body.
func TestErrorClass(t *testing.T) {
	t.Parallel()

	apiErr := &APIError{Action: ActionAdd, StatusCode: http.StatusForbidden,
		Body: "Permission denied for record _acme-challenge.www.example.com"}

	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "403", err: apiErr, want: ErrForbidden},
		{name: "401", err: &APIError{StatusCode: http.StatusUnauthorized}, want: ErrUnauthorized},
		{name: "429", err: &APIError{StatusCode: http.StatusTooManyRequests}, want: ErrRateLimited},
		{
			name: "404 on delete",
			err:  &APIError{Action: ActionDelete, StatusCode: http.StatusNotFound},
			want: ErrRecordNotFound,
		},
		{name: "500", err: &APIError{StatusCode: http.StatusInternalServerError}, want: ErrUnexpectedStatus},
		{name: "timeout", err: fmt.Errorf("call: %w", context.DeadlineExceeded), want: context.DeadlineExceeded},
		{name: "without sentinel", err: errors.New("something"), want: errUnclassified},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := errorClass(tt.err)
			assert.Equal(t, tt.want, got)
			assert.NotContains(t, got.Error(), "_acme-challenge.www.example.com",
				"the error class must not carry a record name")
		})
	}
}
