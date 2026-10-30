package ispconfig

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// Sentinel errors that callers can check with errors.Is.
var (
	// ErrRecordNotFound reports that a record to be deleted does not exist (HTTP 404 on
	// action=delete). For CleanUp this is a success in domain terms.
	ErrRecordNotFound = errors.New("no matching DNS record exists")
	// ErrUnauthorized reports a missing, unknown or inactive token (HTTP 401).
	ErrUnauthorized = errors.New("invalid or unknown token")
	// ErrForbidden reports a missing permission of the token (HTTP 403), e.g. for the zone,
	// record name or record type.
	ErrForbidden = errors.New("permission denied")
	// ErrRateLimited reports too many failed attempts per source IP (HTTP 429).
	ErrRateLimited = errors.New("too many requests")
	// ErrUnexpectedStatus reports any other error status of the remote side.
	ErrUnexpectedStatus = errors.New("unexpected HTTP status")
)

// Sentinel errors for invalid configuration and input.
var (
	// ErrInvalidEndpoint reports an unusable base URL.
	ErrInvalidEndpoint = errors.New("invalid endpoint")
	// ErrInsecureEndpoint reports an http endpoint without explicit opt-in. A separate
	// sentinel, because callers distinguish this case from a plainly broken URL.
	ErrInsecureEndpoint = errors.New("unencrypted endpoint not allowed")
	// ErrInvalidToken reports a token that the remote side would silently filter and then
	// reject with 401.
	ErrInvalidToken = errors.New("invalid token")
	// ErrInvalidAuthMode reports an unknown auth mode.
	ErrInvalidAuthMode = errors.New("invalid auth mode")
	// ErrInvalidRecord reports an unusable record name.
	ErrInvalidRecord = errors.New("invalid record name")
	// ErrInvalidValue reports an unusable record value.
	ErrInvalidValue = errors.New("invalid record value")
)

// APIError describes an error response of the DDNS API. Depending on status and action, the
// error wraps exactly one of the sentinel errors, so callers can use
// errors.Is(err, ispconfig.ErrRecordNotFound) and still get status and response body for
// diagnosis.
type APIError struct {
	// Action is the executed action.
	Action Action
	// StatusCode is the HTTP status of the response.
	StatusCode int
	// Body is the truncated response body.
	Body string
}

// Error names action, status and the truncated response body.
func (e *APIError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("DDNS action %s failed: HTTP %d (empty response body)", e.Action, e.StatusCode)
	}
	return fmt.Sprintf("DDNS action %s failed: HTTP %d: %s", e.Action, e.StatusCode, e.Body)
}

// Unwrap returns the sentinel error matching the status. A 404 means "record not found" only
// on delete — on add, the remote side uses it to report an unknown zone.
func (e *APIError) Unwrap() error {
	switch {
	case e.StatusCode == http.StatusNotFound && e.Action == ActionDelete:
		return ErrRecordNotFound
	case e.StatusCode == http.StatusUnauthorized:
		return ErrUnauthorized
	case e.StatusCode == http.StatusForbidden:
		return ErrForbidden
	case e.StatusCode == http.StatusTooManyRequests:
		return ErrRateLimited
	default:
		return ErrUnexpectedStatus
	}
}

// errUnclassified stands for an error without its own sentinel — in practice a transport error
// without a response from the remote side.
var errUnclassified = errors.New("DDNS call failed")

// errorClass reduces err to its sentinel. Used for span.RecordError so that telemetry exports
// a low-cardinality error class instead of a message that can contain the remote side's
// response body and thus a record name.
func errorClass(err error) error {
	for _, sentinel := range []error{
		context.DeadlineExceeded,
		context.Canceled,
		ErrRecordNotFound,
		ErrUnauthorized,
		ErrForbidden,
		ErrRateLimited,
		ErrInvalidRecord,
		ErrInvalidValue,
		ErrUnexpectedStatus,
	} {
		if errors.Is(err, sentinel) {
			return sentinel
		}
	}
	return errUnclassified
}

// transportError reports a failed HTTP call without the request URL that *url.Error otherwise
// carries in its message and URL field (including the token in query mode). Only the cause is
// wrapped, not the *url.Error itself — otherwise errors.As would hand out the URL again.
type transportError struct {
	op   string
	host string
	err  error
}

// Error names operation, host and cause — not the URL.
func (e *transportError) Error() string {
	return fmt.Sprintf("%s %s: %s", e.op, e.host, e.err)
}

// Unwrap returns the cause so that errors.Is recognizes e.g. context.DeadlineExceeded.
func (e *transportError) Unwrap() error { return e.err }

// redactedError hides the token value in the message of a transport error. errors.Is and
// errors.As still reach the original error, so callers can recognize e.g.
// context.DeadlineExceeded; only the text output is redacted.
type redactedError struct {
	msg string
	err error
}

// Error returns the redacted message.
func (e *redactedError) Error() string { return e.msg }

// Unwrap returns the original error.
func (e *redactedError) Unwrap() error { return e.err }
