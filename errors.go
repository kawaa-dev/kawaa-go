package kawaa

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"
)

// MaxRetryAfter is the longest this client waits before an automatic retry
// when the API names a delay (the Retry-After header, or the error body's
// retry_after_seconds). When the API asks for longer, the call is not
// retried: the *APIError is returned at once, with the API's own value on
// APIError.RetryAfter, and a longer wait is the caller's to make. Up to
// v0.3.1 the client waited MaxRetryAfter and tried again, so an address the
// API edge had refused for 3,900 seconds held each call for about three
// minutes before the same error.
const MaxRetryAfter = 60 * time.Second

// APIError represents an error returned by the Kawaa API.
//
// The error body is {"success": false, "error": {"code", "message",
// "request_id"?, "retryable"?, "retry_after_seconds"?,
// "retry_requires_same_idempotency_key"?, "retry_may_charge_again"?}}.
// Every retry field is optional: the API leaves one out rather than guess.
//
// Returned as the *APIError itself, so both errors.As(err, &apiErr) and a
// type assertion err.(*kawaa.APIError) work.
type APIError struct {
	StatusCode int    `json:"-"`
	Message    string `json:"error"`
	Code       string `json:"code,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
	// RetryAfter is how many seconds the API asked the caller to wait: the
	// body's retry_after_seconds, or else the Retry-After header (0 when
	// neither carries a usable value). It is the API's own value. When it is
	// longer than MaxRetryAfter, this client did not retry the call.
	RetryAfter int `json:"-"`
	// Retryable is the API's answer to "can the same request succeed if it
	// is sent again after a wait?". Nil when the API did not say (it leaves
	// the field out when the answer depends on the call).
	Retryable *bool `json:"-"`
	// RetryRequiresSameIdempotencyKey is true when the API says a repeat of
	// this request must carry the SAME Idempotency-Key (IdempotencyKey):
	// under that key a charge already made is replayed rather than bought
	// again. A new key would pay again.
	RetryRequiresSameIdempotencyKey bool `json:"-"`
	// RetryMayChargeAgain is true when the request charges credits, carried
	// no key the API could replay, and may already have been charged. This
	// client never repeats such a request on its own; check the balance or
	// the credit history before repeating it.
	RetryMayChargeAgain bool `json:"-"`
	// IdempotencyKey is the Idempotency-Key this call sent on every attempt
	// (Verify, VerifyBatch, Find), or "" for a call that sends none. Pass it
	// back (VerifyOptions.IdempotencyKey, FindOptions.IdempotencyKey) to
	// repeat the call without paying twice.
	IdempotencyKey string `json:"-"`
	// Attempts is how many requests this call sent before giving up (0 when
	// the error was not produced by the request loop).
	Attempts int `json:"-"`

	// serverDelay is the wait the response named for a retry, already
	// limited to MaxRetryAfter; hasServerDelay is false when it named none.
	// serverDelayOverCap is true when the named wait was longer than
	// MaxRetryAfter: such an answer is not retried.
	serverDelay        time.Duration
	hasServerDelay     bool
	serverDelayOverCap bool
}

func (e *APIError) Error() string {
	if e.Attempts > 1 {
		return fmt.Sprintf("kawaa: %s (status: %d, after %d attempts)", e.Message, e.StatusCode, e.Attempts)
	}
	return fmt.Sprintf("kawaa: %s (status: %d)", e.Message, e.StatusCode)
}

// RequestError is returned when a call failed without an API error to show
// for it: a timeout, a dropped connection, the caller's context ending
// between attempts, or a successful response this client could not decode.
// Err is the underlying cause (errors.Is and errors.As reach it).
//
// IdempotencyKey is the key the call sent, or "" for a call that sends none.
// A keyed call that timed out or lost its connection may have been charged:
// repeat it with this key and the API replays the charged attempt instead
// of charging again.
type RequestError struct {
	IdempotencyKey string
	// Attempts is how many requests the call sent (0 when the failure came
	// after the request loop, such as decoding a successful response).
	Attempts int
	Err      error
}

func (e *RequestError) Error() string {
	if e.Attempts == 0 {
		return fmt.Sprintf("kawaa: %v", e.Err)
	}
	plural := "s"
	if e.Attempts == 1 {
		plural = ""
	}
	return fmt.Sprintf("kawaa: request failed after %d attempt%s: %v", e.Attempts, plural, e.Err)
}

// Unwrap returns the underlying cause.
func (e *RequestError) Unwrap() error {
	return e.Err
}

// unreadableBodyError is a successful status whose body is not a JSON
// object. It reaches the caller wrapped in a *RequestError carrying the
// call's key.
type unreadableBodyError struct {
	status int
}

func (e *unreadableBodyError) Error() string {
	return fmt.Sprintf("the API answered HTTP %d with a body that is not a JSON object", e.status)
}

// IdempotencyKeyOf returns the Idempotency-Key the failed call sent, read
// from an *APIError or *RequestError anywhere in err's chain, or "" when the
// call sent none.
//
//	key := kawaa.IdempotencyKeyOf(err)
//	result, err = client.Find(ctx, "Ada", "Lovelace", "example.org", kawaa.FindOptions{IdempotencyKey: key})
func IdempotencyKeyOf(err error) string {
	var reqErr *RequestError
	if errors.As(err, &reqErr) && reqErr.IdempotencyKey != "" {
		return reqErr.IdempotencyKey
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.IdempotencyKey
	}
	return ""
}

// withIdempotencyKey makes err carry key: it is set on the *APIError or
// *RequestError in err's chain when that has none, and any other error is
// wrapped in a *RequestError (errors.Is and errors.As still reach it).
func withIdempotencyKey(err error, key string) error {
	if err == nil || key == "" {
		return err
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		if apiErr.IdempotencyKey == "" {
			apiErr.IdempotencyKey = key
		}
		return err
	}
	var reqErr *RequestError
	if errors.As(err, &reqErr) {
		if reqErr.IdempotencyKey == "" {
			reqErr.IdempotencyKey = key
		}
		return err
	}
	return &RequestError{IdempotencyKey: key, Err: err}
}

// IsAuthenticationError returns true if this is an authentication error.
func (e *APIError) IsAuthenticationError() bool {
	return e.StatusCode == 401
}

// IsRateLimitError returns true if this is a rate limit error.
func (e *APIError) IsRateLimitError() bool {
	return e.StatusCode == 429
}

// IsInsufficientCreditsError returns true if this is an insufficient credits error.
func (e *APIError) IsInsufficientCreditsError() bool {
	return e.StatusCode == 402
}

// IsValidationError returns true if this is a validation error.
func (e *APIError) IsValidationError() bool {
	return e.StatusCode == 400 || e.StatusCode == 422
}

// IsNotFoundError returns true if this is a not found error.
func (e *APIError) IsNotFoundError() bool {
	return e.StatusCode == 404
}

// IsServerError returns true if this is a server error (5xx).
func (e *APIError) IsServerError() bool {
	return e.StatusCode >= 500
}

// parseAPIError parses an API error response. header may be nil; when
// present, the Retry-After header is read for the retry delay.
func parseAPIError(statusCode int, body []byte, header http.Header) *APIError {
	apiErr := &APIError{
		StatusCode: statusCode,
		Message:    "Unknown error",
	}

	headerSeconds, headerOK := -1.0, false
	if header != nil {
		headerSeconds, headerOK = parseRetryAfterSeconds(header.Get("Retry-After"))
	}

	if len(body) > 0 {
		// Try parsing error as an envelope with error object:
		// { "success": false, "error": { "code": "...", "message": "...", "request_id": "..." } }
		var errObj struct {
			Success bool `json:"success"`
			Error   struct {
				Code      string `json:"code"`
				Message   string `json:"message"`
				RequestID string `json:"request_id"`
			} `json:"error"`
		}
		if err := json.Unmarshal(body, &errObj); err == nil && errObj.Error.Message != "" {
			apiErr.Message = errObj.Error.Message
			apiErr.Code = errObj.Error.Code
			apiErr.RequestID = errObj.Error.RequestID
		} else {
			// Fall back to flat error format: { "error": "string", "code": "..." },
			// or API Gateway's own { "message": "..." }.
			var errResp struct {
				Error   string `json:"error"`
				Message string `json:"message"`
				Code    string `json:"code"`
			}

			if err := json.Unmarshal(body, &errResp); err == nil {
				if errResp.Error != "" {
					apiErr.Message = errResp.Error
				} else if errResp.Message != "" {
					apiErr.Message = errResp.Message
				}
				apiErr.Code = errResp.Code
			} else {
				apiErr.Message = string(body)
			}
		}
	}

	bodySeconds, bodyOK := applyRetryGuidance(apiErr, body)

	// The reported value prefers the body, which states it as a number.
	switch {
	case bodyOK:
		apiErr.RetryAfter = wholeSeconds(bodySeconds)
	case headerOK:
		apiErr.RetryAfter = wholeSeconds(headerSeconds)
	}
	// The wait prefers the header, which is what HTTP intermediaries honour.
	switch {
	case headerOK:
		apiErr.serverDelay, apiErr.hasServerDelay = clampRetryAfter(headerSeconds), true
		apiErr.serverDelayOverCap = headerSeconds > MaxRetryAfter.Seconds()
	case bodyOK:
		apiErr.serverDelay, apiErr.hasServerDelay = clampRetryAfter(bodySeconds), true
		apiErr.serverDelayOverCap = bodySeconds > MaxRetryAfter.Seconds()
	}

	// Set default message based on status code
	if apiErr.Message == "Unknown error" {
		switch statusCode {
		case 401:
			apiErr.Message = "Invalid or missing API key"
		case 402:
			apiErr.Message = "Insufficient credits"
		case 404:
			apiErr.Message = "Resource not found"
		case 429:
			apiErr.Message = "Rate limit exceeded"
		case 500:
			apiErr.Message = "Internal server error"
		}
	}

	return apiErr
}

// applyRetryGuidance copies the envelope's retry fields onto apiErr and
// returns the body's retry_after_seconds when it is usable. Each field is
// read only when it has the documented type: decoding into any and checking,
// because json.Unmarshal of null into a bool is false with no error.
func applyRetryGuidance(apiErr *APIError, body []byte) (float64, bool) {
	var envelope struct {
		Error json.RawMessage `json:"error"`
	}
	if len(body) == 0 || json.Unmarshal(body, &envelope) != nil || len(envelope.Error) == 0 {
		return 0, false
	}
	var fields map[string]any
	if json.Unmarshal(envelope.Error, &fields) != nil {
		return 0, false
	}
	if retryable, ok := fields["retryable"].(bool); ok {
		apiErr.Retryable = &retryable
	}
	apiErr.RetryRequiresSameIdempotencyKey = fields["retry_requires_same_idempotency_key"] == true
	apiErr.RetryMayChargeAgain = fields["retry_may_charge_again"] == true
	if seconds, ok := fields["retry_after_seconds"].(float64); ok && seconds >= 0 && !math.IsInf(seconds, 0) && !math.IsNaN(seconds) {
		return seconds, true
	}
	return 0, false
}

// parseRetryAfterSeconds reads a Retry-After header given in seconds: digits
// with an optional decimal fraction. Anything else (empty, negative, an
// HTTP-date, text, exponent notation) is unusable and reported as such, so
// the caller falls back to its own backoff.
func parseRetryAfterSeconds(value string) (float64, bool) {
	if value == "" {
		return 0, false
	}
	digits, dot := 0, false
	for i := 0; i < len(value); i++ {
		switch ch := value[i]; {
		case ch >= '0' && ch <= '9':
			digits++
		case ch == '.' && !dot && digits > 0 && i < len(value)-1:
			dot = true
		default:
			return 0, false
		}
	}
	seconds, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsInf(seconds, 0) || math.IsNaN(seconds) {
		return 0, false
	}
	return seconds, true
}

// wholeSeconds rounds a non-negative delay up to whole seconds, saturating
// rather than overflowing int on an absurd value.
func wholeSeconds(seconds float64) int {
	const ceiling = float64(math.MaxInt32)
	if seconds >= ceiling {
		return math.MaxInt32
	}
	return int(math.Ceil(seconds))
}

// clampRetryAfter converts a non-negative delay in seconds to a wait of at
// most MaxRetryAfter.
func clampRetryAfter(seconds float64) time.Duration {
	if seconds >= MaxRetryAfter.Seconds() {
		return MaxRetryAfter
	}
	return time.Duration(seconds * float64(time.Second))
}

// IncompleteExportError means the API could not certify that an export is
// the whole job result set. Complete points to false for a measured shortfall
// and is nil when no comparison was possible. Callers must not process the
// returned file in either case.
type IncompleteExportError struct {
	JobID        string
	Complete     *bool
	ExpectedRows *int
	RowsMissing  *int
	Message      string
	// API response metadata is populated when the route refused an inline
	// measured-short export with HTTP 409. It is zero-valued for a 200
	// completeness envelope.
	StatusCode int
	Code       string
	RequestID  string
}

func (e *IncompleteExportError) Error() string {
	return fmt.Sprintf("kawaa: %s", e.Message)
}

// Retryable reports whether this was a measured shortfall that will normally
// clear after the eventually-consistent results index catches up.
func (e *IncompleteExportError) Retryable() bool {
	return e.Complete != nil && !*e.Complete
}
