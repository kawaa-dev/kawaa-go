// Package kawaa provides a Go client for the Kawaa Email Verification API.
//
// Example usage:
//
//	client := kawaa.NewClient("your-api-key")
//	result, err := client.Verify(context.Background(), "test@example.com")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Status: %s, Score: %d\n", result.Status, result.Score)
package kawaa

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the default API base URL.
	DefaultBaseURL = "https://api.kawaa.com"

	// DefaultTimeout is the default request timeout.
	DefaultTimeout = 30 * time.Second

	// DefaultMaxRetries is the default number of retries after the first
	// attempt (so up to four requests in all).
	DefaultMaxRetries = 3

	// DefaultPollInterval is the default interval for polling job status.
	DefaultPollInterval = 2 * time.Second

	// DefaultPollTimeout is the default timeout for waiting for job completion.
	DefaultPollTimeout = 5 * time.Minute

	// SDKVersion is the current SDK version.
	SDKVersion = "0.3.3"
)

// Client is the Kawaa API client.
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
	maxRetries int
	userAgent  string

	// timeout is the WithTimeout value, or nil. It is applied after every
	// option has run, so it holds whether WithHTTPClient comes before or
	// after it.
	timeout *time.Duration

	// retryBaseDelay is the unit of the exponential backoff between
	// attempts (1x, 2x, 4x, ...). Tests shorten it.
	retryBaseDelay time.Duration

	// replayPollInterval is the wait between reads of the job behind an
	// idempotent verify replay (see resolveVerifyReplay). Tests shorten it.
	replayPollInterval time.Duration
}

const (
	// defaultReplayPollInterval and replayPollMaxReads bound how long Verify
	// waits for the job behind an idempotent replay: at most three reads,
	// two seconds apart. A short poll, not WaitForJob: past it the caller
	// gets the pending answer and the job id to poll themselves.
	defaultReplayPollInterval = 2 * time.Second
	replayPollMaxReads        = 3
)

// ClientOption is a function that configures a Client.
type ClientOption func(*Client)

// WithBaseURL sets a custom base URL for the API.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) {
		c.baseURL = baseURL
	}
}

// WithHTTPClient sets a custom HTTP client. Its Timeout is used unless
// WithTimeout is also given, in either order. A nil client is ignored.
//
// The client uses a copy of it that never follows a redirect (its
// CheckRedirect is replaced), so the *http.Client you pass is not changed:
// see NewClient.
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *Client) {
		if httpClient != nil {
			c.httpClient = httpClient
		}
	}
}

// WithTimeout sets the request timeout. It applies whether it comes before or
// after WithHTTPClient, and never changes the *http.Client you passed there:
// the client uses a copy of it with this timeout.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.timeout = &timeout
	}
}

// WithMaxRetries sets how many times a failed request may be retried after
// its first attempt. 0 sends each request once; a negative value counts as 0.
func WithMaxRetries(maxRetries int) ClientOption {
	return func(c *Client) {
		c.maxRetries = maxRetries
	}
}

// NewClient creates a new Kawaa API client.
//
// API requests never follow a redirect. Every request carries the API key in
// X-Api-Key, and net/http keeps that header when it follows a redirect to
// another host (it drops only Authorization, Cookie and the like), so
// following one would send the key to wherever it points. The Kawaa API never
// redirects; a 3xx answer is returned as an *APIError with that status, which
// is not retried. The presigned download of a large export, which carries no
// key, is not affected.
func NewClient(apiKey string, opts ...ClientOption) *Client {
	c := &Client{
		apiKey:  apiKey,
		baseURL: DefaultBaseURL,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		maxRetries:         DefaultMaxRetries,
		userAgent:          fmt.Sprintf("kawaa-go/%s", SDKVersion),
		retryBaseDelay:     time.Second,
		replayPollInterval: defaultReplayPollInterval,
	}

	for _, opt := range opts {
		opt(c)
	}
	// A copy, so a client passed to WithHTTPClient is never changed.
	apiClient := *c.httpClient
	if c.timeout != nil {
		apiClient.Timeout = *c.timeout
	}
	apiClient.CheckRedirect = refuseRedirect
	c.httpClient = &apiClient

	return c
}

// refuseRedirect is the API client's CheckRedirect: it never follows a
// redirect, and hands the 3xx back so doRequest can refuse it.
func refuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// redirectRefused is the error for a 3xx answer. It names where the redirect
// pointed (the origin only, never a path or query), so a wrong base URL, such
// as an http:// address answered by a redirect to https://, is plain to see.
func redirectRefused(resp *http.Response) *APIError {
	target := ""
	if location, err := resp.Location(); err == nil && location.Host != "" {
		target = " to " + location.Scheme + "://" + location.Host
	}
	return &APIError{
		StatusCode: resp.StatusCode,
		Message: fmt.Sprintf("The API answered HTTP %d, a redirect%s. This client does not follow redirects, "+
			"because the request carries your API key and following one would send the key on to wherever it "+
			"points. The Kawaa API never redirects, so check the base URL this client was given (the default is %s).",
			resp.StatusCode, target, DefaultBaseURL),
	}
}

// request makes an HTTP request with retry logic. See send.
func (c *Client) request(ctx context.Context, method, path string, body interface{}, query url.Values, idempotencyKey string) ([]byte, error) {
	return c.send(ctx, method, path, body, query, idempotencyKey, false)
}

// send makes an HTTP request, retrying it while that is safe.
//
// It makes at most maxRetries+1 attempts: WithMaxRetries(0) sends one
// request and never repeats it.
//
// Only a request the server can safely receive twice is retried after a 5xx,
// a timeout or a dropped connection: one that carries an Idempotency-Key
// (Verify, VerifyBatch and Find), which the API replays without another
// charge, or a GET that charges nothing. charging marks a call that costs
// credits without honouring a key (DomainSearch, a GET that costs 10): it is
// sent once, because the API may have charged before it failed. Rate limits
// (429) are retried for every method: the limiter refuses before anything is
// charged. A keyed request refused with a retryable 409 (a copy under the
// same key is still in flight) is retried with the same key. A failure to
// connect at all (DNS lookup, connection refused) never reached the API and
// is retried for every method. Nothing is retried when the API says a repeat
// may charge again (retry_may_charge_again).
//
// The wait before a retry is the delay the API named (Retry-After, or the
// body's retry_after_seconds), or else exponential backoff. An answer that
// names a delay longer than MaxRetryAfter is not retried at all: waiting
// less than the API asked would only be refused again.
//
// Every error it returns carries the call's key: an *APIError with
// IdempotencyKey set, or a *RequestError for anything else.
func (c *Client) send(ctx context.Context, method, path string, body interface{}, query url.Values, idempotencyKey string, charging bool) ([]byte, error) {
	keyed := idempotencyKey != ""
	replaySafe := keyed || (method == http.MethodGet && !charging)

	maxAttempts := c.maxRetries + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	var lastErr error
	attempts := 0

	for attempt := 0; attempt < maxAttempts; attempt++ {
		attempts = attempt + 1
		respBody, err := c.doRequest(ctx, method, path, body, query, idempotencyKey)
		if err == nil {
			return respBody, nil
		}
		lastErr = err

		delay, retry := c.retryAfterFailure(err, attempt, keyed, replaySafe)
		if !retry || attempt == maxAttempts-1 {
			break
		}

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, &RequestError{IdempotencyKey: idempotencyKey, Attempts: attempts, Err: ctx.Err()}
		case <-timer.C:
		}
	}

	var apiErr *APIError
	if errors.As(lastErr, &apiErr) {
		apiErr.IdempotencyKey = idempotencyKey
		apiErr.Attempts = attempts
		return nil, apiErr
	}
	return nil, &RequestError{IdempotencyKey: idempotencyKey, Attempts: attempts, Err: lastErr}
}

// retryAfterFailure decides whether a failed attempt may be sent again, and
// how long to wait first.
func (c *Client) retryAfterFailure(err error, attempt int, keyed, replaySafe bool) (time.Duration, bool) {
	var unreadable *unreadableBodyError
	if errors.As(err, &unreadable) {
		// The API answered; repeating it would not make the answer readable.
		return 0, false
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		// A timeout or dropped connection after the request went out: the
		// server may have acted (and charged). A failed dial sent nothing.
		return c.backoff(attempt), replaySafe || failedBeforeSend(err)
	}

	switch {
	case apiErr.RetryMayChargeAgain:
		// The API says this attempt may have been charged and no key can
		// replay it: never repeated automatically.
		return 0, false
	case apiErr.Retryable != nil && !*apiErr.Retryable:
		// The API's own answer that waiting cannot cure it (a 501, a 503 for
		// an integration that is not configured), whatever the status.
		return 0, false
	case apiErr.StatusCode == http.StatusTooManyRequests:
		// Rate limited: nothing was charged, so every method retries.
	case apiErr.StatusCode == http.StatusConflict && keyed && apiErr.Retryable != nil && *apiErr.Retryable:
		// A copy under the same key is still in flight; the same key
		// replays its result once it lands.
	case apiErr.StatusCode >= 500 && replaySafe:
		// Safe to repeat: a free GET, or a request replayed under its key.
	default:
		// A client error, or a 5xx on a charging request that may already
		// have been charged: surface it unchanged.
		return 0, false
	}
	if apiErr.serverDelayOverCap {
		// The API asked for a longer wait than this client makes on its
		// own (the API edge refuses a blocked address for 3,900 seconds):
		// returned at once with the API's value on RetryAfter.
		return 0, false
	}
	return c.retryDelay(apiErr, attempt), true
}

// retryDelay is the wait before retrying after apiErr: the delay the API
// named, already limited to MaxRetryAfter, or else exponential backoff.
func (c *Client) retryDelay(apiErr *APIError, attempt int) time.Duration {
	if apiErr != nil && apiErr.hasServerDelay {
		return apiErr.serverDelay
	}
	return c.backoff(attempt)
}

// backoff returns the delay after the given zero-based attempt.
func (c *Client) backoff(attempt int) time.Duration {
	unit := c.retryBaseDelay
	if unit <= 0 {
		unit = time.Second
	}
	return time.Duration(1<<attempt) * unit
}

// failedBeforeSend reports whether a transport error certainly happened
// before any byte of the request was sent: the DNS lookup or the TCP dial
// failed (for example connection refused). net/http surfaces both as a
// *net.OpError with Op "dial" (or a *net.DNSError). A failure on an
// established connection (a write or read error, a reset, a client timeout)
// is none of these, so it is never mistaken for a safe retry.
func failedBeforeSend(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}

// newIdempotencyKey returns a random UUID v4 naming one logical request.
func newIdempotencyKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("failed to generate idempotency key: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// resolveIdempotencyKey returns the caller's key, or a fresh one when unset.
func resolveIdempotencyKey(key string) (string, error) {
	if key != "" {
		return key, nil
	}
	return newIdempotencyKey()
}

// doRequest performs a single HTTP request.
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}, query url.Values, idempotencyKey string) ([]byte, error) {
	fullURL := c.baseURL + path
	if len(query) > 0 {
		fullURL += "?" + query.Encode()
	}

	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Returned as is: send wraps it in a *RequestError that says the
		// request failed, how many times, and under which key.
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		// Not followed (refuseRedirect), and not retried: the same request
		// meets the same redirect. send puts the call's key on the error.
		return nil, redirectRefused(resp)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, parseAPIError(resp.StatusCode, respBody, resp.Header)
	}

	// Every API answer is a JSON object. Anything else (not JSON, null, a
	// list) would decode into an empty result for a call that may have been
	// charged, so it is refused; send puts the call's key on the error.
	if trimmed := bytes.TrimSpace(respBody); len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
		return nil, &unreadableBodyError{status: resp.StatusCode}
	}

	// Unwrap response envelope: { "success": true, "data": { ... } }
	// Success is read as a real boolean: absent is not false.
	var envelope struct {
		Success json.RawMessage `json:"success"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(respBody, &envelope); err == nil {
		success := optionalBool(envelope.Success)
		if success != nil && *success && envelope.Data != nil {
			return []byte(envelope.Data), nil
		}
		if success != nil && !*success {
			// The API's own failure, even though the status was < 400.
			// Mapped as data it would read as an empty result.
			return nil, parseAPIError(resp.StatusCode, respBody, resp.Header)
		}
	}

	// Fall back to raw body if not an envelope format
	return respBody, nil
}

// VerifyOptions contains options for email verification.
//
// These are the options the API accepts: deep_verify, include_ai, enrich,
// timeout_ms, skip_cache. The old check_mx / check_smtp / check_catch_all /
// use_ai names were never real API options (MX and catch-all checks always
// run server-side).
//
// A field left at its zero value is not sent, so the API's default applies.
// DeepVerify and IncludeAI default to on, so they are pointers: set
// kawaa.Bool(false) to turn one off.
type VerifyOptions struct {
	// DeepVerify performs deep (SMTP-level) verification. nil leaves the
	// API's default, which is on.
	DeepVerify *bool `json:"deep_verify,omitempty"`
	// IncludeAI enables AI typo detection / catch-all confidence. nil leaves
	// the API's default, which is on.
	IncludeAI *bool `json:"include_ai,omitempty"`
	// Enrich opts in to data enrichment (name, gender, country); default: false.
	Enrich bool `json:"enrich,omitempty"`
	// TimeoutMs bounds how long Verify waits for a synchronous result, in
	// milliseconds. Verify only: the API refuses it on a batch with
	// 400 INVALID_OPTION.
	TimeoutMs int `json:"timeout_ms,omitempty"`
	// SkipCache bypasses the verification cache (default: false).
	SkipCache bool `json:"skip_cache,omitempty"`
	// IdempotencyKey is sent as the Idempotency-Key header, not in the
	// request body. When empty a random key is generated per call, so a
	// retry after a timeout or 5xx never charges twice; supply your own to
	// make repeats of the same logical request from your side safe too.
	IdempotencyKey string `json:"-"`
}

// Bool returns a pointer to v, for VerifyOptions.DeepVerify and IncludeAI.
func Bool(v bool) *bool {
	return &v
}

// DefaultVerifyOptions returns the default verification options: the API's
// own defaults, stated explicitly.
func DefaultVerifyOptions() VerifyOptions {
	return VerifyOptions{
		DeepVerify: Bool(true),
		IncludeAI:  Bool(true),
	}
}

// Verify verifies a single email address.
//
// A result with Status StatusPending carries a JobID: the synchronous poll
// window elapsed before the worker finished, so poll GetJobStatus(JobID).
//
// Every call carries an Idempotency-Key, so a retry after a timeout or 5xx
// cannot charge twice. When an earlier attempt had already been accepted,
// the API answers the retry with a replay that says only "pending" and the
// original job's id; Verify then reads that job back (briefly polling while
// it is still running) and returns the finished result with
// IdempotentReplay set. See VerificationResult.IdempotentReplay.
func (c *Client) Verify(ctx context.Context, email string, opts ...VerifyOptions) (*VerificationResult, error) {
	options := DefaultVerifyOptions()
	if len(opts) > 0 {
		options = opts[0]
	}

	body := map[string]interface{}{
		"email":   email,
		"options": options,
	}

	idempotencyKey, err := resolveIdempotencyKey(options.IdempotencyKey)
	if err != nil {
		return nil, err
	}

	respBody, err := c.request(ctx, http.MethodPost, "/v1/verify", body, nil, idempotencyKey)
	if err != nil {
		return nil, err
	}

	var result VerificationResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		// The request succeeded, so it was charged: the key lets a repeat
		// replay it instead of paying again.
		return nil, &RequestError{IdempotencyKey: idempotencyKey, Err: fmt.Errorf("failed to parse response: %w", err)}
	}

	if result.IdempotentReplay != nil && *result.IdempotentReplay && result.JobID != "" {
		return c.resolveVerifyReplay(ctx, &result), nil
	}

	return &result, nil
}

// replayJob is the part of GET /v1/jobs/{id} that resolveVerifyReplay reads.
// Raw messages throughout, so no field of the job can fail the read of
// another: this is best-effort enrichment of an answer Verify already has.
type replayJob struct {
	Status          JobStatus         `json:"status"`
	Results         []json.RawMessage `json:"results"`
	CreditsUsed     json.RawMessage   `json:"credits_used"`
	CreditsRefunded json.RawMessage   `json:"credits_refunded"`
	// CacheDiscountPending is true on a completed job whose result was
	// served from cache but whose 0.5 cache-discount refund this read could
	// not apply; the next read retries it. Until then the charge is not final.
	CacheDiscountPending json.RawMessage `json:"cache_discount_pending"`
}

// resolveVerifyReplay turns an idempotent verify replay back into the result
// it stands for.
//
// A replay says only "pending", with credits_used 0 and the job id of the
// attempt that was charged, even when that job finished long ago. Returned
// as-is, a completed verification read as unfinished and free: the SDK's own
// retry after a lost response turned the caller's one paid verification into
// a pending one at zero cost. So the job is read back (every few seconds
// while it is still running, at most replayPollMaxReads times) and a
// completed result is returned in the replay's place, with IdempotentReplay
// set and CreditsUsed the job's net cost.
//
// A completed read that says cache_discount_pending is final for the verdict
// but not for the bill: the worker served a cached result and the discount
// refund has not been applied yet (each read retries it). Such a read is
// read again while reads remain; if the last one still says so, the verdict
// is returned with CreditsUsed nil (not measured) rather than the
// pre-discount charge. That verdict is kept once read: a later read that
// fails or finds nothing usable returns it, not the pending replay.
//
// This never fails. The POST succeeded and the verification was paid for;
// an error here would drive the caller to retry under a fresh key and pay
// again. Short of a verdict ever having been read (the job still running
// after the short poll, a terminal job with no result, or a read that failed
// for any reason: a key without verification:read, a network error, the
// caller's context ending), it returns the replay itself: pending, with the
// job id to poll and the marker saying nothing more was charged. Its
// CreditsUsed is nil: the replay's own 0 is what the repeat cost, and the
// verification's cost is on the job.
func (c *Client) resolveVerifyReplay(ctx context.Context, replay *VerificationResult) *VerificationResult {
	replay.CreditsUsed = nil
	interval := c.replayPollInterval
	if interval <= 0 {
		interval = defaultReplayPollInterval
	}
	query := url.Values{}
	query.Set("include_results", "true")
	path := "/v1/jobs/" + url.PathEscape(replay.JobID)

	// A verdict read on a completed job whose cache discount was still
	// pending: final for the result, not for the bill (CreditsUsed nil). Once
	// read it is kept, so a later read that fails, or finds nothing usable,
	// cannot turn a verdict the caller has effectively received back into
	// "pending". The replay itself is the answer only when no verdict was
	// ever read.
	var kept *VerificationResult
	fallback := func() *VerificationResult {
		if kept != nil {
			return kept
		}
		return replay
	}

	for read := 1; ; read++ {
		respBody, err := c.request(ctx, http.MethodGet, path, nil, query, "")
		if err != nil {
			return fallback()
		}
		var job replayJob
		if err := json.Unmarshal(respBody, &job); err != nil {
			return fallback()
		}

		switch job.Status {
		case JobStatusCompleted:
			discountPending := optionalBool(job.CacheDiscountPending)
			if discountPending == nil || !*discountPending {
				if resolved := resolvedReplayResult(replay, &job, true); resolved != nil {
					return resolved
				}
				return fallback()
			}
			// The verdict is in but the discount is not: keep the verdict,
			// then wait and read again while reads remain; the re-read
			// retries the settlement server-side.
			if resolved := resolvedReplayResult(replay, &job, false); resolved != nil {
				kept = resolved
			}
		case JobStatusFailed, JobStatusCancelled:
			// Terminal without a verdict (a failed job's refund shows on
			// the job): the caller polls it by id.
			return fallback()
		}

		if read >= replayPollMaxReads {
			return fallback()
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fallback()
		case <-timer.C:
		}
	}
}

// resolvedReplayResult builds the result a completed job stands for, or nil
// when the job carries no readable result. costFinal is false when the job's
// cache discount was still pending on this read: CreditsUsed is then left
// nil, never the pre-discount charge.
func resolvedReplayResult(replay *VerificationResult, job *replayJob, costFinal bool) *VerificationResult {
	if len(job.Results) == 0 {
		return nil
	}
	// The first result must be an object with a string status: the same
	// shape POST /v1/verify answers with.
	var probe map[string]json.RawMessage
	if json.Unmarshal(job.Results[0], &probe) != nil || probe == nil {
		return nil
	}
	var status string
	if raw, ok := probe["status"]; !ok || json.Unmarshal(raw, &status) != nil {
		return nil
	}

	var resolved VerificationResult
	if err := json.Unmarshal(job.Results[0], &resolved); err != nil {
		return nil
	}
	if resolved.Email == "" {
		resolved.Email = replay.Email
	}
	resolved.JobID = replay.JobID
	resolved.Message = ""
	resolved.CreditsHeld = nil
	replayed := true
	resolved.IdempotentReplay = &replayed
	// The balance the ledger recorded right after the original charge, as
	// the replay reported it; nil when the replay omitted it.
	resolved.CreditsRemaining = replay.CreditsRemaining
	// What the verification cost: the job's charge less what came back (the
	// cache discount on a result served from cache), the figure the
	// synchronous response and the verification.completed webhook report.
	if !costFinal {
		// The discount is still owed: the job's charge minus its refunds
		// would overstate the cost, and the replay's 0 understate it.
		resolved.CreditsUsed = nil
		return &resolved
	}
	// A job read without a numeric charge leaves the cost unknown (nil), not
	// the replay's 0.
	resolved.CreditsUsed = nil
	if charged := optionalNumber(job.CreditsUsed); charged != nil {
		cost := *charged
		if refunded := optionalNumber(job.CreditsRefunded); refunded != nil {
			cost -= *refunded
		}
		resolved.CreditsUsed = &cost
	}
	return &resolved
}

// BatchOptions contains options for batch verification. The embedded
// VerifyOptions.IdempotencyKey is sent as the batch's Idempotency-Key header.
// Options left unset are not sent, so BatchOptions{WebhookURL: url} runs the
// API's default checks (deep verification and AI on).
type BatchOptions struct {
	WebhookURL    string `json:"webhook_url,omitempty"`
	WebhookSecret string `json:"webhook_secret,omitempty"`
	VerifyOptions
}

// VerifyBatch starts a batch email verification job.
func (c *Client) VerifyBatch(ctx context.Context, emails []string, opts ...BatchOptions) (*BatchJobResult, error) {
	options := BatchOptions{
		VerifyOptions: DefaultVerifyOptions(),
	}
	if len(opts) > 0 {
		options = opts[0]
	}

	body := map[string]interface{}{
		"emails":  emails,
		"options": options.VerifyOptions,
	}

	if options.WebhookURL != "" {
		body["webhook_url"] = options.WebhookURL
	}
	if options.WebhookSecret != "" {
		body["webhook_secret"] = options.WebhookSecret
	}

	idempotencyKey, err := resolveIdempotencyKey(options.IdempotencyKey)
	if err != nil {
		return nil, err
	}

	respBody, err := c.request(ctx, http.MethodPost, "/v1/verify/batch", body, nil, idempotencyKey)
	if err != nil {
		return nil, err
	}

	var result BatchJobResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		// The request succeeded, so it was charged: the key lets a repeat
		// replay it instead of paying again.
		return nil, &RequestError{IdempotencyKey: idempotencyKey, Err: fmt.Errorf("failed to parse response: %w", err)}
	}

	return &result, nil
}

// VerifyBatchAndWait starts a batch job and waits for completion.
func (c *Client) VerifyBatchAndWait(ctx context.Context, emails []string, pollInterval, timeout time.Duration, opts ...BatchOptions) (*JobStatusResult, error) {
	if pollInterval == 0 {
		pollInterval = DefaultPollInterval
	}
	if timeout == 0 {
		timeout = DefaultPollTimeout
	}

	options := BatchOptions{VerifyOptions: DefaultVerifyOptions()}
	if len(opts) > 0 {
		options = opts[0]
	}
	// Resolved here rather than inside VerifyBatch, so a failure while
	// waiting carries the batch's key too: repeating the whole call under it
	// replays the paid batch and waits again, where a fresh key buys it twice.
	idempotencyKey, err := resolveIdempotencyKey(options.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	options.IdempotencyKey = idempotencyKey

	job, err := c.VerifyBatch(ctx, emails, options)
	if err != nil {
		return nil, err
	}

	status, err := c.WaitForJob(ctx, job.JobID, pollInterval, timeout)
	if err != nil {
		return nil, withIdempotencyKey(err, idempotencyKey)
	}
	return status, nil
}

// GetJobStatus gets the status of a batch verification job.
//
// When includeResults is true the API returns only the FIRST page of
// results (100 per page); JobStatusResult.NextKey / HasMore describe
// further pages. Use DownloadResults to fetch the complete result set.
func (c *Client) GetJobStatus(ctx context.Context, jobID string, includeResults bool) (*JobStatusResult, error) {
	query := url.Values{}
	// The API defaults include_results to true, so send it explicitly.
	if includeResults {
		query.Set("include_results", "true")
	} else {
		query.Set("include_results", "false")
	}

	respBody, err := c.request(ctx, http.MethodGet, "/v1/jobs/"+jobID, nil, query, "")
	if err != nil {
		return nil, err
	}

	var result JobStatusResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// WaitForJob waits for a batch job to complete.
func (c *Client) WaitForJob(ctx context.Context, jobID string, pollInterval, timeout time.Duration) (*JobStatusResult, error) {
	if pollInterval == 0 {
		pollInterval = DefaultPollInterval
	}
	if timeout == 0 {
		timeout = DefaultPollTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		status, err := c.GetJobStatus(ctx, jobID, true)
		if err != nil {
			return nil, err
		}

		if status.IsCompleted() {
			return status, nil
		}

		// The status, not settlement: a cancelled job's verdicts are final the moment
		// it reads `cancelled`, because the worker commits each result under a
		// condition on the running statuses. Only the refund is still outstanding.
		if status.IsCancelled() {
			return status, nil
		}

		if status.IsFailed() {
			if status.ErrorMessage != "" {
				return nil, fmt.Errorf("job %s failed: %s", jobID, status.ErrorMessage)
			}
			return nil, fmt.Errorf("job %s failed", jobID)
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout waiting for job %s (progress: %.1f%%): %w", jobID, status.ProgressPercent, ctx.Err())
		case <-ticker.C:
		}
	}
}

// DownloadResults downloads results from a completed batch job.
//
// The endpoint returns FLAT rows ({email, status, score, ...}), not the
// nested VerificationResult shape. Jobs with more than 1000 results return
// a presigned download URL, which is fetched transparently so Results is
// always populated.
func (c *Client) DownloadResults(ctx context.Context, jobID string) (*DownloadResult, error) {
	query := url.Values{}
	query.Set("format", "json")

	respBody, err := c.request(ctx, http.MethodGet, "/v1/jobs/"+jobID+"/download", nil, query, "")
	if err != nil {
		return nil, translateExportConflict(jobID, err)
	}

	var result DownloadResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	if err := ensureExportComplete(jobID, &result); err != nil {
		return nil, err
	}

	// >1000-result shape ({download_url, format, result_count,
	// expires_in_seconds}): fetch the presigned URL so Results is populated.
	if result.DownloadURL != "" && len(result.Results) == 0 {
		content, err := c.fetchDownloadURL(ctx, result.DownloadURL)
		if err != nil {
			return nil, err
		}
		var rows []DownloadRow
		if err := json.Unmarshal(content, &rows); err != nil {
			return nil, fmt.Errorf("failed to parse downloaded results: %w", err)
		}
		result.JobID = jobID
		result.Results = rows
		if result.ResultCount == 0 {
			result.ResultCount = len(rows)
		}
	}

	return &result, nil
}

// DownloadResultsCSV downloads results as CSV from a completed batch job.
//
// Jobs with more than 1000 results return a JSON envelope with a presigned
// download URL instead of the CSV body; it is fetched transparently. Any
// other JSON response is an error; JSON must never be handed back as
// "CSV" (the Content-Type decides, matching the other SDKs' CSV paths).
func (c *Client) DownloadResultsCSV(ctx context.Context, jobID string) (string, error) {
	fullURL := c.baseURL + "/v1/jobs/" + jobID + "/download?format=csv"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		// Not followed (refuseRedirect); its body is not the export.
		return "", redirectRefused(resp)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return "", translateExportConflict(jobID, parseAPIError(resp.StatusCode, respBody, resp.Header))
	}

	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		// The only legitimate JSON response is the >1000-result envelope
		// ({download_url, ...}); follow it.
		var envelope DownloadResult
		if err := json.Unmarshal(respBody, &envelope); err == nil && envelope.DownloadURL != "" {
			if err := ensureExportComplete(jobID, &envelope); err != nil {
				return "", err
			}
			content, err := c.fetchDownloadURL(ctx, envelope.DownloadURL)
			if err != nil {
				return "", err
			}
			return string(content), nil
		}
		return "", fmt.Errorf("unexpected JSON response for CSV download")
	}

	return string(respBody), nil
}

// translateExportConflict maps the download route's retryable 409 onto the
// same typed error as a measured-short success envelope. Other endpoints use
// 409 for unrelated conflicts, so this translation stays scoped here.
func translateExportConflict(jobID string, err error) error {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusConflict || apiErr.Code != "CONFLICT" {
		return err
	}

	complete := false
	return &IncompleteExportError{
		JobID:      jobID,
		Complete:   &complete,
		Message:    apiErr.Message,
		StatusCode: apiErr.StatusCode,
		Code:       apiErr.Code,
		RequestID:  apiErr.RequestID,
	}
}

func ensureExportComplete(jobID string, result *DownloadResult) error {
	if result.Complete != nil && *result.Complete {
		return nil
	}

	message := result.Message
	if message == "" {
		if result.Complete != nil {
			message = fmt.Sprintf("Export for job %s is incomplete. Retry the download in a few seconds.", jobID)
		} else {
			message = fmt.Sprintf(
				"Completeness of the export for job %s could not be verified. Do not treat it as the whole result set.",
				jobID,
			)
		}
	}

	return &IncompleteExportError{
		JobID:        jobID,
		Complete:     result.Complete,
		ExpectedRows: result.ExpectedRows,
		RowsMissing:  result.RowsMissing,
		Message:      message,
	}
}

// fetchDownloadURL fetches the body of a presigned results download URL.
//
// It deliberately uses a dedicated clean http.Client (default transport,
// same timeout) instead of c.httpClient: a client injected via
// WithHTTPClient may carry a RoundTripper that adds the X-Api-Key header
// to every request, which would leak the credential to the presigned host
// (S3/third-party infrastructure). The presigned URL itself is the
// credential, so this request must carry none.
func (c *Client) fetchDownloadURL(ctx context.Context, downloadURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create download request: %w", err)
	}

	cleanClient := &http.Client{Timeout: c.httpClient.Timeout}

	resp, err := cleanClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("failed to fetch results from download URL (HTTP %d)", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// DomainSearch searches for email addresses at a domain.
//
// The first uncached call starts an async discovery job and returns
// Status == "processing" with an empty Emails list; re-call DomainSearch
// to poll until result.IsProcessing() is false.
func (c *Client) DomainSearch(ctx context.Context, domain string) (*DomainSearchResult, error) {
	// Charges 10 credits and honours no Idempotency-Key, so it is never
	// re-sent after a 5xx or a timeout: the attempt may have been charged.
	respBody, err := c.send(ctx, http.MethodGet, "/v1/domain/"+domain, nil, nil, "", true)
	if err != nil {
		return nil, err
	}

	var result DomainSearchResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// Find finds a business email address by name and domain.
// FindOptions controls a Find call.
type FindOptions struct {
	// IdempotencyKey is sent as the Idempotency-Key header. A repeat of the
	// same search under the same key replays the stored result and charges
	// nothing (the receipt lasts 30 days). Generated when unset. Pass your
	// own whenever you may need to retry, and reuse that value on the retry.
	IdempotencyKey string `json:"-"`
}

// Find finds a business email address by name and domain. It charges 5
// credits, so every call carries an Idempotency-Key: a retry after a lost
// response replays the original search instead of buying it again.
func (c *Client) Find(ctx context.Context, firstName, lastName, domain string, opts ...FindOptions) (*FindResult, error) {
	var options FindOptions
	if len(opts) > 0 {
		options = opts[0]
	}

	body := map[string]string{
		"first_name": firstName,
		"last_name":  lastName,
		"domain":     domain,
	}

	idempotencyKey, err := resolveIdempotencyKey(options.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	respBody, err := c.request(ctx, http.MethodPost, "/v1/find", body, nil, idempotencyKey)
	if err != nil {
		return nil, err
	}

	var result FindResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		// The request succeeded, so it was charged: the key lets a repeat
		// replay it instead of paying again.
		return nil, &RequestError{IdempotencyKey: idempotencyKey, Err: fmt.Errorf("failed to parse response: %w", err)}
	}

	return &result, nil
}

// GetAccount gets account information.
func (c *Client) GetAccount(ctx context.Context) (*AccountInfo, error) {
	respBody, err := c.request(ctx, http.MethodGet, "/v1/account", nil, nil, "")
	if err != nil {
		return nil, err
	}

	var result AccountInfo
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}
