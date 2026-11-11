package kawaa

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// When this client stops retrying a keyed call, the key it sent must reach
// the caller: the API's remedy for a lost or in-flight charged request is to
// repeat it with the SAME key, and a fresh key pays again.

type scriptedResponse struct {
	status int
	header map[string]string
	body   string
	delay  time.Duration
}

// scriptedAPI answers the i-th request with replies[i] (the last repeats) and
// records the Idempotency-Key of every request it received.
type scriptedAPI struct {
	mu      sync.Mutex
	replies []scriptedResponse
	keys    []string
}

func (a *scriptedAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Read the body first: the server notices a client that gave up (and
	// cancels r.Context()) only once the body has been consumed.
	_, _ = io.Copy(io.Discard, r.Body)
	a.mu.Lock()
	i := len(a.keys)
	a.keys = append(a.keys, r.Header.Get("Idempotency-Key"))
	reply := a.replies[len(a.replies)-1]
	if i < len(a.replies) {
		reply = a.replies[i]
	}
	a.mu.Unlock()

	if reply.delay > 0 {
		select {
		case <-time.After(reply.delay):
		case <-r.Context().Done():
			return
		}
	}
	for k, v := range reply.header {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(reply.status)
	_, _ = w.Write([]byte(reply.body))
}

func (a *scriptedAPI) sentKeys() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.keys...)
}

func newScriptedClient(t *testing.T, api *scriptedAPI, maxRetries int, opts ...ClientOption) *Client {
	t.Helper()
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	client := NewClient("test-key", append([]ClientOption{WithBaseURL(srv.URL), WithMaxRetries(maxRetries)}, opts...)...)
	client.retryBaseDelay = time.Millisecond
	return client
}

const (
	keyedServerErrorBody = `{"success":false,"error":{"code":"INTERNAL_ERROR","message":"boom","request_id":"req_1","retryable":true,"retry_requires_same_idempotency_key":true}}`
	inFlightConflictBody = `{"success":false,"error":{"code":"CONFLICT","message":"A matching email finder request is already running under this Idempotency-Key. Retry shortly with the same key.","retryable":true,"retry_requires_same_idempotency_key":true}}`
	keyConflictBody      = `{"success":false,"error":{"code":"IDEMPOTENCY_KEY_CONFLICT","message":"key reused","retryable":false}}`
	mayChargeAgainBody   = `{"success":false,"error":{"code":"INTERNAL_ERROR","message":"Domain search failed to start","retry_may_charge_again":true}}`
	findOKBody           = `{"success":true,"data":{"email":"ada@example.org","confidence":90}}`
	verifyOKBody         = `{"success":true,"data":{"email":"a@b.com","status":"valid","score":90}}`
	accountOKBody        = `{"success":true,"data":{"credits_balance":10}}`
	domainOKBody         = `{"success":true,"data":{"domain":"example.org","status":"completed","emails":[]}}`
)

func requireOneKey(t *testing.T, keys []string) string {
	t.Helper()
	require.NotEmpty(t, keys)
	assert.Regexp(t, uuidV4, keys[0])
	for _, k := range keys {
		assert.Equal(t, keys[0], k, "every attempt must carry the same key")
	}
	return keys[0]
}

func TestVerifyGivingUpOnServerErrorsKeepsTheKeyOnTheError(t *testing.T) {
	api := &scriptedAPI{replies: []scriptedResponse{{status: 500, body: keyedServerErrorBody}}}
	client := newScriptedClient(t, api, 2)

	_, err := client.Verify(context.Background(), "a@b.com")
	require.Error(t, err)

	keys := api.sentKeys()
	require.Len(t, keys, 3, "max retries 2 is three attempts")
	key := requireOneKey(t, keys)

	// The README's type assertion and errors.As both reach it.
	apiErr, ok := err.(*APIError)
	require.True(t, ok, "expected *APIError, got %T", err)
	var viaAs *APIError
	require.True(t, errors.As(err, &viaAs))
	assert.Same(t, apiErr, viaAs)

	assert.Equal(t, key, apiErr.IdempotencyKey)
	assert.Equal(t, key, IdempotencyKeyOf(err))
	assert.Equal(t, 500, apiErr.StatusCode)
	assert.Equal(t, "INTERNAL_ERROR", apiErr.Code)
	assert.Equal(t, "req_1", apiErr.RequestID)
	require.NotNil(t, apiErr.Retryable)
	assert.True(t, *apiErr.Retryable)
	assert.True(t, apiErr.RetryRequiresSameIdempotencyKey)
	assert.False(t, apiErr.RetryMayChargeAgain)
	assert.Equal(t, 3, apiErr.Attempts)
}

func TestTheKeyFromAGivenUpCallReplaysWhenPassedBack(t *testing.T) {
	// First call: a gateway 503 (the charge may have landed), then the
	// in-flight 409 until retries run out. Second call, with the key read
	// off the error: the stored result.
	api := &scriptedAPI{replies: []scriptedResponse{
		{status: 503, body: `{"message":"Service Unavailable"}`},
		{status: 409, body: inFlightConflictBody},
		{status: 409, body: inFlightConflictBody},
		{status: 200, body: findOKBody},
	}}
	client := newScriptedClient(t, api, 2)

	_, err := client.Find(context.Background(), "Ada", "Lovelace", "example.org")
	require.Error(t, err)
	key := IdempotencyKeyOf(err)
	require.NotEmpty(t, key)

	result, err := client.Find(context.Background(), "Ada", "Lovelace", "example.org", FindOptions{IdempotencyKey: key})
	require.NoError(t, err)
	assert.Equal(t, "ada@example.org", result.Email)
	requireOneKey(t, api.sentKeys())
	assert.Len(t, api.sentKeys(), 4)
}

// keyRecordingTransport fails every round trip with err and records keys.
type keyRecordingTransport struct {
	mu   sync.Mutex
	keys []string
	err  error
}

func (f *keyRecordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys = append(f.keys, r.Header.Get("Idempotency-Key"))
	return nil, f.err
}

func TestFindGivingUpOnDroppedConnectionsKeepsTheKeyOnTheError(t *testing.T) {
	transport := &keyRecordingTransport{err: io.ErrUnexpectedEOF}
	client := NewClient("test-key", WithHTTPClient(&http.Client{Transport: transport}), WithMaxRetries(1))
	client.retryBaseDelay = time.Millisecond

	_, err := client.Find(context.Background(), "Ada", "Lovelace", "example.org")
	require.Error(t, err)
	require.Len(t, transport.keys, 2)
	key := requireOneKey(t, transport.keys)

	var reqErr *RequestError
	require.True(t, errors.As(err, &reqErr), "expected *RequestError, got %T", err)
	assert.Equal(t, key, reqErr.IdempotencyKey)
	assert.Equal(t, 2, reqErr.Attempts)
	assert.Equal(t, key, IdempotencyKeyOf(err))
	assert.True(t, errors.Is(err, io.ErrUnexpectedEOF), "the cause stays reachable")
}

func TestVerifyGivingUpOnTimeoutsKeepsTheKeyOnTheError(t *testing.T) {
	api := &scriptedAPI{replies: []scriptedResponse{{status: 200, body: verifyOKBody, delay: 2 * time.Second}}}
	client := newScriptedClient(t, api, 1, WithTimeout(50*time.Millisecond))

	_, err := client.Verify(context.Background(), "a@b.com")
	require.Error(t, err)
	keys := api.sentKeys()
	require.Len(t, keys, 2, "a keyed request is retried after a timeout")
	key := requireOneKey(t, keys)

	var reqErr *RequestError
	require.True(t, errors.As(err, &reqErr), "expected *RequestError, got %T", err)
	assert.Equal(t, key, reqErr.IdempotencyKey)
}

func TestContextEndingBetweenAttemptsKeepsTheKey(t *testing.T) {
	api := &scriptedAPI{replies: []scriptedResponse{{status: 500, body: keyedServerErrorBody, header: map[string]string{"Retry-After": "30"}}}}
	client := newScriptedClient(t, api, 3)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := client.VerifyBatch(ctx, []string{"a@b.com"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded))
	key := requireOneKey(t, api.sentKeys())
	assert.Equal(t, key, IdempotencyKeyOf(err))
}

func TestKeyedDecodeFailureKeepsTheKey(t *testing.T) {
	// A 200 this client cannot read was still charged.
	api := &scriptedAPI{replies: []scriptedResponse{{status: 200, body: `{"success":true,"data":{"email":42}}`}}}
	client := newScriptedClient(t, api, 3)

	_, err := client.Find(context.Background(), "Ada", "Lovelace", "example.org")
	require.Error(t, err)
	key := requireOneKey(t, api.sentKeys())
	assert.Equal(t, key, IdempotencyKeyOf(err))
}

func TestKeyedSuccessBodyThatIsNotAJSONObjectKeepsTheKey(t *testing.T) {
	// `null` used to decode into an empty FindResult for a charged search.
	for _, body := range []string{"null", "[1,2,3]", `"ok"`, "", "<html>gateway</html>"} {
		t.Run(body, func(t *testing.T) {
			api := &scriptedAPI{replies: []scriptedResponse{{status: 200, body: body}}}
			client := newScriptedClient(t, api, 3)

			result, err := client.Find(context.Background(), "Ada", "Lovelace", "example.org")
			require.Error(t, err)
			assert.Nil(t, result)
			keys := api.sentKeys()
			require.Len(t, keys, 1, "an answer that cannot be read is not sent again")
			assert.Equal(t, keys[0], IdempotencyKeyOf(err))
		})
	}
}

// A 2xx whose envelope says success false is the API's own failure: an error
// carrying the key, never data mapped into an empty result, and not sent
// again.
func TestSuccessStatusWithSuccessFalseIsAnError(t *testing.T) {
	for _, body := range []string{
		`{"success":false,"error":{"code":"INTERNAL_ERROR","message":"boom"}}`,
		`{"success":false}`,
	} {
		t.Run(body, func(t *testing.T) {
			api := &scriptedAPI{replies: []scriptedResponse{{status: 200, body: body}}}
			client := newScriptedClient(t, api, 3)

			result, err := client.VerifyBatch(context.Background(), []string{"a@example.com"})
			require.Error(t, err)
			assert.Nil(t, result)
			var apiErr *APIError
			require.ErrorAs(t, err, &apiErr)
			assert.Equal(t, 200, apiErr.StatusCode)
			keys := api.sentKeys()
			require.Len(t, keys, 1, "the API's answer is not sent again")
			assert.Equal(t, keys[0], IdempotencyKeyOf(err))
		})
	}
}

func TestInFlightConflictIsRetriedWithTheSameKey(t *testing.T) {
	for name, header := range map[string]map[string]string{
		"no Retry-After (find)": nil,
		"Retry-After 0":         {"Retry-After": "0"},
	} {
		t.Run(name, func(t *testing.T) {
			api := &scriptedAPI{replies: []scriptedResponse{
				{status: 409, header: header, body: inFlightConflictBody},
				{status: 200, body: findOKBody},
			}}
			client := newScriptedClient(t, api, 3)

			result, err := client.Find(context.Background(), "Ada", "Lovelace", "example.org")
			require.NoError(t, err)
			assert.Equal(t, "ada@example.org", result.Email)
			keys := api.sentKeys()
			require.Len(t, keys, 2)
			requireOneKey(t, keys)
		})
	}
}

func TestVerifyInFlightConflictHonoursRetryAfter(t *testing.T) {
	api := &scriptedAPI{replies: []scriptedResponse{
		{status: 409, header: map[string]string{"Retry-After": "0.2"}, body: inFlightConflictBody},
		{status: 200, body: verifyOKBody},
	}}
	client := newScriptedClient(t, api, 3)

	start := time.Now()
	_, err := client.Verify(context.Background(), "a@b.com")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, time.Since(start), 200*time.Millisecond, "waits the named delay, not the 1ms backoff")
	requireOneKey(t, api.sentKeys())
}

func TestNonRetryableConflictIsNotRetried(t *testing.T) {
	api := &scriptedAPI{replies: []scriptedResponse{{status: 409, body: keyConflictBody}}}
	client := newScriptedClient(t, api, 3)

	_, err := client.Find(context.Background(), "Ada", "Lovelace", "example.org", FindOptions{IdempotencyKey: "order-7"})
	require.Error(t, err)
	assert.Equal(t, []string{"order-7"}, api.sentKeys())

	apiErr, ok := err.(*APIError)
	require.True(t, ok, "expected *APIError, got %T", err)
	assert.Equal(t, "order-7", apiErr.IdempotencyKey)
	assert.Equal(t, "IDEMPOTENCY_KEY_CONFLICT", apiErr.Code)
	require.NotNil(t, apiErr.Retryable)
	assert.False(t, *apiErr.Retryable)
	assert.Equal(t, "kawaa: key reused (status: 409)", apiErr.Error())
}

func TestUnkeyedRetryableConflictIsNotRetried(t *testing.T) {
	// Only a keyed 409 means "your own request is in flight under this key".
	api := &scriptedAPI{replies: []scriptedResponse{{status: 409, body: `{"success":false,"error":{"code":"CONFLICT","message":"changed","retryable":true}}`}}}
	client := newScriptedClient(t, api, 3)

	_, err := client.GetAccount(context.Background())
	require.Error(t, err)
	assert.Len(t, api.sentKeys(), 1)
	assert.Equal(t, "", IdempotencyKeyOf(err))
}

func TestMaxRetriesZeroSendsExactlyOneRequest(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		api := &scriptedAPI{replies: []scriptedResponse{{status: 200, body: accountOKBody}}}
		client := newScriptedClient(t, api, 0)
		_, err := client.GetAccount(context.Background())
		require.NoError(t, err)
		assert.Len(t, api.sentKeys(), 1)
	})
	t.Run("server error", func(t *testing.T) {
		api := &scriptedAPI{replies: []scriptedResponse{{status: 500, body: keyedServerErrorBody}}}
		client := newScriptedClient(t, api, 0)
		_, err := client.Verify(context.Background(), "a@b.com")
		require.Error(t, err)
		key := requireOneKey(t, api.sentKeys())
		assert.Len(t, api.sentKeys(), 1)
		assert.Equal(t, key, IdempotencyKeyOf(err))
	})
	t.Run("negative counts as zero", func(t *testing.T) {
		api := &scriptedAPI{replies: []scriptedResponse{{status: 500, body: keyedServerErrorBody}}}
		client := newScriptedClient(t, api, -2)
		_, err := client.GetAccount(context.Background())
		require.Error(t, err)
		assert.Len(t, api.sentKeys(), 1)
	})
}

func TestRetryAfterIsClampedAndGarbageFallsBackToBackoff(t *testing.T) {
	client := NewClient("test-key")
	client.retryBaseDelay = 7 * time.Millisecond
	backoff := client.backoff(1)

	cases := []struct {
		name   string
		header string
		body   string
		want   time.Duration
		report int
	}{
		{"huge header is clamped", "3000000", "", MaxRetryAfter, 3000000},
		{"fractional header", "2.5", "", 2500 * time.Millisecond, 3},
		{"zero header", "0", "", 0, 0},
		{"negative header", "-5", "", backoff, 0},
		{"HTTP-date header", "Wed, 21 Oct 2026 07:28:00 GMT", "", backoff, 0},
		{"text header", "soon", "", backoff, 0},
		{"exponent header", "1e10", "", backoff, 0},
		{"infinity header", "Infinity", "", backoff, 0},
		{"body only", "", `,"retry_after_seconds":7`, 7 * time.Second, 7},
		{"huge body is clamped", "", `,"retry_after_seconds":3000000`, MaxRetryAfter, 3000000},
		{"negative body", "", `,"retry_after_seconds":-1`, backoff, 0},
		{"string body", "", `,"retry_after_seconds":"5"`, backoff, 0},
		{"null body", "", `,"retry_after_seconds":null`, backoff, 0},
		{"header wins the wait", "2", `,"retry_after_seconds":9`, 2 * time.Second, 9},
		{"garbage header, usable body", "-5", `,"retry_after_seconds":4`, 4 * time.Second, 4},
		{"neither", "", "", backoff, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header := http.Header{}
			if tc.header != "" {
				header.Set("Retry-After", tc.header)
			}
			body := `{"success":false,"error":{"code":"RATE_LIMITED","message":"slow down"` + tc.body + `}}`
			apiErr := parseAPIError(429, []byte(body), header)
			assert.Equal(t, tc.want, client.retryDelay(apiErr, 1))
			assert.Equal(t, tc.report, apiErr.RetryAfter, "the API's own value is reported unclamped")
		})
	}
}

func TestGarbageRetryAfterStillRetriesWithoutCrashing(t *testing.T) {
	for _, value := range []string{"-5", "Wed, 21 Oct 2026 07:28:00 GMT", "inf"} {
		api := &scriptedAPI{replies: []scriptedResponse{
			{status: 429, header: map[string]string{"Retry-After": value}, body: `{"success":false,"error":{"code":"RATE_LIMITED","message":"slow down"}}`},
			{status: 200, body: verifyOKBody},
		}}
		client := newScriptedClient(t, api, 3)
		_, err := client.Verify(context.Background(), "a@b.com")
		require.NoError(t, err, value)
		requireOneKey(t, api.sentKeys())
		assert.Len(t, api.sentKeys(), 2, value)
	}
}

func TestRetryFieldsIgnoreWrongTypes(t *testing.T) {
	body := `{"success":false,"error":{"code":"INTERNAL_ERROR","message":"boom","retryable":null,"retry_requires_same_idempotency_key":"true","retry_may_charge_again":1}}`
	apiErr := parseAPIError(500, []byte(body), nil)
	assert.Nil(t, apiErr.Retryable)
	assert.False(t, apiErr.RetryRequiresSameIdempotencyKey)
	assert.False(t, apiErr.RetryMayChargeAgain)
	assert.Equal(t, "boom", apiErr.Message)
}

func TestGatewayBodyMessageSurfaces(t *testing.T) {
	apiErr := parseAPIError(503, []byte(`{"message":"Service Unavailable"}`), nil)
	assert.Equal(t, "Service Unavailable", apiErr.Message)
	assert.Nil(t, apiErr.Retryable)
}

func TestDomainSearchIsNotResentWhenItMayHaveCharged(t *testing.T) {
	t.Run("500 that says a retry may charge again", func(t *testing.T) {
		api := &scriptedAPI{replies: []scriptedResponse{{status: 500, body: mayChargeAgainBody}}}
		client := newScriptedClient(t, api, 3)
		_, err := client.DomainSearch(context.Background(), "example.org")
		require.Error(t, err)
		assert.Len(t, api.sentKeys(), 1)
		apiErr, ok := err.(*APIError)
		require.True(t, ok, "expected *APIError, got %T", err)
		assert.True(t, apiErr.RetryMayChargeAgain)
		assert.Equal(t, "", apiErr.IdempotencyKey)
	})
	t.Run("bare gateway 503", func(t *testing.T) {
		api := &scriptedAPI{replies: []scriptedResponse{{status: 503, body: `{"message":"Service Unavailable"}`}}}
		client := newScriptedClient(t, api, 3)
		_, err := client.DomainSearch(context.Background(), "example.org")
		require.Error(t, err)
		assert.Len(t, api.sentKeys(), 1)
	})
	t.Run("timeout", func(t *testing.T) {
		api := &scriptedAPI{replies: []scriptedResponse{{status: 200, body: domainOKBody, delay: 2 * time.Second}}}
		client := newScriptedClient(t, api, 3, WithTimeout(50*time.Millisecond))
		_, err := client.DomainSearch(context.Background(), "example.org")
		require.Error(t, err)
		assert.Len(t, api.sentKeys(), 1)
		var reqErr *RequestError
		assert.True(t, errors.As(err, &reqErr), "expected *RequestError, got %T", err)
	})
	t.Run("rate limit is still retried", func(t *testing.T) {
		api := &scriptedAPI{replies: []scriptedResponse{
			{status: 429, header: map[string]string{"Retry-After": "0"}, body: `{"success":false,"error":{"code":"RATE_LIMITED","message":"slow down","retryable":true}}`},
			{status: 200, body: domainOKBody},
		}}
		client := newScriptedClient(t, api, 3)
		result, err := client.DomainSearch(context.Background(), "example.org")
		require.NoError(t, err)
		assert.Equal(t, "example.org", result.Domain)
		assert.Len(t, api.sentKeys(), 2)
	})
}

func TestNothingIsRetriedWhenTheBodySaysARetryMayChargeAgain(t *testing.T) {
	// Defensive: even a keyed request, or a 429, is surfaced at once.
	for _, status := range []int{500, 429} {
		api := &scriptedAPI{replies: []scriptedResponse{{status: status, body: mayChargeAgainBody}}}
		client := newScriptedClient(t, api, 3)
		_, err := client.Verify(context.Background(), "a@b.com")
		require.Error(t, err)
		assert.Len(t, api.sentKeys(), 1, "status %d", status)
	}
}

func TestAnAnswerMarkedNotRetryableIsNotRetried(t *testing.T) {
	for _, tc := range []struct {
		status int
		code   string
	}{{503, "INTEGRATION_NOT_CONFIGURED"}, {501, "NOT_IMPLEMENTED"}, {429, "TWO_FACTOR_ACCOUNT_LOCKED"}} {
		t.Run(tc.code, func(t *testing.T) {
			body := `{"success":false,"error":{"code":"` + tc.code + `","message":"no","retryable":false}}`
			api := &scriptedAPI{replies: []scriptedResponse{{status: tc.status, body: body}, {status: 200, body: accountOKBody}}}
			client := newScriptedClient(t, api, 3)

			_, err := client.GetAccount(context.Background())
			require.Error(t, err)
			assert.Len(t, api.sentKeys(), 1)
			var apiErr *APIError
			require.True(t, errors.As(err, &apiErr))
			require.NotNil(t, apiErr.Retryable)
			assert.False(t, *apiErr.Retryable)
		})
	}
}

func TestFreeGetIsStillRetriedAfterServerErrors(t *testing.T) {
	api := &scriptedAPI{replies: []scriptedResponse{
		{status: 503, body: `{"message":"Service Unavailable"}`},
		{status: 200, body: accountOKBody},
	}}
	client := newScriptedClient(t, api, 3)
	_, err := client.GetAccount(context.Background())
	require.NoError(t, err)
	assert.Len(t, api.sentKeys(), 2)
}

const (
	batchOKBody      = `{"success":true,"data":{"job_id":"job_1","status":"processing","total_emails":1}}`
	jobRunningBody   = `{"success":true,"data":{"job_id":"job_1","status":"processing","progress_percent":10}}`
	jobReadFailsBody = `{"success":false,"error":{"code":"INTERNAL_ERROR","message":"boom"}}`
)

// VerifyBatchAndWait pays for the batch before it waits. A failure while
// waiting must carry the batch's key, or repeating the convenience call buys
// the batch again under a fresh one.
func TestVerifyBatchAndWaitKeepsTheBatchKeyWhenTheWaitFails(t *testing.T) {
	t.Run("a job read that fails", func(t *testing.T) {
		api := &scriptedAPI{replies: []scriptedResponse{
			{status: 200, body: batchOKBody},
			{status: 500, body: jobReadFailsBody},
		}}
		client := newScriptedClient(t, api, 0)

		_, err := client.VerifyBatchAndWait(context.Background(), []string{"a@b.com"}, time.Millisecond, time.Second)
		require.Error(t, err)
		keys := api.sentKeys()
		require.Len(t, keys, 2)
		assert.Regexp(t, uuidV4, keys[0])
		assert.Equal(t, "", keys[1], "the job read carries no key of its own")
		assert.Equal(t, keys[0], IdempotencyKeyOf(err))
		var apiErr *APIError
		require.True(t, errors.As(err, &apiErr), "expected *APIError, got %T", err)
		assert.Equal(t, 500, apiErr.StatusCode)
	})

	t.Run("the wait running out", func(t *testing.T) {
		api := &scriptedAPI{replies: []scriptedResponse{
			{status: 200, body: batchOKBody},
			{status: 200, body: jobRunningBody},
		}}
		client := newScriptedClient(t, api, 0)

		_, err := client.VerifyBatchAndWait(context.Background(), []string{"a@b.com"}, time.Millisecond, 30*time.Millisecond)
		require.Error(t, err)
		assert.True(t, errors.Is(err, context.DeadlineExceeded), "the timeout stays visible: %v", err)
		assert.Equal(t, api.sentKeys()[0], IdempotencyKeyOf(err))
	})

	t.Run("a caller's own key", func(t *testing.T) {
		api := &scriptedAPI{replies: []scriptedResponse{
			{status: 200, body: batchOKBody},
			{status: 500, body: jobReadFailsBody},
		}}
		client := newScriptedClient(t, api, 0)

		_, err := client.VerifyBatchAndWait(context.Background(), []string{"a@b.com"}, time.Millisecond, time.Second,
			BatchOptions{VerifyOptions: VerifyOptions{IdempotencyKey: "batch-key-1"}})
		require.Error(t, err)
		assert.Equal(t, "batch-key-1", api.sentKeys()[0])
		assert.Equal(t, "batch-key-1", IdempotencyKeyOf(err))
	})
}
