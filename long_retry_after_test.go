package kawaa

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The API edge answers an address it has blocked with this 429. Up to v0.3.1
// the client waited MaxRetryAfter (60 seconds) and tried again, maxRetries
// times, so each call hung about three minutes before the same error.
const edgeBlockBody = `{"success":false,"error":{"code":"RATE_LIMITED","message":"This address is blocked.","retryable":true,"retry_after_seconds":3900}}`

func TestALongerRetryAfterThanTheCapIsReturnedAtOnce(t *testing.T) {
	api := &scriptedAPI{replies: []scriptedResponse{
		{status: 429, header: map[string]string{"Retry-After": "3900"}, body: edgeBlockBody},
		{status: 200, body: verifyOKBody},
	}}
	client := newScriptedClient(t, api, 3)

	started := time.Now()
	_, err := client.Verify(context.Background(), "a@b.com")
	elapsed := time.Since(started)

	require.Error(t, err)
	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr), "expected *APIError, got %T", err)
	assert.Equal(t, http.StatusTooManyRequests, apiErr.StatusCode)
	assert.Equal(t, 3900, apiErr.RetryAfter, "the API's own value")
	assert.Equal(t, "RATE_LIMITED", apiErr.Code)
	require.NotNil(t, apiErr.Retryable)
	assert.True(t, *apiErr.Retryable)
	assert.Equal(t, 1, apiErr.Attempts)
	assert.Len(t, api.sentKeys(), 1, "not retried")
	// The key the one attempt sent, for the caller's own retry later.
	assert.Equal(t, requireOneKey(t, api.sentKeys()), apiErr.IdempotencyKey)
	assert.Less(t, elapsed, 5*time.Second, "returned without waiting")
}

func TestNoAnswerAskingForLongerThanTheCapIsRetried(t *testing.T) {
	cases := map[string]scriptedResponse{
		"the header":       {status: 429, header: map[string]string{"Retry-After": "61"}, body: `{"success":false,"error":{"code":"RATE_LIMITED","message":"slow down","retryable":true}}`},
		"the body alone":   {status: 429, body: `{"success":false,"error":{"code":"RATE_LIMITED","message":"slow down","retryable":true,"retry_after_seconds":61}}`},
		"a keyed 5xx":      {status: 503, header: map[string]string{"Retry-After": "3900"}, body: keyedServerErrorBody},
		"a keyed 409":      {status: 409, header: map[string]string{"Retry-After": "120"}, body: inFlightConflictBody},
		"a fraction above": {status: 429, header: map[string]string{"Retry-After": "60.5"}, body: `{"success":false,"error":{"code":"RATE_LIMITED","message":"slow down"}}`},
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			api := &scriptedAPI{replies: []scriptedResponse{reply, {status: 200, body: findOKBody}}}
			client := newScriptedClient(t, api, 3)

			_, err := client.Find(context.Background(), "Ada", "Lovelace", "example.org")

			require.Error(t, err)
			var apiErr *APIError
			require.True(t, errors.As(err, &apiErr), "expected *APIError, got %T", err)
			assert.Greater(t, apiErr.RetryAfter, int(MaxRetryAfter.Seconds()))
			assert.Len(t, api.sentKeys(), 1, "not retried")
		})
	}
}

func TestARetryAfterUpToTheCapIsStillWaitedAndRetried(t *testing.T) {
	client := NewClient("test-key")
	for _, value := range []string{"60", "59.5", "2", "0"} {
		header := http.Header{}
		header.Set("Retry-After", value)
		apiErr := parseAPIError(429, []byte(`{"success":false,"error":{"code":"RATE_LIMITED","message":"slow down"}}`), header)
		delay, retry := client.retryAfterFailure(apiErr, 0, true, true)
		assert.True(t, retry, value)
		want, _ := parseRetryAfterSeconds(value)
		assert.Equal(t, time.Duration(want*float64(time.Second)), delay, value)
	}
	// Over the cap, whichever field names it.
	for _, body := range []string{
		`{"success":false,"error":{"code":"RATE_LIMITED","message":"slow down","retry_after_seconds":3900}}`,
	} {
		_, retry := client.retryAfterFailure(parseAPIError(429, []byte(body), nil), 0, true, true)
		assert.False(t, retry)
	}
}

func TestALongDelayAfterAShortOneStopsAndKeepsTheKey(t *testing.T) {
	api := &scriptedAPI{replies: []scriptedResponse{
		{status: 503, body: keyedServerErrorBody},
		{status: 429, header: map[string]string{"Retry-After": "3900"}, body: edgeBlockBody},
		{status: 200, body: verifyOKBody},
	}}
	client := newScriptedClient(t, api, 3)

	_, err := client.Verify(context.Background(), "a@b.com")

	require.Error(t, err)
	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr), "expected *APIError, got %T", err)
	assert.Equal(t, http.StatusTooManyRequests, apiErr.StatusCode)
	assert.Equal(t, 3900, apiErr.RetryAfter)
	assert.Equal(t, 2, apiErr.Attempts)
	assert.Len(t, api.sentKeys(), 2)
	assert.Equal(t, requireOneKey(t, api.sentKeys()), apiErr.IdempotencyKey, "the same key on both attempts and on the error")
}

func TestShortRateLimitsAreStillRetried(t *testing.T) {
	short := scriptedResponse{status: 429, header: map[string]string{"Retry-After": "0"}, body: `{"success":false,"error":{"code":"RATE_LIMITED","message":"slow down","retryable":true}}`}
	api := &scriptedAPI{replies: []scriptedResponse{short, short, {status: 200, body: verifyOKBody}}}
	client := newScriptedClient(t, api, 3)

	_, err := client.Verify(context.Background(), "a@b.com")

	require.NoError(t, err)
	assert.Len(t, api.sentKeys(), 3)
}
