package kawaa

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Retry policy: a charging POST is never re-sent after it may have
// reached the API; GETs and the Idempotency-Key-carrying verify routes are.

var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// recordingServer answers each request with the next status from statuses
// (the last one repeats) and records the requests it received.
type recordingServer struct {
	mu       sync.Mutex
	statuses []int
	body     string
	requests []*http.Request
}

func (s *recordingServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	i := len(s.requests)
	s.requests = append(s.requests, r.Clone(context.Background()))
	status := s.statuses[len(s.statuses)-1]
	if i < len(s.statuses) {
		status = s.statuses[i]
	}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if status >= 400 {
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":"ERR","message":"failure"}}`))
		return
	}
	_, _ = w.Write([]byte(s.body))
}

func (s *recordingServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

func newRetryTestClient(t *testing.T, srv *recordingServer) *Client {
	t.Helper()
	api := httptest.NewServer(srv)
	t.Cleanup(api.Close)
	client := NewClient("test-key", WithBaseURL(api.URL), WithMaxRetries(3))
	client.retryBaseDelay = time.Millisecond
	return client
}

func TestFindRetriesServerErrorWithOneIdempotencyKey(t *testing.T) {
	// Find charges 5 credits and carries a key on every call, so a 5xx retry
	// replays or finishes the paid search instead of buying it again.
	srv := &recordingServer{statuses: []int{500, 200}, body: `{"email":"a@b.com"}`}
	client := newRetryTestClient(t, srv)

	_, err := client.Find(context.Background(), "Jane", "Doe", "example.com")
	require.NoError(t, err)
	assert.Equal(t, 2, srv.count())

	key := srv.requests[0].Header.Get("Idempotency-Key")
	assert.Regexp(t, uuidV4, key)
	assert.Equal(t, key, srv.requests[1].Header.Get("Idempotency-Key"), "every attempt must carry the same key")
}

func TestFindSendsTheCallerKeyVerbatim(t *testing.T) {
	srv := &recordingServer{statuses: []int{200}, body: `{"email":"a@b.com"}`}
	client := newRetryTestClient(t, srv)

	_, err := client.Find(context.Background(), "Jane", "Doe", "example.com", FindOptions{IdempotencyKey: "order-7"})
	require.NoError(t, err)
	assert.Equal(t, "order-7", srv.requests[0].Header.Get("Idempotency-Key"))
}

func TestVerifyRetriesServerErrorWithOneIdempotencyKey(t *testing.T) {
	srv := &recordingServer{statuses: []int{502, 503, 200}, body: `{"email":"a@b.com","status":"valid","score":90}`}
	client := newRetryTestClient(t, srv)

	result, err := client.Verify(context.Background(), "a@b.com")
	require.NoError(t, err)
	assert.Equal(t, "a@b.com", result.Email)
	require.Equal(t, 3, srv.count())

	key := srv.requests[0].Header.Get("Idempotency-Key")
	assert.Regexp(t, uuidV4, key)
	for _, r := range srv.requests {
		assert.Equal(t, key, r.Header.Get("Idempotency-Key"), "every attempt must carry the same key")
	}

	_, err = client.Verify(context.Background(), "a@b.com")
	require.NoError(t, err)
	require.Equal(t, 4, srv.count())
	second := srv.requests[3].Header.Get("Idempotency-Key")
	assert.Regexp(t, uuidV4, second)
	assert.NotEqual(t, key, second, "separate calls must use separate keys")
}

func TestVerifyBatchRetriesWithCallerKey(t *testing.T) {
	srv := &recordingServer{statuses: []int{500, 200}, body: `{"job_id":"job-1","status":"pending"}`}
	client := newRetryTestClient(t, srv)

	opts := BatchOptions{VerifyOptions: DefaultVerifyOptions()}
	opts.IdempotencyKey = "caller-key-1"
	job, err := client.VerifyBatch(context.Background(), []string{"a@b.com"}, opts)
	require.NoError(t, err)
	assert.Equal(t, "job-1", job.JobID)
	require.Equal(t, 2, srv.count())
	for _, r := range srv.requests {
		assert.Equal(t, "caller-key-1", r.Header.Get("Idempotency-Key"))
	}
}

func TestVerifyGivesUpReportingAttemptsMade(t *testing.T) {
	srv := &recordingServer{statuses: []int{500}}
	client := newRetryTestClient(t, srv)
	client.maxRetries = 2

	// Two retries after the first attempt: three requests in all.
	_, err := client.Verify(context.Background(), "a@b.com")
	require.Error(t, err)
	assert.Equal(t, 3, srv.count())
	assert.Contains(t, err.Error(), "after 3 attempts")
}

func TestGetRetriesAfterServerError(t *testing.T) {
	srv := &recordingServer{statuses: []int{500, 200}, body: `{"email":"a@b.com"}`}
	client := newRetryTestClient(t, srv)

	_, err := client.GetAccount(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, srv.count())
	assert.Empty(t, srv.requests[0].Header.Get("Idempotency-Key"))
}

func TestRateLimitRetriesChargingPost(t *testing.T) {
	srv := &recordingServer{statuses: []int{429, 200}, body: `{"email":"a@b.com"}`}
	client := newRetryTestClient(t, srv)

	_, err := client.Find(context.Background(), "Jane", "Doe", "example.com")
	require.NoError(t, err)
	assert.Equal(t, 2, srv.count(), "a 429 is refused before charging, so every method retries")
}

// failingTransport fails every round trip with err and counts attempts.
type failingTransport struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (f *failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return nil, f.err
}

func TestFindIsRetriedAfterDroppedConnection(t *testing.T) {
	// The request may have charged before the connection died; the key every
	// Find call carries makes the retry safe, so it happens.
	transport := &failingTransport{err: io.ErrUnexpectedEOF}
	client := NewClient("test-key", WithHTTPClient(&http.Client{Transport: transport}))
	client.retryBaseDelay = time.Millisecond

	_, err := client.Find(context.Background(), "Jane", "Doe", "example.com")
	require.Error(t, err)
	assert.Equal(t, DefaultMaxRetries+1, transport.calls)
}

func TestVerifyIsRetriedAfterDroppedConnection(t *testing.T) {
	transport := &failingTransport{err: io.ErrUnexpectedEOF}
	client := NewClient("test-key", WithHTTPClient(&http.Client{Transport: transport}))
	client.retryBaseDelay = time.Millisecond

	_, err := client.Verify(context.Background(), "a@b.com")
	require.Error(t, err)
	assert.Equal(t, DefaultMaxRetries+1, transport.calls)
	assert.Contains(t, err.Error(), "after 4 attempts")
}

func TestFindIsRetriedWhenTheDialFailed(t *testing.T) {
	// Connection refused: nothing was sent, so no charge is possible.
	transport := &failingTransport{err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}}
	client := NewClient("test-key", WithHTTPClient(&http.Client{Transport: transport}))
	client.retryBaseDelay = time.Millisecond

	_, err := client.Find(context.Background(), "Jane", "Doe", "example.com")
	require.Error(t, err)
	assert.Equal(t, DefaultMaxRetries+1, transport.calls)
}

func TestNewIdempotencyKeyIsUUIDv4(t *testing.T) {
	key, err := newIdempotencyKey()
	require.NoError(t, err)
	assert.Regexp(t, uuidV4, key)
}
