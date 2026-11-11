package kawaa

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bodyRecorder answers every request with body and keeps each request's
// decoded "options" object.
type bodyRecorder struct {
	mu      sync.Mutex
	body    string
	options []map[string]interface{}
}

func (b *bodyRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var payload struct {
		Options map[string]interface{} `json:"options"`
	}
	_ = json.Unmarshal(raw, &payload)
	b.mu.Lock()
	b.options = append(b.options, payload.Options)
	b.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(b.body))
}

func newBodyRecorderClient(t *testing.T, rec *bodyRecorder) *Client {
	t.Helper()
	api := httptest.NewServer(rec)
	t.Cleanup(api.Close)
	return NewClient("test-key", WithBaseURL(api.URL), WithMaxRetries(0))
}

// BatchOptions{WebhookURL: url}, as the README shows it, must not turn deep
// verification and AI off: before they were optional, the zero values were
// sent as deep_verify:false and include_ai:false.
func TestBatchOptionsLeftUnsetKeepTheAPIDefaults(t *testing.T) {
	rec := &bodyRecorder{body: `{"job_id":"job-1","status":"pending"}`}
	client := newBodyRecorderClient(t, rec)

	_, err := client.VerifyBatch(context.Background(), []string{"a@b.com"}, BatchOptions{
		WebhookURL: "https://example.com/hook",
	})
	require.NoError(t, err)

	require.Len(t, rec.options, 1)
	assert.NotContains(t, rec.options[0], "deep_verify")
	assert.NotContains(t, rec.options[0], "include_ai")
}

func TestVerifyOptionsLeftUnsetKeepTheAPIDefaults(t *testing.T) {
	rec := &bodyRecorder{body: `{"email":"a@b.com","status":"valid"}`}
	client := newBodyRecorderClient(t, rec)

	_, err := client.Verify(context.Background(), "a@b.com", VerifyOptions{SkipCache: true})
	require.NoError(t, err)

	require.Len(t, rec.options, 1)
	assert.NotContains(t, rec.options[0], "deep_verify")
	assert.NotContains(t, rec.options[0], "include_ai")
	assert.Equal(t, true, rec.options[0]["skip_cache"])
}

func TestVerifyOptionsCanTurnTheDefaultsOff(t *testing.T) {
	rec := &bodyRecorder{body: `{"job_id":"job-1","status":"pending"}`}
	client := newBodyRecorderClient(t, rec)

	_, err := client.VerifyBatch(context.Background(), []string{"a@b.com"}, BatchOptions{
		VerifyOptions: VerifyOptions{DeepVerify: Bool(false), IncludeAI: Bool(false)},
	})
	require.NoError(t, err)

	require.Len(t, rec.options, 1)
	assert.Equal(t, false, rec.options[0]["deep_verify"])
	assert.Equal(t, false, rec.options[0]["include_ai"])
}

func TestNoOptionsSendTheDefaultsExplicitly(t *testing.T) {
	rec := &bodyRecorder{body: `{"job_id":"job-1","status":"pending"}`}
	client := newBodyRecorderClient(t, rec)

	_, err := client.VerifyBatch(context.Background(), []string{"a@b.com"})
	require.NoError(t, err)

	require.Len(t, rec.options, 1)
	assert.Equal(t, true, rec.options[0]["deep_verify"])
	assert.Equal(t, true, rec.options[0]["include_ai"])
}

// WithTimeout must hold in either order with WithHTTPClient. The README
// lists WithTimeout first, and WithHTTPClient used to replace the client the
// timeout had been set on.
func TestWithTimeoutHoldsInEitherOrder(t *testing.T) {
	custom := &http.Client{Timeout: 5 * time.Second}

	before := NewClient("test-key", WithTimeout(30*time.Second), WithHTTPClient(custom))
	assert.Equal(t, 30*time.Second, before.httpClient.Timeout)

	after := NewClient("test-key", WithHTTPClient(custom), WithTimeout(30*time.Second))
	assert.Equal(t, 30*time.Second, after.httpClient.Timeout)

	// The caller's own client is left as it was.
	assert.Equal(t, 5*time.Second, custom.Timeout)
}

func TestWithHTTPClientKeepsItsOwnTimeoutWithoutWithTimeout(t *testing.T) {
	transport := &http.Transport{}
	custom := &http.Client{Timeout: 5 * time.Second, Transport: transport}
	client := NewClient("test-key", WithHTTPClient(custom))
	assert.Equal(t, 5*time.Second, client.httpClient.Timeout)
	// A copy of it, on the caller's transport, that refuses redirects; the
	// caller's own client is left as it was.
	assert.Same(t, transport, client.httpClient.Transport)
	assert.NotNil(t, client.httpClient.CheckRedirect)
	assert.Nil(t, custom.CheckRedirect)
}

func TestWithTimeoutAlone(t *testing.T) {
	client := NewClient("test-key", WithTimeout(7*time.Second))
	assert.Equal(t, 7*time.Second, client.httpClient.Timeout)
}

func TestWithHTTPClientNilIsIgnored(t *testing.T) {
	client := NewClient("test-key", WithHTTPClient(nil))
	require.NotNil(t, client.httpClient)
	assert.Equal(t, DefaultTimeout, client.httpClient.Timeout)
}
