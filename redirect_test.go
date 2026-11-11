package kawaa

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keyCatcher is a second host: it records the X-Api-Key of every request
// that reaches it.
type keyCatcher struct {
	mu   sync.Mutex
	keys []string
}

func (k *keyCatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	k.mu.Lock()
	k.keys = append(k.keys, r.Header.Get("X-Api-Key"))
	k.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"success":true,"data":{"email":"a@example.com","status":"valid","quality_score":90}}`))
}

func (k *keyCatcher) received() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.keys...)
}

// redirectingAPI answers every request with status and a Location on the
// other host, and counts the requests.
func redirectingAPI(t *testing.T, status int, location string) (*httptest.Server, func() int) {
	t.Helper()
	var mu sync.Mutex
	count := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		count++
		mu.Unlock()
		w.Header().Set("Location", location)
		w.WriteHeader(status)
	}))
	t.Cleanup(api.Close)
	return api, func() int {
		mu.Lock()
		defer mu.Unlock()
		return count
	}
}

// A redirect to another host is refused: the API key never reaches it, the
// error says where the redirect pointed, and it is not retried.
func TestARedirectIsRefusedAndTheKeyNeverReachesTheOtherHost(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			other := &keyCatcher{}
			otherHost := httptest.NewServer(other)
			t.Cleanup(otherHost.Close)
			api, requests := redirectingAPI(t, status, otherHost.URL+"/collect?x=1")

			client := NewClient("secret-key", WithBaseURL(api.URL), WithMaxRetries(3))
			client.retryBaseDelay = 0

			result, err := client.Verify(context.Background(), "a@example.com")
			require.Error(t, err)
			assert.Nil(t, result)
			var apiErr *APIError
			require.True(t, errors.As(err, &apiErr), "an *APIError: %v", err)
			assert.Equal(t, status, apiErr.StatusCode)
			assert.Contains(t, apiErr.Message, "a redirect to "+otherHost.URL+".")
			assert.NotContains(t, apiErr.Message, "/collect", "the origin only, never the path")
			assert.NotEmpty(t, IdempotencyKeyOf(err), "the call's key is on the error")

			assert.Empty(t, other.received(), "nothing reaches the other host")
			assert.Equal(t, 1, requests(), "a redirect is not retried")
		})
	}
}

// The CSV download is sent outside the retry loop; a redirect there is
// refused too, never read as the export.
func TestACSVDownloadRedirectIsRefused(t *testing.T) {
	other := &keyCatcher{}
	otherHost := httptest.NewServer(other)
	t.Cleanup(otherHost.Close)
	api, requests := redirectingAPI(t, http.StatusTemporaryRedirect, otherHost.URL+"/export.csv")

	client := NewClient("secret-key", WithBaseURL(api.URL))
	csv, err := client.DownloadResultsCSV(context.Background(), "job-1")
	require.Error(t, err)
	assert.Empty(t, csv)
	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr), "an *APIError: %v", err)
	assert.Equal(t, http.StatusTemporaryRedirect, apiErr.StatusCode)
	assert.Contains(t, apiErr.Message, "a redirect to "+otherHost.URL+".")
	assert.Empty(t, other.received(), "nothing reaches the other host")
	assert.Equal(t, 1, requests())
}

// A client passed to WithHTTPClient follows redirects by default; the SDK
// refuses them all the same, and leaves that client as it was.
func TestARedirectIsRefusedWithACallersOwnHTTPClient(t *testing.T) {
	other := &keyCatcher{}
	otherHost := httptest.NewServer(other)
	t.Cleanup(otherHost.Close)
	api, requests := redirectingAPI(t, http.StatusTemporaryRedirect, otherHost.URL+"/v1/verify")

	own := &http.Client{}
	client := NewClient("secret-key", WithBaseURL(api.URL), WithHTTPClient(own))

	_, err := client.Verify(context.Background(), "a@example.com")
	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr), "an *APIError: %v", err)
	assert.Equal(t, http.StatusTemporaryRedirect, apiErr.StatusCode)
	assert.Empty(t, other.received(), "nothing reaches the other host")
	assert.Equal(t, 1, requests())
	assert.Nil(t, own.CheckRedirect, "the caller's client is not changed")
}

// The control: without the refusal, net/http follows this very redirect and
// carries the key to the other host. So the tests above would see a leak.
func TestTheLeakTheRefusalPrevents(t *testing.T) {
	other := &keyCatcher{}
	otherHost := httptest.NewServer(other)
	t.Cleanup(otherHost.Close)
	api, _ := redirectingAPI(t, http.StatusTemporaryRedirect, otherHost.URL+"/v1/verify")

	req, err := http.NewRequest(http.MethodPost, api.URL+"/v1/verify", strings.NewReader(`{}`))
	require.NoError(t, err)
	req.Header.Set("X-Api-Key", "secret-key")
	resp, err := (&http.Client{}).Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, []string{"secret-key"}, other.received())
}

// The presigned download of a large export carries no key, so it may follow
// a redirect as before.
func TestThePresignedDownloadStillFollowsARedirect(t *testing.T) {
	other := &keyCatcher{}
	otherHost := httptest.NewServer(other)
	t.Cleanup(otherHost.Close)
	storage, _ := redirectingAPI(t, http.StatusTemporaryRedirect, otherHost.URL+"/results.json")

	client := NewClient("secret-key")
	body, err := client.fetchDownloadURL(context.Background(), storage.URL+"/presigned")
	require.NoError(t, err)
	assert.Contains(t, string(body), "a@example.com")
	assert.Equal(t, []string{""}, other.received(), "followed, and without the key")
}
