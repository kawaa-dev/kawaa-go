package kawaa

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Webhook verification fails closed: no secret never means "skip the check".

const verifySecret = "whsec_correct-horse"

var forgedWebhook = []byte(`{"event":"job.completed","data":{"job_id":"job_forged","status":"completed"},"webhook_id":"wh_forged","timestamp":"2026-10-01T00:00:00Z"}`)

func signWebhook(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

var blankSecrets = []string{"", "   "}

func TestVerifyWebhookSignatureFailsClosed(t *testing.T) {
	for _, secret := range blankSecrets {
		assert.False(t, VerifyWebhookSignature(forgedWebhook, signWebhook(forgedWebhook, secret), secret),
			"an HMAC keyed with %q must not verify", secret)
		assert.False(t, VerifyWebhookSignature(forgedWebhook, "", secret))
	}
	assert.False(t, VerifyWebhookSignature(forgedWebhook, "", verifySecret))
	assert.True(t, VerifyWebhookSignature(forgedWebhook, signWebhook(forgedWebhook, verifySecret), verifySecret))
}

func TestParseWebhookFailsClosed(t *testing.T) {
	for _, secret := range blankSecrets {
		_, err := ParseWebhook(forgedWebhook, "", secret)
		require.Error(t, err, "blank secret %q with no signature", secret)
		assert.Contains(t, err.Error(), "secret is missing")

		_, err = ParseWebhook(forgedWebhook, signWebhook(forgedWebhook, ""), secret)
		require.Error(t, err, "blank secret %q with an empty-key HMAC", secret)
		assert.Contains(t, err.Error(), "secret is missing")
	}

	_, err := ParseWebhook(forgedWebhook, "", verifySecret)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature missing")

	for _, secret := range blankSecrets {
		_, err = ParseWebhook(forgedWebhook, signWebhookV2(forgedWebhook, secret, time.Now().Unix()), secret)
		require.Error(t, err, "blank secret %q with an empty-key V2 header", secret)
		assert.Contains(t, err.Error(), "secret is missing")
	}

	event, err := ParseWebhook(forgedWebhook, signWebhookV2(forgedWebhook, verifySecret, time.Now().Unix()), verifySecret)
	require.NoError(t, err)
	data, err := event.JobCompleted()
	require.NoError(t, err)
	assert.Equal(t, "job_forged", data.JobID)

	// The legacy header is accepted only with the opt-in.
	_, err = ParseWebhook(forgedWebhook, signWebhook(forgedWebhook, verifySecret), verifySecret)
	require.Error(t, err)
	event, err = ParseWebhook(forgedWebhook, signWebhook(forgedWebhook, verifySecret), verifySecret, WithLegacyWebhookSignature())
	require.NoError(t, err)
	assert.Equal(t, "job.completed", event.Event)
}

func TestNewWebhookHandlerRefusesBlankSecret(t *testing.T) {
	for _, secret := range blankSecrets {
		assert.Panics(t, func() { NewWebhookHandler(secret) }, "secret %q", secret)
	}
}

func TestZeroValueWebhookHandlerRefusesEveryRequest(t *testing.T) {
	// A handler built without NewWebhookHandler has no secret; it must not
	// fall back to parsing unverified bodies.
	h := &WebhookHandler{}
	assert.False(t, h.VerifySignature(forgedWebhook, signWebhook(forgedWebhook, "")))
	_, err := h.Parse(forgedWebhook, "")
	require.Error(t, err)
	_, err = h.Parse(forgedWebhook, signWebhook(forgedWebhook, ""))
	require.Error(t, err)
	_, err = h.Parse(forgedWebhook, signWebhookV2(forgedWebhook, "", time.Now().Unix()))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret is missing")
}

func TestWebhookHTTPHandlerFailsClosed(t *testing.T) {
	const (
		v2Header     = "X-Kawaa-Signature-V2"
		legacyHeader = "X-Kawaa-Signature"
	)
	now := time.Now().Unix()
	cases := []struct {
		name      string
		handler   *WebhookHandler
		header    string
		signature string
		status    int
		ran       bool
	}{
		{"unsigned request", NewWebhookHandler(verifySecret), "", "", http.StatusUnauthorized, false},
		{"empty-key V2 HMAC", NewWebhookHandler(verifySecret), v2Header, signWebhookV2(forgedWebhook, "", now), http.StatusUnauthorized, false},
		{"empty-key legacy HMAC", NewWebhookHandler(verifySecret), legacyHeader, signWebhook(forgedWebhook, ""), http.StatusUnauthorized, false},
		{"empty-key legacy HMAC with the opt-in", NewWebhookHandler(verifySecret, WithLegacyWebhookSignature()), legacyHeader, signWebhook(forgedWebhook, ""), http.StatusUnauthorized, false},
		{"zero-value handler, unsigned", &WebhookHandler{}, "", "", http.StatusUnauthorized, false},
		{"zero-value handler, empty-key V2 HMAC", &WebhookHandler{}, v2Header, signWebhookV2(forgedWebhook, "", now), http.StatusUnauthorized, false},
		{"zero-value handler, empty-key legacy HMAC", &WebhookHandler{}, legacyHeader, signWebhook(forgedWebhook, ""), http.StatusUnauthorized, false},
		{"valid V2 signature", NewWebhookHandler(verifySecret), v2Header, signWebhookV2(forgedWebhook, verifySecret, now), http.StatusOK, true},
		{"valid legacy signature without the opt-in", NewWebhookHandler(verifySecret), legacyHeader, signWebhook(forgedWebhook, verifySecret), http.StatusUnauthorized, false},
		{"valid legacy signature with the opt-in", NewWebhookHandler(verifySecret, WithLegacyWebhookSignature()), legacyHeader, signWebhook(forgedWebhook, verifySecret), http.StatusOK, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ran := false
			h := tc.handler.HTTPHandler(func(event *WebhookEvent) error {
				ran = true
				return nil
			})
			req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(forgedWebhook))
			if tc.header != "" {
				req.Header.Set(tc.header, tc.signature)
			}
			rec := httptest.NewRecorder()
			h(rec, req)
			assert.Equal(t, tc.status, rec.Code)
			assert.Equal(t, tc.ran, ran)
		})
	}
}

func TestParseWebhookUnverifiedIsTheExplicitUnsignedPath(t *testing.T) {
	event, err := ParseWebhookUnverified(forgedWebhook)
	require.NoError(t, err)
	assert.Equal(t, "job.completed", event.Event)
}
