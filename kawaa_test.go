package kawaa

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	client := NewClient("test-api-key")
	assert.NotNil(t, client)
	assert.Equal(t, "test-api-key", client.apiKey)
	assert.Equal(t, DefaultBaseURL, client.baseURL)
	assert.Equal(t, DefaultMaxRetries, client.maxRetries)
}

func TestNewClientWithOptions(t *testing.T) {
	client := NewClient("test-api-key",
		WithBaseURL("https://custom.api.com"),
		WithMaxRetries(5),
	)
	assert.Equal(t, "https://custom.api.com", client.baseURL)
	assert.Equal(t, 5, client.maxRetries)
}

func TestVerificationResultIsValid(t *testing.T) {
	tests := []struct {
		status   VerificationStatus
		expected bool
	}{
		{StatusValid, true},
		{StatusInvalid, false},
		{StatusRisky, false},
		{StatusUnknown, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			result := &VerificationResult{Status: tt.status}
			assert.Equal(t, tt.expected, result.IsValid())
		})
	}
}

func TestVerificationResultIsDeliverable(t *testing.T) {
	tests := []struct {
		name     string
		status   VerificationStatus
		score    int
		expected bool
	}{
		{"valid", StatusValid, 50, true},
		{"invalid", StatusInvalid, 50, false},
		{"risky high score", StatusRisky, 75, false},
		{"risky low score", StatusRisky, 50, false},
		{"unknown", StatusUnknown, 50, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &VerificationResult{Status: tt.status, Score: tt.score}
			assert.Equal(t, tt.expected, result.IsDeliverable())
		})
	}
}

func TestJobStatusResultIsCompleted(t *testing.T) {
	tests := []struct {
		status   JobStatus
		expected bool
	}{
		{JobStatusCompleted, true},
		{JobStatusPending, false},
		{JobStatusProcessing, false},
		{JobStatusFailed, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			result := &JobStatusResult{Status: tt.status}
			assert.Equal(t, tt.expected, result.IsCompleted())
		})
	}
}

func TestFindResultFound(t *testing.T) {
	// Only a confirmed address is a find. The API also returns its best
	// guess, with verified false, on a catch-all, risky or role result.
	tests := []struct {
		name       string
		email      string
		confidence int
		verified   bool
		expected   bool
	}{
		{"verified", "john@example.com", 95, true, true},
		{"not found - no email", "", 0, false, false},
		{"unconfirmed guess with high confidence", "john@example.com", 95, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &FindResult{Email: tt.email, Confidence: tt.confidence, Verified: tt.verified}
			assert.Equal(t, tt.expected, result.Found())
		})
	}
}

func TestFindResultUnconfirmedGuessIsNotFound(t *testing.T) {
	for _, status := range []string{"catch_all", "risky", "role", "unknown"} {
		t.Run(status, func(t *testing.T) {
			body := []byte(`{
				"first_name": "John",
				"last_name": "Smith",
				"email": "john.smith@company.com",
				"confidence": 85,
				"pattern": "first.last",
				"verified": false,
				"status": "` + status + `",
				"credits_used": 5,
				"credits_remaining": 95
			}`)

			var result FindResult
			require.NoError(t, json.Unmarshal(body, &result))

			assert.Equal(t, "john.smith@company.com", result.Email)
			assert.Equal(t, 85, result.Confidence)
			assert.False(t, result.Verified)
			assert.False(t, result.Found())
		})
	}
}

func TestParseAPIError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		expected   string
	}{
		{
			name:       "json error",
			statusCode: 400,
			body:       `{"error": "Invalid email format"}`,
			expected:   "Invalid email format",
		},
		{
			name:       "message field",
			statusCode: 400,
			body:       `{"message": "Validation failed"}`,
			expected:   "Validation failed",
		},
		{
			name:       "plain text",
			statusCode: 500,
			body:       "Internal server error",
			expected:   "Internal server error",
		},
		{
			name:       "empty body 401",
			statusCode: 401,
			body:       "",
			expected:   "Invalid or missing API key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parseAPIError(tt.statusCode, []byte(tt.body), nil)
			assert.Equal(t, tt.statusCode, err.StatusCode)
			assert.Equal(t, tt.expected, err.Message)
		})
	}
}

func TestParseAPIErrorEnvelopeAndRetryAfterHeader(t *testing.T) {
	body := `{"success":false,"error":{"code":"RATE_LIMITED","message":"Rate limit exceeded. Retry after 30 seconds.","request_id":"req-1"}}`
	header := http.Header{}
	header.Set("Retry-After", "30")

	err := parseAPIError(429, []byte(body), header)

	assert.Equal(t, 429, err.StatusCode)
	assert.Equal(t, "Rate limit exceeded. Retry after 30 seconds.", err.Message)
	assert.Equal(t, "RATE_LIMITED", err.Code)
	assert.Equal(t, "req-1", err.RequestID)
	assert.Equal(t, 30, err.RetryAfter)
	assert.True(t, err.IsRateLimitError())
}

func TestParseAPIErrorNoRetryAfterWithoutHeader(t *testing.T) {
	body := `{"success":false,"error":{"code":"RATE_LIMITED","message":"Rate limit exceeded"}}`
	err := parseAPIError(429, []byte(body), http.Header{})
	assert.Equal(t, 0, err.RetryAfter)
}

func TestAPIErrorTypes(t *testing.T) {
	tests := []struct {
		statusCode int
		isAuth     bool
		isRate     bool
		isCredits  bool
		isValid    bool
		isNotFound bool
		isServer   bool
	}{
		{401, true, false, false, false, false, false},
		{429, false, true, false, false, false, false},
		{402, false, false, true, false, false, false},
		{400, false, false, false, true, false, false},
		{422, false, false, false, true, false, false},
		{404, false, false, false, false, true, false},
		{500, false, false, false, false, false, true},
		{502, false, false, false, false, false, true},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.statusCode)), func(t *testing.T) {
			err := &APIError{StatusCode: tt.statusCode}
			assert.Equal(t, tt.isAuth, err.IsAuthenticationError())
			assert.Equal(t, tt.isRate, err.IsRateLimitError())
			assert.Equal(t, tt.isCredits, err.IsInsufficientCreditsError())
			assert.Equal(t, tt.isValid, err.IsValidationError())
			assert.Equal(t, tt.isNotFound, err.IsNotFoundError())
			assert.Equal(t, tt.isServer, err.IsServerError())
		})
	}
}

func TestWebhookVerifySignature(t *testing.T) {
	secret := "webhook-secret"
	payload := []byte(`{"event":"batch.completed","job_id":"test-123"}`)

	// Generate valid signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	validSignature := hex.EncodeToString(mac.Sum(nil))

	handler := NewWebhookHandler(secret)

	t.Run("valid signature", func(t *testing.T) {
		assert.True(t, handler.VerifySignature(payload, validSignature))
	})

	t.Run("invalid signature", func(t *testing.T) {
		assert.False(t, handler.VerifySignature(payload, "invalid"))
	})
}

func TestWebhookParse(t *testing.T) {
	secret := "webhook-secret"
	// Registered-webhook deliveries wrap the event data in an envelope.
	payload := map[string]interface{}{
		"event": "job.completed",
		"data": map[string]interface{}{
			"job_id":           "job-123",
			"status":           "completed",
			"total_emails":     100,
			"processed_emails": 100,
			"summary": map[string]interface{}{
				"valid":   80,
				"invalid": 15,
				"risky":   5,
				"unknown": 0,
			},
			"created_at":   "2024-01-15T09:00:00Z",
			"completed_at": "2024-01-15T10:00:00Z",
			"download_url": "https://example.com/download",
		},
		"webhook_id": "wh_abc",
		"timestamp":  "2024-01-15T10:00:01Z",
	}

	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	// The legacy X-Kawaa-Signature value (bare hex), accepted only with the opt-in.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payloadBytes)
	signature := hex.EncodeToString(mac.Sum(nil))

	handler := NewWebhookHandler(secret)
	legacyHandler := NewWebhookHandler(secret, WithLegacyWebhookSignature())

	t.Run("valid payload and signature", func(t *testing.T) {
		event, err := handler.Parse(payloadBytes, signWebhookV2(payloadBytes, secret, time.Now().Unix()))
		require.NoError(t, err)
		assert.Equal(t, "job.completed", event.Event)
		assert.Equal(t, "wh_abc", event.WebhookID)
		assert.Equal(t, "2024-01-15T10:00:01Z", event.Timestamp)
		assert.False(t, event.Test)

		data, err := event.JobCompleted()
		require.NoError(t, err)
		assert.Equal(t, "job-123", data.JobID)
		assert.Equal(t, "completed", data.Status)
		assert.Equal(t, 100, data.TotalEmails)
		assert.Equal(t, 100, data.ProcessedEmails)
		require.NotNil(t, data.Summary)
		assert.Equal(t, 80, data.Summary.Valid)
		assert.Equal(t, 15, data.Summary.Invalid)
		assert.Equal(t, "2024-01-15T10:00:00Z", data.CompletedAt)

		// Wrong-event accessor errors instead of returning junk.
		_, err = event.CreditsLow()
		assert.Error(t, err)
	})

	t.Run("verification.completed envelope", func(t *testing.T) {
		body := []byte(`{"event":"verification.completed","data":{"job_id":"job_abc","email":"user@example.com","status":"valid","quality_score":95,"verified_at":"2025-01-01T00:00:00Z","credits_used":1},"webhook_id":"wh_1","timestamp":"2025-01-01T00:00:01Z"}`)
		event, err := ParseWebhookUnverified(body)
		require.NoError(t, err)
		data, err := event.VerificationCompleted()
		require.NoError(t, err)
		assert.Equal(t, "job_abc", data.JobID)
		assert.Equal(t, "user@example.com", data.Email)
		assert.Equal(t, "valid", data.Status)
		assert.Equal(t, 95, data.QualityScore)
	})

	t.Run("test delivery with omitted data fields", func(t *testing.T) {
		body := []byte(`{"event":"job.completed","data":{"job_id":"job_t","total_emails":1000,"summary":{"valid":800,"invalid":150,"risky":50},"completed_at":"2025-01-01T00:00:00Z"},"webhook_id":"wh_t","test":true,"timestamp":"2025-01-01T00:00:01Z"}`)
		event, err := ParseWebhookUnverified(body)
		require.NoError(t, err)
		assert.True(t, event.Test)
		data, err := event.JobCompleted()
		require.NoError(t, err)
		assert.Equal(t, "job_t", data.JobID)
		assert.Equal(t, "", data.Status)
		require.NotNil(t, data.Summary)
		assert.Equal(t, 0, data.Summary.Unknown)
	})

	t.Run("legacy flat per-job callback is normalized", func(t *testing.T) {
		// Stray envelope keys (webhook_id/timestamp/test) on a flat body must
		// come back empty: legacy callbacks carry no subscription metadata.
		flat := []byte(`{"event":"job.completed","job_id":"job-9","status":"completed","created_at":"2024-01-15T09:00:00Z","completed_at":"2024-01-15T10:00:00Z","results":{"total":10,"processed":10,"valid":8,"invalid":1,"risky":1,"unknown":0},"download_url":"https://example.com/download","webhook_id":"wh_stray","timestamp":"2024-01-15T10:00:01Z","test":true}`)
		event, err := ParseWebhookUnverified(flat)
		require.NoError(t, err)
		assert.Equal(t, "job.completed", event.Event)
		assert.Empty(t, event.WebhookID)
		assert.Empty(t, event.Timestamp)
		assert.False(t, event.Test)
		data, err := event.JobCompleted()
		require.NoError(t, err)
		assert.Equal(t, "job-9", data.JobID)
		assert.Equal(t, 10, data.TotalEmails)
		assert.Equal(t, 10, data.ProcessedEmails)
		require.NotNil(t, data.Summary)
		assert.Equal(t, 8, data.Summary.Valid)
		assert.Equal(t, "https://example.com/download", data.DownloadURL)
	})

	t.Run("null data with flat fields is legacy callback", func(t *testing.T) {
		body := []byte(`{"event":"job.completed","data":null,"job_id":"job-null-data","status":"completed","results":{"total":10,"processed":10,"valid":8,"invalid":2,"risky":0,"unknown":0},"download_url":"https://api.kawaa.com/v1/jobs/job-null-data/download"}`)
		event, err := ParseWebhookUnverified(body)
		require.NoError(t, err)
		assert.Empty(t, event.WebhookID)
		data, err := event.JobCompleted()
		require.NoError(t, err)
		assert.Equal(t, "job-null-data", data.JobID)
		assert.Equal(t, 10, data.TotalEmails)
		require.NotNil(t, data.Summary)
		assert.Equal(t, 8, data.Summary.Valid)
	})

	t.Run("null job_id still gates legacy callback", func(t *testing.T) {
		// The job_id KEY (even explicitly null) gates the legacy fallback.
		body := []byte(`{"event":"job.completed","job_id":null,"status":"completed","results":{"total":5,"processed":5,"valid":5,"invalid":0,"risky":0,"unknown":0}}`)
		event, err := ParseWebhookUnverified(body)
		require.NoError(t, err)
		assert.Empty(t, event.WebhookID)
		data, err := event.JobCompleted()
		require.NoError(t, err)
		assert.Equal(t, "", data.JobID)
		assert.Equal(t, 5, data.TotalEmails)
		require.NotNil(t, data.Summary)
		assert.Equal(t, 5, data.Summary.Valid)
	})

	t.Run("unknown event keeps raw data", func(t *testing.T) {
		body := []byte(`{"event":"something.new","data":{"foo":"bar","count":3},"webhook_id":"wh_9","timestamp":"2025-01-01T00:00:00Z"}`)
		event, err := ParseWebhookUnverified(body)
		require.NoError(t, err)
		assert.Equal(t, "something.new", event.Event)
		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(event.Data, &raw))
		assert.Equal(t, "bar", raw["foo"])
	})

	t.Run("invalid signature", func(t *testing.T) {
		_, err := handler.Parse(payloadBytes, "invalid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid or expired webhook signature")

		_, err = legacyHandler.Parse(payloadBytes, "sha256="+strings.Repeat("0", 64))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid webhook signature")
	})

	t.Run("unsigned body parses only through ParseWebhookUnverified", func(t *testing.T) {
		event, err := ParseWebhookUnverified(payloadBytes)
		require.NoError(t, err)
		data, err := event.JobCompleted()
		require.NoError(t, err)
		assert.Equal(t, "job-123", data.JobID)
	})

	t.Run("rejects missing signature when secret set", func(t *testing.T) {
		_, err := handler.Parse(payloadBytes, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "signature missing")
	})

	t.Run("rejects missing secret when signature set", func(t *testing.T) {
		_, err := ParseWebhook(payloadBytes, "sha256=abc", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "secret is missing")
	})

	t.Run("legacy signature only with the opt-in", func(t *testing.T) {
		for _, legacy := range []string{signature, "sha256=" + signature} {
			_, err := handler.Parse(payloadBytes, legacy)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "WithLegacyWebhookSignature")

			event, err := legacyHandler.Parse(payloadBytes, legacy)
			require.NoError(t, err)
			data, err := event.JobCompleted()
			require.NoError(t, err)
			assert.Equal(t, "job-123", data.JobID)
		}
	})
}

func TestVerifyWebhookSignature(t *testing.T) {
	secret := "test-secret"
	payload := []byte("test payload")

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	signature := hex.EncodeToString(mac.Sum(nil))

	assert.True(t, VerifyWebhookSignature(payload, signature, secret))
	assert.True(t, VerifyWebhookSignature(payload, "sha256="+signature, secret))
	assert.False(t, VerifyWebhookSignature(payload, "wrong", secret))
}

func TestDefaultVerifyOptions(t *testing.T) {
	opts := DefaultVerifyOptions()
	require.NotNil(t, opts.DeepVerify)
	assert.True(t, *opts.DeepVerify)
	require.NotNil(t, opts.IncludeAI)
	assert.True(t, *opts.IncludeAI)
	assert.False(t, opts.Enrich)
	assert.False(t, opts.SkipCache)
}

func TestVerifyOptionsJSONUsesRealAPINames(t *testing.T) {
	data, err := json.Marshal(DefaultVerifyOptions())
	require.NoError(t, err)

	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &m))

	assert.Contains(t, m, "deep_verify")
	assert.Contains(t, m, "include_ai")
	assert.NotContains(t, m, "check_mx")
	assert.NotContains(t, m, "check_smtp")
	assert.NotContains(t, m, "check_catch_all")
	assert.NotContains(t, m, "use_ai")
}

func TestJobStatusResultReadsSummary(t *testing.T) {
	body := []byte(`{
		"job_id": "job-123",
		"status": "completed",
		"total_emails": 10,
		"processed_emails": 10,
		"summary": {"valid": 8, "invalid": 1, "risky": 1, "unknown": 0},
		"progress_percent": 100,
		"next_key": "b64cursor",
		"has_more": true
	}`)

	var result JobStatusResult
	require.NoError(t, json.Unmarshal(body, &result))

	assert.Equal(t, 8, result.ValidCount)
	assert.Equal(t, 1, result.InvalidCount)
	assert.Equal(t, 1, result.RiskyCount)
	assert.Equal(t, 0, result.UnknownCount)
	assert.Equal(t, "b64cursor", result.NextKey)
	assert.True(t, result.HasMore)
}

func TestJobStatusSummaryNullBucketFallsBackPerField(t *testing.T) {
	// A summary object that is present but carries a null bucket must not
	// zero that bucket while a legacy flat count is available; numeric
	// buckets (including 0) still win.
	body := []byte(`{
		"job_id": "job-123",
		"status": "completed",
		"total_emails": 6,
		"processed_emails": 6,
		"summary": {"valid": null, "invalid": 1, "unknown": 0},
		"valid_count": 3,
		"risky_count": 2,
		"unknown_count": 9,
		"progress_percent": 100
	}`)

	var result JobStatusResult
	require.NoError(t, json.Unmarshal(body, &result))

	assert.Equal(t, 3, result.ValidCount, "null summary bucket falls back to legacy count")
	assert.Equal(t, 1, result.InvalidCount, "numeric summary bucket wins")
	assert.Equal(t, 2, result.RiskyCount, "absent summary bucket falls back to legacy count")
	assert.Equal(t, 0, result.UnknownCount, "a legitimate 0 in the summary is kept")
}

func TestJobStatusResultLegacyFlatCounts(t *testing.T) {
	body := []byte(`{
		"job_id": "job-legacy",
		"status": "completed",
		"total_emails": 4,
		"processed_emails": 4,
		"valid_count": 3,
		"invalid_count": 1,
		"risky_count": 0,
		"unknown_count": 0,
		"progress_percent": 100
	}`)

	var result JobStatusResult
	require.NoError(t, json.Unmarshal(body, &result))

	assert.Equal(t, 3, result.ValidCount)
	assert.Equal(t, 1, result.InvalidCount)
}

func TestVerificationResultExtendedStatusesAndCatchAll(t *testing.T) {
	body := []byte(`{
		"email": "trap@example.com",
		"status": "spam_trap",
		"sub_status": "mailbox_reject",
		"quality_score": 0,
		"flags": {"disposable": false, "role_account": false, "free_provider": false}
	}`)

	var result VerificationResult
	require.NoError(t, json.Unmarshal(body, &result))
	assert.Equal(t, StatusSpamTrap, result.Status)
	assert.Equal(t, "mailbox_reject", result.SubStatus)
	assert.False(t, result.IsValid())
	// spam_trap derives from the status when the flags object omits it.
	assert.True(t, result.Flags.SpamTrap)

	// ...and parses from the flags object directly.
	body = []byte(`{"email": "t@x.com", "status": "risky", "quality_score": 10, "flags": {"spam_trap": true}}`)
	var flagged VerificationResult
	require.NoError(t, json.Unmarshal(body, &flagged))
	assert.True(t, flagged.Flags.SpamTrap)

	// catch_all derived from verification.catch_all
	body = []byte(`{
		"email": "any@catchall.com",
		"status": "catch_all",
		"quality_score": 60,
		"flags": {"disposable": false},
		"verification": {"mx_records": ["mx1"], "catch_all": true}
	}`)
	var catchAll VerificationResult
	require.NoError(t, json.Unmarshal(body, &catchAll))
	assert.Equal(t, StatusCatchAll, catchAll.Status)
	assert.True(t, catchAll.Flags.CatchAll)

	// catch_all derived from status alone
	body = []byte(`{"email": "x@y.com", "status": "catch_all", "quality_score": 55, "flags": {}}`)
	var statusOnly VerificationResult
	require.NoError(t, json.Unmarshal(body, &statusOnly))
	assert.True(t, statusOnly.Flags.CatchAll)
}

func TestVerificationResultPendingShape(t *testing.T) {
	body := []byte(`{
		"job_id": "job-pending",
		"email": "slow@example.com",
		"status": "pending",
		"message": "Verification still processing."
	}`)

	var result VerificationResult
	require.NoError(t, json.Unmarshal(body, &result))
	assert.True(t, result.IsPending())
	assert.Equal(t, "job-pending", result.JobID)
	assert.Equal(t, 0, result.Score)
	assert.False(t, result.IsValid())
}

func TestAccountInfoNestedMapping(t *testing.T) {
	body := []byte(`{
		"account": {
			"user_id": "user-123",
			"email": "user@example.com",
			"name": "Jane Doe",
			"plan": "professional",
			"status": "active",
			"created_at": "2024-01-01T00:00:00Z"
		},
		"credits": {
			"balance": 1000,
			"used_this_month": 500,
			"monthly_allowance": 10000,
			"next_reset": "2024-02-01T00:00:00Z"
		},
		"usage": {"current_month": {}, "period": {}},
		"api_keys": [],
		"recent_jobs": [],
		"rate_limits": {"requests_per_minute": 300, "concurrent_requests": 10}
	}`)

	var account AccountInfo
	require.NoError(t, json.Unmarshal(body, &account))

	assert.Equal(t, "user-123", account.UserID)
	assert.Equal(t, "user@example.com", account.Email)
	assert.Equal(t, "Jane Doe", account.Name)
	assert.Equal(t, "professional", account.Plan)
	assert.Equal(t, "active", account.Status)
	assert.Equal(t, 1000.0, account.CreditsRemaining)
	require.NotNil(t, account.CreditsUsed)
	assert.Equal(t, 500.0, *account.CreditsUsed)
	assert.Equal(t, 10000.0, account.MonthlyAllowance)
	assert.Equal(t, "2024-02-01T00:00:00Z", account.NextReset)
	assert.Equal(t, "2024-01-01T00:00:00Z", account.CreatedAt)
}

func TestDownloadRowsParseFlatShape(t *testing.T) {
	body := []byte(`{
		"job_id": "job-123",
		"status": "completed",
		"result_count": 2,
		"results": [
			{"email": "a@example.com", "status": "valid", "score": 95, "disposable": false, "role": false, "free_provider": false, "catch_all": false, "suggestion": null, "mx_records": ["mx1.example.com"], "smtp_response": "250 OK", "verified_at": "2024-01-15T10:00:00Z", "sub_status": "mailbox_exists"},
			{"email": "b@example.com", "status": "risky", "score": 40, "disposable": false, "role": true, "free_provider": false, "catch_all": true, "suggestion": null, "mx_records": [], "smtp_response": null, "verified_at": "2024-01-15T10:00:00Z"}
		]
	}`)

	var result DownloadResult
	require.NoError(t, json.Unmarshal(body, &result))

	require.Len(t, result.Results, 2)
	assert.Equal(t, 95, result.Results[0].Score)
	assert.True(t, result.Results[0].IsValid())
	assert.Equal(t, "250 OK", result.Results[0].SMTPResponse)
	assert.Equal(t, "mailbox_exists", result.Results[0].SubStatus)
	assert.True(t, result.Results[1].Role)
	assert.True(t, result.Results[1].CatchAll)
	assert.Empty(t, result.Results[1].SubStatus)
}

func TestDomainSearchResultRealShape(t *testing.T) {
	body := []byte(`{
		"domain": "example.com",
		"emails": [
			{"email": "info@example.com", "status": "role", "quality_score": 90, "is_role_account": true, "is_catch_all": false, "from_cache": true}
		],
		"email_count": 1,
		"status": "completed",
		"patterns_checked": 12,
		"completion_reason": "all_candidates_checked",
		"from_cache": false,
		"credits_used": 10,
		"credits_remaining": 90
	}`)

	var result DomainSearchResult
	require.NoError(t, json.Unmarshal(body, &result))

	assert.Equal(t, "example.com", result.Domain)
	assert.Equal(t, 1, result.EmailCount)
	require.Len(t, result.Emails, 1)
	assert.True(t, result.Emails[0].IsRoleAccount)
	assert.Equal(t, 90, result.Emails[0].QualityScore)
	assert.False(t, result.IsProcessing())

	processing := []byte(`{"domain":"example.com","emails":[],"email_count":0,"status":"processing","progress_percent":25,"job_id":"dj-1","from_cache":false,"credits_used":10,"credits_remaining":90}`)
	var pending DomainSearchResult
	require.NoError(t, json.Unmarshal(processing, &pending))
	assert.True(t, pending.IsProcessing())
	assert.Equal(t, "dj-1", pending.JobID)

	// The owner's poll that completes a partial search carries the refund for
	// the candidates it could not check.
	partial := []byte(`{"domain":"example.com","emails":[],"email_count":0,"status":"completed","patterns_checked":45,"completion_reason":"time_limit_reached","from_cache":false,"credits_used":0,"credits_refunded":0.5,"credits_remaining":90.5}`)
	var incomplete DomainSearchResult
	require.NoError(t, json.Unmarshal(partial, &incomplete))
	assert.Equal(t, "time_limit_reached", incomplete.CompletionReason)
	assert.Equal(t, 45, incomplete.PatternsChecked)
	assert.Equal(t, 0.5, incomplete.CreditsRefunded)
	assert.Equal(t, 90.5, incomplete.CreditsRemaining)
	assert.Equal(t, 0.0, result.CreditsRefunded)
}

func TestFindResultRealShape(t *testing.T) {
	body := []byte(`{
		"first_name": "John",
		"last_name": "Smith",
		"email": "john.smith@company.com",
		"confidence": 92,
		"pattern": "first.last",
		"verified": true,
		"status": "valid",
		"credits_used": 5,
		"credits_remaining": 95
	}`)

	var result FindResult
	require.NoError(t, json.Unmarshal(body, &result))

	assert.True(t, result.Found())
	assert.Equal(t, "John", result.FirstName)
	assert.Equal(t, "Smith", result.LastName)
	assert.Equal(t, 5.0, result.CreditsUsed)
	// Absent means the API said nothing either way, not that it charged.
	assert.Nil(t, result.IdempotentReplay)
}

// A de-duplicated repeat still reports credits_used: 5, which is what the
// SEARCH cost, so idempotent_replay is the only thing that says THIS call
// charged nothing. A caller summing credits_used without it over-counts by
// exactly what the de-duplication saved.
func TestFindResultIdempotentReplay(t *testing.T) {
	body := []byte(`{
		"first_name": "John",
		"last_name": "Smith",
		"email": "john.smith@company.com",
		"confidence": 92,
		"status": "valid",
		"credits_used": 5,
		"credits_remaining": 95,
		"idempotent_replay": true
	}`)

	var result FindResult
	require.NoError(t, json.Unmarshal(body, &result))

	require.NotNil(t, result.IdempotentReplay)
	assert.True(t, *result.IdempotentReplay)
	assert.Equal(t, 5.0, result.CreditsUsed)
}

// An explicit null reads as "not stated", the same answer as an absent key:
// and the right one, because false here is itself the claim "you were
// charged". encoding/json leaves a *bool nil for null, which is what we want;
// pinned so a future switch to a plain bool cannot quietly turn unknown into
// "charged".
func TestFindResultNullReplayMarkerIsUnknown(t *testing.T) {
	body := []byte(`{"status":"valid","credits_used":5,"idempotent_replay":null}`)

	var result FindResult
	require.NoError(t, json.Unmarshal(body, &result))

	assert.Nil(t, result.IdempotentReplay)
}

// A wrong-typed marker must not cost the caller the result it paid for.
//
// encoding/json refuses the whole object on a type mismatch, so before
// FindResult had its own UnmarshalJSON this returned "failed to parse
// response" and no address at all, for a search already charged at 5
// credits, over a hint about how to count them. The marker reads as unknown
// and everything else survives.
func TestFindResultMalformedReplayMarkerKeepsThePaidResult(t *testing.T) {
	for _, raw := range []string{`"true"`, `"false"`, `0`, `1`, `[]`, `{}`} {
		body := []byte(`{"email":"john.smith@company.com","confidence":95,"status":"valid","credits_used":5,"credits_remaining":95,"idempotent_replay":` + raw + `}`)

		var result FindResult
		require.NoError(t, json.Unmarshal(body, &result), "raw=%s", raw)

		assert.Nil(t, result.IdempotentReplay, "raw=%s", raw)
		assert.Equal(t, "john.smith@company.com", result.Email, "raw=%s", raw)
		assert.Equal(t, 5.0, result.CreditsUsed, "raw=%s", raw)
		require.NotNil(t, result.CreditsRemaining, "raw=%s", raw)
		assert.Equal(t, 95.0, *result.CreditsRemaining, "raw=%s", raw)
	}
}

// A keyed replay whose ledger snapshot could not be read omits
// credits_remaining entirely; the SDK must report that as unknown, not zero.
func TestFindResultOmittedBalanceReadsAsUnknown(t *testing.T) {
	for _, raw := range []string{
		`{"email":"a@b.com","confidence":90,"status":"valid","credits_used":5}`,
		`{"email":"a@b.com","confidence":90,"status":"valid","credits_used":5,"credits_remaining":null}`,
		`{"email":"a@b.com","confidence":90,"status":"valid","credits_used":5,"credits_remaining":"95"}`,
	} {
		var result FindResult
		require.NoError(t, json.Unmarshal([]byte(raw), &result), "raw=%s", raw)
		assert.Nil(t, result.CreditsRemaining, "raw=%s", raw)
		assert.Equal(t, 5.0, result.CreditsUsed, "raw=%s", raw)
	}
}

// The lenient marker must not make the rest of the object lenient too: a
// malformed `confidence` is still a malformed response.
func TestFindResultStillRejectsOtherWrongTypes(t *testing.T) {
	body := []byte(`{"email":"a@b.com","confidence":"high","status":"valid"}`)

	var result FindResult
	require.Error(t, json.Unmarshal(body, &result))
}

func TestDownloadResultsPresignedURLCarriesNoAPIKey(t *testing.T) {
	// The presigned download host must never receive the API key: the
	// presigned URL itself is the credential.
	var presignedHeaders http.Header
	presigned := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presignedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"email":"a@example.com","status":"valid","score":95}]`))
	}))
	defer presigned.Close()

	var apiHeaders http.Header
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"download_url":%q,"format":"json","result_count":1,"expires_in_seconds":3600,"complete":true,"expected_rows":1,"rows_missing":0}`, presigned.URL)
	}))
	defer api.Close()

	client := NewClient("secret-api-key", WithBaseURL(api.URL))
	result, err := client.DownloadResults(context.Background(), "job-huge")
	require.NoError(t, err)
	require.Len(t, result.Results, 1)

	// The API request carries the key; the presigned fetch must not.
	assert.Equal(t, "secret-api-key", apiHeaders.Get("X-Api-Key"))
	assert.Empty(t, presignedHeaders.Get("X-Api-Key"))
	assert.Empty(t, presignedHeaders.Get("Authorization"))
}

func TestDownloadResultsCSVPresignedURLCarriesNoAPIKey(t *testing.T) {
	var presignedHeaders http.Header
	presigned := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presignedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte("email,status,score\na@example.com,valid,95\n"))
	}))
	defer presigned.Close()

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"download_url":%q,"format":"csv","result_count":1500,"expires_in_seconds":3600,"complete":true,"expected_rows":1500,"rows_missing":0}`, presigned.URL)
	}))
	defer api.Close()

	client := NewClient("secret-api-key", WithBaseURL(api.URL))
	csv, err := client.DownloadResultsCSV(context.Background(), "job-huge")
	require.NoError(t, err)
	assert.Contains(t, csv, "a@example.com")

	assert.Empty(t, presignedHeaders.Get("X-Api-Key"))
	assert.Empty(t, presignedHeaders.Get("Authorization"))
}

func TestAccountInfoZeroUsedThisMonthIsNotTreatedAsMissing(t *testing.T) {
	// A main account that has used nothing this month reports
	// used_this_month: 0. Presence, not zero-ness, must decide which
	// field applies, so the value must NOT fall back to credits_used.
	body := []byte(`{
		"account": {"user_id": "user-1", "email": "u@example.com", "plan": "professional", "created_at": "2024-01-01T00:00:00Z"},
		"credits": {"balance": 5000, "used_this_month": 0, "credits_used": 999, "monthly_allowance": 10000}
	}`)

	var account AccountInfo
	require.NoError(t, json.Unmarshal(body, &account))

	require.NotNil(t, account.CreditsUsed)
	assert.Equal(t, 0.0, *account.CreditsUsed)
	assert.Equal(t, 5000.0, account.CreditsRemaining)

	// Sub-account shape (no used_this_month) still maps credits_used.
	sub := []byte(`{
		"account": {"user_id": "sub-1", "email": "s@example.com", "plan": "sub_account", "created_at": "2024-01-01T00:00:00Z"},
		"credits": {"balance": 100, "credits_used": 25, "allocated": 125}
	}`)
	var subAccount AccountInfo
	require.NoError(t, json.Unmarshal(sub, &subAccount))
	require.NotNil(t, subAccount.CreditsUsed)
	assert.Equal(t, 25.0, *subAccount.CreditsUsed)
}

// apiKeyInjectingTransport simulates a user-supplied RoundTripper (via
// WithHTTPClient) that stamps the API key onto every outgoing request.
type apiKeyInjectingTransport struct {
	base http.RoundTripper
}

func (t *apiKeyInjectingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("X-Api-Key", "injected-secret")
	return t.base.RoundTrip(clone)
}

func TestPresignedFetchBypassesInjectedTransport(t *testing.T) {
	// Even when the user supplies an http.Client whose transport adds
	// X-Api-Key to every request, the presigned download fetch must use a
	// clean client and leak nothing to the download host.
	var presignedHeaders http.Header
	presigned := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presignedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"email":"a@example.com","status":"valid","score":95}]`))
	}))
	defer presigned.Close()

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"download_url":%q,"format":"json","result_count":1,"expires_in_seconds":3600,"complete":true,"expected_rows":1,"rows_missing":0}`, presigned.URL)
	}))
	defer api.Close()

	injecting := &http.Client{Transport: &apiKeyInjectingTransport{base: http.DefaultTransport}}
	client := NewClient("secret-api-key",
		WithBaseURL(api.URL),
		WithHTTPClient(injecting),
	)

	result, err := client.DownloadResults(context.Background(), "job-huge")
	require.NoError(t, err)
	require.Len(t, result.Results, 1)

	assert.Empty(t, presignedHeaders.Get("X-Api-Key"))
	assert.Empty(t, presignedHeaders.Get("Authorization"))
}

func TestDownloadResultsCSVReturnsPlainCSVVerbatim(t *testing.T) {
	csvBody := "email,status,score\na@example.com,valid,95\n"
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte(csvBody))
	}))
	defer api.Close()

	client := NewClient("secret-api-key", WithBaseURL(api.URL))
	csv, err := client.DownloadResultsCSV(context.Background(), "job-1")
	require.NoError(t, err)
	assert.Equal(t, csvBody, csv)
}

func TestDownloadResultsCSVRejectsNonEnvelopeJSON(t *testing.T) {
	// A JSON response without download_url must never be handed back as
	// "CSV": that would silently give callers JSON in a .csv file.
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"job_id":"job-1","status":"completed","result_count":2,"results":[]}`))
	}))
	defer api.Close()

	client := NewClient("secret-api-key", WithBaseURL(api.URL))
	_, err := client.DownloadResultsCSV(context.Background(), "job-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected JSON response for CSV download")
}

func TestDownloadResultsCSVMapsErrorResponses(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":"BAD_REQUEST","message":"Job is still processing. Please wait for completion."}}`))
	}))
	defer api.Close()

	client := NewClient("secret-api-key", WithBaseURL(api.URL))
	_, err := client.DownloadResultsCSV(context.Background(), "job-1")
	require.Error(t, err)
	apiErr, ok := err.(*APIError)
	require.True(t, ok, "expected *APIError, got %T", err)
	assert.Equal(t, 400, apiErr.StatusCode)
	assert.Contains(t, apiErr.Message, "still processing")
}

func TestDownloadResultsCSVRejectsMeasuredShortExport(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"download_url":"http://127.0.0.1:1/must-not-be-fetched","format":"csv","result_count":1497,"complete":false,"expected_rows":1500,"rows_missing":3}`))
	}))
	defer api.Close()

	client := NewClient("secret-api-key", WithBaseURL(api.URL))
	_, err := client.DownloadResultsCSV(context.Background(), "job-short")
	require.Error(t, err)
	incomplete, ok := err.(*IncompleteExportError)
	require.True(t, ok, "expected *IncompleteExportError, got %T", err)
	require.NotNil(t, incomplete.Complete)
	assert.False(t, *incomplete.Complete)
	assert.Equal(t, 1500, *incomplete.ExpectedRows)
	assert.Equal(t, 3, *incomplete.RowsMissing)
	assert.True(t, incomplete.Retryable())
}

func TestDownloadResultsCSVTranslatesRefusedInlineShortfall(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":"CONFLICT","message":"This CSV export is not the whole job. Request it again.","request_id":"req-short","retryable":true}}`))
	}))
	defer api.Close()

	client := NewClient("secret-api-key", WithBaseURL(api.URL))
	_, err := client.DownloadResultsCSV(context.Background(), "job-short")
	require.Error(t, err)
	incomplete, ok := err.(*IncompleteExportError)
	require.True(t, ok, "expected *IncompleteExportError, got %T", err)
	require.NotNil(t, incomplete.Complete)
	assert.False(t, *incomplete.Complete)
	assert.Nil(t, incomplete.ExpectedRows)
	assert.Nil(t, incomplete.RowsMissing)
	assert.Equal(t, http.StatusConflict, incomplete.StatusCode)
	assert.Equal(t, "CONFLICT", incomplete.Code)
	assert.Equal(t, "req-short", incomplete.RequestID)
	assert.True(t, incomplete.Retryable())
}

func TestDownloadResultsRejectsUnverifiableExport(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"job_id":"job-legacy","result_count":1,"complete":null,"expected_rows":null,"rows_missing":null,"results":[{"email":"a@example.com","status":"valid","score":95}]}`))
	}))
	defer api.Close()

	client := NewClient("secret-api-key", WithBaseURL(api.URL))
	_, err := client.DownloadResults(context.Background(), "job-legacy")
	require.Error(t, err)
	incomplete, ok := err.(*IncompleteExportError)
	require.True(t, ok, "expected *IncompleteExportError, got %T", err)
	assert.Nil(t, incomplete.Complete)
	assert.Nil(t, incomplete.ExpectedRows)
	assert.Nil(t, incomplete.RowsMissing)
	assert.False(t, incomplete.Retryable())
}
