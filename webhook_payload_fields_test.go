package kawaa

// The documented webhook fields survive parsing.
//
// The fixtures in testdata/webhooks are bodies the senders' own builders
// produced (the server tests hold them to those
// builders). The typed models used to drop partial, requested_emails,
// credits_refunded and cache_discount_pending from job events, the per-job
// failure's error and failed_at, and a sub-account's identity from credit
// events.

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readWebhookFixture(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(sharedFixture("webhooks", name))
	require.NoError(t, err)
	return body
}

func parseWebhookFixture(t *testing.T, name string) *WebhookEvent {
	t.Helper()
	body := readWebhookFixture(t, name)
	event, err := ParseWebhookUnverified(body)
	require.NoError(t, err)
	assert.JSONEq(t, string(body), string(event.RawPayload), "RawPayload is the body as received")
	return event
}

func TestWebhookVerifyingParseOfASignedBodyKeepsThemToo(t *testing.T) {
	secret := "whsec_fixture"
	signed := func(name string) *WebhookEvent {
		body := readWebhookFixture(t, name)
		event, err := ParseWebhook(body, signWebhookV2(body, secret, time.Now().Unix()), secret)
		require.NoError(t, err)
		return event
	}

	job, err := signed("job-completed-partial.json").JobCompleted()
	require.NoError(t, err)
	require.NotNil(t, job.RequestedEmails)
	assert.Equal(t, 1000, *job.RequestedEmails)
	require.NotNil(t, job.Partial)
	assert.True(t, *job.Partial)
	require.NotNil(t, job.CreditsRefunded)
	assert.Equal(t, 40.0, *job.CreditsRefunded)
	require.NotNil(t, job.CacheDiscountPending)
	assert.True(t, *job.CacheDiscountPending)

	low, err := signed("credits-low-sub-account.json").CreditsLow()
	require.NoError(t, err)
	assert.Equal(t, "sub_account", low.AccountType)
	assert.Equal(t, "sub_3f9a1c7e5b2d8a64", low.SubAccountID)

	// The handler's Parse takes the same path.
	body := readWebhookFixture(t, "per-job-failed.json")
	event, err := NewWebhookHandler(secret).Parse(body, signWebhookV2(body, secret, time.Now().Unix()))
	require.NoError(t, err)
	failed, err := event.JobFailed()
	require.NoError(t, err)
	assert.Equal(t, "All messages failed to enqueue", failed.Error)
	assert.Equal(t, "2026-09-30T15:00:04.215Z", failed.FailedAt)
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(event.RawPayload, &raw))
	assert.Contains(t, raw, "results")
}

func TestWebhookPartialJobCompletedKeepsCoverageAndRefund(t *testing.T) {
	data, err := parseWebhookFixture(t, "job-completed-partial.json").JobCompleted()
	require.NoError(t, err)
	assert.Equal(t, "6f1c2b9e-0d4a-4c8e-9b7f-2a3d4e5f6a7b", data.JobID)
	assert.Equal(t, 960, data.TotalEmails)
	assert.Equal(t, 960, data.ProcessedEmails)
	require.NotNil(t, data.RequestedEmails)
	assert.Equal(t, 1000, *data.RequestedEmails)
	require.NotNil(t, data.Partial)
	assert.True(t, *data.Partial)
	require.NotNil(t, data.CreditsRefunded)
	assert.Equal(t, 40.0, *data.CreditsRefunded)
	require.NotNil(t, data.CacheDiscountPending)
	assert.True(t, *data.CacheDiscountPending)
}

func TestWebhookJobFailedKeepsCoverageAndRefund(t *testing.T) {
	data, err := parseWebhookFixture(t, "job-failed.json").JobFailed()
	require.NoError(t, err)
	assert.Equal(t, "b2d7e1f0-3c4a-4b5d-8e6f-7a8b9c0d1e2f", data.JobID)
	assert.Equal(t, 2500, data.TotalEmails)
	assert.Equal(t, 0, data.ProcessedEmails)
	require.NotNil(t, data.RequestedEmails)
	assert.Equal(t, 2500, *data.RequestedEmails)
	require.NotNil(t, data.CreditsRefunded)
	assert.Equal(t, 2500.0, *data.CreditsRefunded)
	assert.Equal(t, "All messages failed to enqueue", data.Error)
	assert.Equal(t, "2026-09-30T15:00:04.215Z", data.FailedAt)
}

func TestWebhookPerJobCompletionKeepsCoverageAndRefund(t *testing.T) {
	event := parseWebhookFixture(t, "per-job-completed-partial.json")
	assert.Empty(t, event.WebhookID)
	data, err := event.JobCompleted()
	require.NoError(t, err)
	assert.Equal(t, "completed", data.Status)
	assert.Equal(t, 960, data.TotalEmails)
	assert.Equal(t, 960, data.ProcessedEmails)
	require.NotNil(t, data.RequestedEmails)
	assert.Equal(t, 1000, *data.RequestedEmails)
	require.NotNil(t, data.Partial)
	assert.True(t, *data.Partial)
	require.NotNil(t, data.CreditsRefunded)
	assert.Equal(t, 52.5, *data.CreditsRefunded)
	require.NotNil(t, data.CacheDiscountPending, "absent reads as settled")
	assert.False(t, *data.CacheDiscountPending)
	require.NotNil(t, data.Summary)
	assert.Equal(t, 900, data.Summary.Valid)
	assert.Equal(t, 4, data.Summary.Unknown)
	assert.Equal(t, "2026-09-30T14:21:07.412Z", data.CompletedAt)
	assert.Equal(t, "https://api.kawaa.com/v1/jobs/6f1c2b9e-0d4a-4c8e-9b7f-2a3d4e5f6a7b/download", data.DownloadURL)
}

func TestWebhookPerJobFailureKeepsErrorAndFailedAt(t *testing.T) {
	event := parseWebhookFixture(t, "per-job-failed.json")
	assert.Equal(t, EventJobFailed, event.Event)
	data, err := event.JobFailed()
	require.NoError(t, err)
	assert.Equal(t, "b2d7e1f0-3c4a-4b5d-8e6f-7a8b9c0d1e2f", data.JobID)
	assert.Equal(t, "failed", data.Status)
	assert.Equal(t, 2500, data.TotalEmails)
	assert.Equal(t, 0, data.ProcessedEmails)
	require.NotNil(t, data.RequestedEmails)
	assert.Equal(t, 2500, *data.RequestedEmails)
	require.NotNil(t, data.CreditsRefunded)
	assert.Equal(t, 2500.0, *data.CreditsRefunded)
	assert.Equal(t, "All messages failed to enqueue", data.Error)
	assert.Equal(t, "2026-09-30T15:00:04.215Z", data.FailedAt)
	// The flat body's own results object is still there to read.
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(event.RawPayload, &raw))
	assert.Contains(t, raw, "results")
}

func TestWebhookCreditsLowNamesTheSubAccount(t *testing.T) {
	data, err := parseWebhookFixture(t, "credits-low-sub-account.json").CreditsLow()
	require.NoError(t, err)
	assert.Equal(t, "sub_account", data.AccountType)
	assert.Equal(t, "sub_3f9a1c7e5b2d8a64", data.SubAccountID)
	assert.Equal(t, "Northwind Agency", data.SubAccountName)
	require.NotNil(t, data.CreditsAllocated)
	assert.Equal(t, 5000.0, *data.CreditsAllocated)
	assert.Equal(t, 999.5, data.CreditsRemaining)
	assert.Equal(t, 1000.0, data.Threshold)
}

func TestWebhookCreditsExhaustedNamesTheSubAccount(t *testing.T) {
	data, err := parseWebhookFixture(t, "credits-exhausted-sub-account.json").CreditsExhausted()
	require.NoError(t, err)
	assert.Equal(t, "sub_account", data.AccountType)
	assert.Equal(t, "sub_3f9a1c7e5b2d8a64", data.SubAccountID)
	assert.Equal(t, "Northwind Agency", data.SubAccountName)
	require.NotNil(t, data.CreditsAllocated)
	assert.Equal(t, 5000.0, *data.CreditsAllocated)
	assert.Equal(t, 0.0, data.CreditsRemaining)
}

func TestWebhookCacheDiscountPendingThatIsNotABooleanIsUnknownNotSettled(t *testing.T) {
	var envelope, flat map[string]any
	require.NoError(t, json.Unmarshal(readWebhookFixture(t, "job-completed-partial.json"), &envelope))
	require.NoError(t, json.Unmarshal(readWebhookFixture(t, "per-job-completed-partial.json"), &flat))
	envelopeData, ok := envelope["data"].(map[string]any)
	require.True(t, ok)

	for _, value := range []any{nil, "true", 1} {
		envelopeData["cache_discount_pending"] = value
		body, err := json.Marshal(envelope)
		require.NoError(t, err)
		event, err := ParseWebhookUnverified(body)
		require.NoError(t, err)
		data, err := event.JobCompleted()
		require.NoError(t, err)
		assert.Nil(t, data.CacheDiscountPending, "%v", value)

		flat["cache_discount_pending"] = value
		body, err = json.Marshal(flat)
		require.NoError(t, err)
		event, err = ParseWebhookUnverified(body)
		require.NoError(t, err)
		data, err = event.JobCompleted()
		require.NoError(t, err)
		assert.Nil(t, data.CacheDiscountPending, "%v", value)
	}
}

func TestWebhookOwnCreditsLowHasNoSubAccount(t *testing.T) {
	data, err := parseWebhookFixture(t, "credits-low.json").CreditsLow()
	require.NoError(t, err)
	assert.Empty(t, data.AccountType)
	assert.Empty(t, data.SubAccountID)
	assert.Empty(t, data.SubAccountName)
	assert.Nil(t, data.CreditsAllocated)
	assert.Equal(t, 99.5, data.CreditsRemaining)
}
