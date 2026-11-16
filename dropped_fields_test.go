package kawaa

// Fields the API sends that 0.2.0 dropped or reported as 0.
//
// The bodies below are production response shapes captured on 2026-11-16
// with a test account and test addresses: POST /v1/verify (fresh, cached and
// with options.enrich), POST /v1/verify/batch, and GET /v1/account read with a
// key scoped to account:read and verification:read only.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const liveFreshVerifyWithEnrichment = `{
	"classifier_version": 7,
	"credits_remaining": 975.25,
	"credits_used": 1,
	"domain_info": {"auth_grade": "C", "auth_score": 74, "domain": "gmail.com", "has_dkim": true, "provider_type": "free"},
	"email": "zz-no-such-user-2b192d6a1b@gmail.com",
	"enrichment": {"country": "United States", "country_code": "US"},
	"flags": {"abuse_email": false, "bot_generated": false, "complainer": false, "disposable": false, "free_provider": true, "honeypot": false, "role_account": false, "spam_trap": false},
	"from_cache": false,
	"job_id": "a033a8e2-bf86-42f1-97cc-6707bbea33ea",
	"processing_time_ms": 153,
	"quality_score": 10,
	"request_id": "1dfdf7bf-d5b3-4a36-b12b-e2b2879d732b",
	"status": "invalid",
	"sub_status": "mailbox_reject",
	"verification": {"domain_exists": true, "greylisted": false, "mailbox_exists": false, "mx_found": true, "mx_records": ["gmail-smtp-in.l.google.com"], "smtp_check": true, "smtp_code": 550, "smtp_message": "550 5.1.1 no such user", "syntax_valid": true},
	"verified_at": "2026-11-16T02:31:49.759Z"
}`

const liveCachedVerify = `{
	"email": "zz-no-such-user-2b192d6a1b@gmail.com",
	"status": "invalid",
	"sub_status": "mailbox_reject",
	"quality_score": 10,
	"verification": {"syntax_valid": true, "domain_exists": true, "mx_found": true, "smtp_check": true, "mailbox_exists": false, "greylisted": false, "smtp_code": 550},
	"flags": {"disposable": false, "role_account": false, "free_provider": true, "spam_trap": false, "abuse_email": false, "honeypot": false, "complainer": false, "bot_generated": false},
	"processing_time_ms": 153,
	"verified_at": "2026-11-16T02:25:50.384Z",
	"from_cache": true,
	"classifier_version": 7,
	"cache_age_seconds": 269,
	"request_id": "772014c5-9db1-4e5d-a5df-dfb61fbe757c",
	"credits_used": 0.5,
	"credits_remaining": 981.25
}`

func decodeResult(t *testing.T, body string) VerificationResult {
	t.Helper()
	var result VerificationResult
	require.NoError(t, json.Unmarshal([]byte(body), &result))
	return result
}

func TestVerifyKeepsTheEnrichmentTheRequestAskedFor(t *testing.T) {
	result := decodeResult(t, liveFreshVerifyWithEnrichment)

	require.NotNil(t, result.Enrichment, "the API answered options.enrich; the result must carry it")
	assert.Equal(t, "United States", result.Enrichment.Country)
	assert.Equal(t, "US", result.Enrichment.CountryCode)
	assert.Empty(t, result.Enrichment.FirstName)
	assert.False(t, result.FromCache)
	assert.Nil(t, result.CacheAgeSeconds)
	assert.Equal(t, "2026-11-16T02:31:49.759Z", result.VerifiedAt)
}

func TestACachedVerdictSaysHowOldItIs(t *testing.T) {
	result := decodeResult(t, liveCachedVerify)

	assert.True(t, result.FromCache)
	require.NotNil(t, result.CacheAgeSeconds)
	assert.Equal(t, 269, *result.CacheAgeSeconds)
	// The time of the original check, not of this call.
	assert.Equal(t, "2026-11-16T02:25:50.384Z", result.VerifiedAt)
	assert.Nil(t, result.Enrichment, "not asked for")
}

func TestEnrichmentAndCacheFieldsAreReadLeniently(t *testing.T) {
	// The verification is charged before it is parsed: a value of the wrong
	// type reads as "not stated", never as an error that drives a retry.
	result := decodeResult(t, `{"email":"a@example.com","status":"valid","quality_score":90,"flags":{},
		"enrichment":"unexpected","from_cache":"yes","cache_age_seconds":"old","verified_at":17}`)
	assert.Nil(t, result.Enrichment)
	assert.False(t, result.FromCache)
	assert.Nil(t, result.CacheAgeSeconds)
	assert.Empty(t, result.VerifiedAt)

	// enrichment null: nothing is known, which is not a judgement.
	result = decodeResult(t, `{"email":"a@example.com","status":"valid","quality_score":90,"flags":{},"enrichment":null,"cache_age_seconds":null}`)
	assert.Nil(t, result.Enrichment)
	assert.Nil(t, result.CacheAgeSeconds)

	// A field that is not a string reads as empty; the others are kept.
	result = decodeResult(t, `{"email":"a@example.com","status":"valid","quality_score":90,"flags":{},
		"enrichment":{"first_name":"Ada","last_name":null,"gender":3,"country_code":"GB"}}`)
	require.NotNil(t, result.Enrichment)
	assert.Equal(t, "Ada", result.Enrichment.FirstName)
	assert.Empty(t, result.Enrichment.LastName)
	assert.Empty(t, result.Enrichment.Gender)
	assert.Equal(t, "GB", result.Enrichment.CountryCode)
}

func TestTheAbuseAndComplainerFlagsAreKept(t *testing.T) {
	result := decodeResult(t, `{"email":"abuse@spamhaus.org","status":"risky","quality_score":20,
		"flags":{"disposable":false,"role_account":true,"free_provider":false,"spam_trap":false,
		"abuse_email":true,"honeypot":true,"complainer":true,"bot_generated":true}}`)
	assert.True(t, result.Flags.AbuseEmail)
	assert.True(t, result.Flags.Complainer)
	assert.True(t, result.Flags.Honeypot)
	assert.True(t, result.Flags.BotGenerated)
	assert.True(t, result.Flags.Role)

	fresh := decodeResult(t, liveFreshVerifyWithEnrichment)
	assert.False(t, fresh.Flags.AbuseEmail)
	assert.False(t, fresh.Flags.Complainer)

	// Lenient: a value that is not a boolean is false, and the rest decodes.
	odd := decodeResult(t, `{"email":"a@example.com","status":"valid","quality_score":90,
		"flags":{"abuse_email":"true","complainer":null,"free_provider":true}}`)
	assert.False(t, odd.Flags.AbuseEmail)
	assert.False(t, odd.Flags.Complainer)
	assert.True(t, odd.Flags.FreeProvider)
}

func TestJobResultRowsKeepTheNewFields(t *testing.T) {
	var job JobStatusResult
	require.NoError(t, json.Unmarshal([]byte(`{"job_id":"j1","status":"completed","total_emails":1,"processed_emails":1,
		"progress_percent":100,"summary":{"valid":0,"invalid":1,"risky":0,"unknown":0},
		"results":[`+liveCachedVerify+`]}`), &job))
	require.Len(t, job.Results, 1)
	assert.True(t, job.Results[0].FromCache)
	require.NotNil(t, job.Results[0].CacheAgeSeconds)
	assert.Equal(t, 269, *job.Results[0].CacheAgeSeconds)
	assert.Equal(t, "2026-11-16T02:25:50.384Z", job.Results[0].VerifiedAt)
}

func TestANullSMTPCodeIsNotReportedAsZero(t *testing.T) {
	result := decodeResult(t, `{"email":"a@example.com","status":"unknown","quality_score":0,"flags":{},
		"verification":{"mx_records":[],"smtp_code":null}}`)
	require.NotNil(t, result.Verification)
	assert.Nil(t, result.Verification.SMTPCode)
}

func TestAccountUsageWithheldFromAScopedKeyIsNotZero(t *testing.T) {
	// GET /v1/account read with a key that has account:read but not
	// analytics:read: the API leaves used_this_month out and says why.
	client := envelopeServer(t, `{
		"account": {"user_id": "user_1", "email": "a@example.com", "plan": "enterprise", "status": "active", "created_at": "2026-06-13T21:54:18Z"},
		"credits": {"balance": 975.75, "monthly_allowance": 500000, "allowance_basis": "no_billing_period"},
		"withheld": {"usage": true, "api_keys": true},
		"usage": {"current_month": null, "period": {}}
	}`)

	account, err := client.GetAccount(context.Background())
	require.NoError(t, err)
	assert.Nil(t, account.CreditsUsed, "a withheld figure is unknown, not 0")
	assert.True(t, account.UsageWithheld)
	assert.Equal(t, 975.75, account.CreditsRemaining)
	assert.Empty(t, account.FreeGrant)
}

func TestAccountReportsAWithheldFreeGrant(t *testing.T) {
	client := envelopeServer(t, `{
		"account": {"user_id": "user_2", "email": "b@example.com", "plan": "free", "status": "active", "created_at": "2026-11-01T00:00:00Z"},
		"credits": {"balance": 0, "used_this_month": 0, "monthly_allowance": 100, "allowance_basis": "one_time_grant", "free_grant": "withheld"}
	}`)

	account, err := client.GetAccount(context.Background())
	require.NoError(t, err)
	require.NotNil(t, account.CreditsUsed)
	assert.Equal(t, 0.0, *account.CreditsUsed, "a stated 0 stays 0")
	assert.False(t, account.UsageWithheld)
	assert.Equal(t, "withheld", account.FreeGrant)
}

func TestAccountWithoutUsageOrWithheldStaysUnknown(t *testing.T) {
	// No figure and no withheld section (an older build, a failed read): the
	// figure is unknown, and nothing claims the API withheld it.
	var account AccountInfo
	require.NoError(t, json.Unmarshal([]byte(`{"account":{"user_id":"u","plan":"starter"},"credits":{"balance":10}}`), &account))
	assert.Nil(t, account.CreditsUsed)
	assert.False(t, account.UsageWithheld)
}

func TestBatchAcceptanceReportsSkippedAndUnconfirmedAddresses(t *testing.T) {
	var job BatchJobResult
	require.NoError(t, json.Unmarshal([]byte(`{"credits_remaining":987.75,"credits_used":3,"duplicates_removed":1,
		"estimated_time_seconds":6,"invalid_emails_skipped":1,"job_id":"92b44b4d-4594-4262-bac5-d3ffb78a62dd",
		"message":"Batch verification started.","status":"processing","total_submitted":5,"unique_emails":3}`), &job))
	require.NotNil(t, job.InvalidEmailsSkipped)
	assert.Equal(t, 1, *job.InvalidEmailsSkipped)
	assert.Nil(t, job.EnqueueUnknown)

	var held BatchJobResult
	require.NoError(t, json.Unmarshal([]byte(`{"job_id":"j2","status":"enqueue_unknown","total_submitted":3,"unique_emails":1,
		"credits_used":1,"credits_held":2,"enqueue_unknown":2,"invalid_emails_skipped":0}`), &held))
	require.NotNil(t, held.EnqueueUnknown)
	assert.Equal(t, 2, *held.EnqueueUnknown)
	require.NotNil(t, held.InvalidEmailsSkipped)
	assert.Equal(t, 0, *held.InvalidEmailsSkipped)

	// A value of the wrong type must not lose the job id of a charged batch.
	var odd BatchJobResult
	require.NoError(t, json.Unmarshal([]byte(`{"job_id":"j3","status":"processing","total_submitted":1,"unique_emails":1,
		"credits_used":1,"invalid_emails_skipped":"one","enqueue_unknown":null}`), &odd))
	assert.Equal(t, "j3", odd.JobID)
	assert.Nil(t, odd.InvalidEmailsSkipped)
	assert.Nil(t, odd.EnqueueUnknown)
}

func TestWaitForJobSaysWhyAJobFailed(t *testing.T) {
	client := envelopeServer(t, `{"job_id":"job_f","status":"failed","total_emails":1,"processed_emails":0,
		"progress_percent":0,"credits_used":1,"credits_refunded":1,"billing_status":"refunded",
		"error_message":"Verification failed and was refunded"}`)

	status, err := client.GetJobStatus(context.Background(), "job_f", false)
	require.NoError(t, err)
	assert.Equal(t, "Verification failed and was refunded", status.ErrorMessage)

	_, err = client.WaitForJob(context.Background(), "job_f", 0, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "job job_f failed: Verification failed and was refunded")
}
