package kawaa

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Credit amounts are routinely fractional: a cached verification costs 0.5,
// an activity lookup 0.25, and a cache discount refunds 0.5. These payloads
// are the shapes the live API sends, inside its {"success":true,"data":...}
// envelope, with fractional figures. Decoding any of them into an int failed
// the whole response, for VerifyBatch, after the batch had been charged.

func envelopeServer(t *testing.T, data string) *Client {
	t.Helper()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":` + data + `}`))
	}))
	t.Cleanup(api.Close)
	client := NewClient("test-key", WithBaseURL(api.URL))
	client.retryBaseDelay = time.Millisecond
	return client
}

func TestGetAccountReadsAFractionalBalance(t *testing.T) {
	client := envelopeServer(t, `{
		"account": {"user_id": "usr_1", "email": "a@example.com", "plan": "starter", "status": "active", "created_at": "2026-01-01T00:00:00.000Z"},
		"credits": {"balance": 260.25, "used_this_month": 39.75, "monthly_allowance": 300, "next_reset": "2026-10-01T00:00:00.000Z", "allowance_basis": "monthly_reset"},
		"usage": {"current_month": {}, "period": {}},
		"rate_limits": {"requests_per_minute": 60, "enforced": true}
	}`)

	account, err := client.GetAccount(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 260.25, account.CreditsRemaining)
	assert.Equal(t, 39.75, account.CreditsUsed)
	assert.Equal(t, 300.0, account.MonthlyAllowance)
	assert.Equal(t, "starter", account.Plan)
}

func TestGetAccountReadsASubAccountsFractionalSpend(t *testing.T) {
	client := envelopeServer(t, `{
		"account": {"user_id": "sub_1", "email": "s@example.com", "plan": "sub_account", "status": "active", "created_at": "2026-01-01T00:00:00.000Z"},
		"credits": {"balance": 99.5, "credits_used": 25.5, "monthly_allowance": 125}
	}`)

	account, err := client.GetAccount(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 99.5, account.CreditsRemaining)
	assert.Equal(t, 25.5, account.CreditsUsed)
}

func TestVerifyBatchReadsFractionalCreditsAndKeepsTheJobID(t *testing.T) {
	client := envelopeServer(t, `{"job_id":"job_b","status":"processing","total_submitted":3,"duplicates_removed":0,"unique_emails":3,"credits_used":2.5,"credits_remaining":257.75,"credits_held":0.5}`)

	job, err := client.VerifyBatch(context.Background(), []string{"a@example.com", "b@example.com", "c@example.com"})
	require.NoError(t, err)
	assert.Equal(t, "job_b", job.JobID)
	require.NotNil(t, job.CreditsUsed)
	assert.Equal(t, 2.5, *job.CreditsUsed)
	assert.Nil(t, job.IdempotentReplay)
	require.NotNil(t, job.CreditsRemaining)
	assert.Equal(t, 257.75, *job.CreditsRemaining)
	require.NotNil(t, job.CreditsHeld)
	assert.Equal(t, 0.5, *job.CreditsHeld)
}

// A replayed batch omits credits_remaining when its ledger snapshot cannot
// be read: that is unknown, not a zero balance. Its credits_used 0 is what the
// repeat cost, not what the batch cost: the cost is unknown here too.
func TestVerifyBatchOmittedBalanceIsUnknown(t *testing.T) {
	client := envelopeServer(t, `{"job_id":"job_b","status":"processing","total_submitted":3,"duplicates_removed":0,"unique_emails":3,"credits_used":0,"idempotent_replay":true}`)

	job, err := client.VerifyBatch(context.Background(), []string{"a@example.com"})
	require.NoError(t, err)
	assert.Equal(t, "job_b", job.JobID)
	assert.Nil(t, job.CreditsUsed)
	require.NotNil(t, job.IdempotentReplay)
	assert.True(t, *job.IdempotentReplay)
	assert.Nil(t, job.CreditsRemaining)
	assert.Nil(t, job.CreditsHeld)
}

// After a lost answer, the client's own retry under the same key gets the
// API's replay. The replay is kept as a replay, and its credits_used 0 is not
// reported as the batch's cost.
func TestVerifyBatchRecoveredLostAnswerKeepsTheReplayAndLeavesTheCostUnset(t *testing.T) {
	var mu sync.Mutex
	var keys []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		n := len(keys)
		mu.Unlock()
		if n == 1 {
			// The first answer is lost after the batch was accepted.
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"message":"Bad Gateway"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"job_id":"job_b","status":"processing","total_submitted":2,"duplicates_removed":0,"invalid_emails_skipped":0,"unique_emails":2,"idempotent_replay":true,"credits_used":0,"credits_remaining":98,"message":"This batch was already accepted under the same Idempotency-Key; nothing more was charged."}}`))
	}))
	t.Cleanup(api.Close)
	client := NewClient("test-key", WithBaseURL(api.URL), WithMaxRetries(2))
	client.retryBaseDelay = time.Millisecond

	job, err := client.VerifyBatch(context.Background(), []string{"a@example.com", "b@example.com"})
	require.NoError(t, err)
	assert.Equal(t, "job_b", job.JobID)
	require.NotNil(t, job.IdempotentReplay)
	assert.True(t, *job.IdempotentReplay)
	assert.Nil(t, job.CreditsUsed, "the replay's 0 is not the batch's cost")
	require.NotNil(t, job.CreditsRemaining)
	assert.Equal(t, 98.0, *job.CreditsRemaining)
	require.Len(t, keys, 2)
	assert.Equal(t, keys[0], keys[1], "the retry repeats the batch under the same key")
}

// Credit figures and the replay marker are read leniently: a wrong-typed
// value is unknown, and does not fail the decode of a batch already charged.
func TestVerifyBatchWrongTypedFiguresAreUnknownNotAnError(t *testing.T) {
	client := envelopeServer(t, `{"job_id":"job_b","status":"processing","total_submitted":1,"duplicates_removed":0,"unique_emails":1,"credits_used":"1","credits_remaining":null,"credits_held":"x","idempotent_replay":"true"}`)

	job, err := client.VerifyBatch(context.Background(), []string{"a@example.com"})
	require.NoError(t, err)
	assert.Equal(t, "job_b", job.JobID)
	assert.Nil(t, job.CreditsUsed)
	assert.Nil(t, job.CreditsRemaining)
	assert.Nil(t, job.CreditsHeld)
	assert.Nil(t, job.IdempotentReplay)
}

// A batch that is not a replay keeps the charge the API reported, 0 included.
func TestVerifyBatchFirstAnswerKeepsAZeroCharge(t *testing.T) {
	client := envelopeServer(t, `{"job_id":"job_b","status":"processing","total_submitted":1,"duplicates_removed":0,"unique_emails":1,"credits_used":0,"credits_remaining":10,"idempotent_replay":false}`)

	job, err := client.VerifyBatch(context.Background(), []string{"a@example.com"})
	require.NoError(t, err)
	require.NotNil(t, job.CreditsUsed)
	assert.Equal(t, 0.0, *job.CreditsUsed)
	require.NotNil(t, job.IdempotentReplay)
	assert.False(t, *job.IdempotentReplay)
}

func TestGetJobStatusReadsAFractionalRefund(t *testing.T) {
	client := envelopeServer(t, `{"job_id":"job_b","status":"completed","total_emails":3,"processed_emails":3,"progress_percent":100,"summary":{"valid":2,"invalid":1,"risky":0,"unknown":0},"credits_used":3,"credits_refunded":0.5,"billing_status":"charged","completed_at":"2026-09-25T10:00:00.000Z"}`)

	status, err := client.GetJobStatus(context.Background(), "job_b", false)
	require.NoError(t, err)
	require.NotNil(t, status.CreditsCharged)
	assert.Equal(t, 3.0, *status.CreditsCharged)
	require.NotNil(t, status.CreditsRefunded)
	assert.Equal(t, 0.5, *status.CreditsRefunded)
	assert.Equal(t, 2, status.ValidCount)
	assert.Equal(t, "charged", status.BillingStatus)
}

func TestGetJobStatusWithoutBillingFieldsLeavesThemNil(t *testing.T) {
	client := envelopeServer(t, `{"job_id":"job_b","status":"processing","total_emails":3,"processed_emails":1,"progress_percent":33}`)

	status, err := client.GetJobStatus(context.Background(), "job_b", false)
	require.NoError(t, err)
	assert.Nil(t, status.CreditsCharged)
	assert.Nil(t, status.CreditsRefunded)
}

func TestVerifyReadsFractionalCredits(t *testing.T) {
	client := envelopeServer(t, `{"email":"user@example.com","status":"valid","sub_status":"mailbox_exists","quality_score":92,"flags":{"disposable":false,"role_account":false,"free_provider":false,"catch_all":false},"verification":{"mx_records":["mx.example.com"],"smtp_response":"250 OK"},"from_cache":true,"cache_age_seconds":120,"credits_used":0.5,"credits_remaining":259.75,"request_id":"req_1"}`)

	result, err := client.Verify(context.Background(), "user@example.com")
	require.NoError(t, err)
	assert.Equal(t, StatusValid, result.Status)
	require.NotNil(t, result.CreditsUsed)
	assert.Equal(t, 0.5, *result.CreditsUsed)
	require.NotNil(t, result.CreditsRemaining)
	assert.Equal(t, 259.75, *result.CreditsRemaining)
	assert.Nil(t, result.CreditsHeld)
	assert.Nil(t, result.IdempotentReplay)
}

func TestVerifyReadsWholeCreditsAndThePendingHold(t *testing.T) {
	client := envelopeServer(t, `{"job_id":"job_p","email":"slow@example.com","status":"pending","message":"Verification is still in progress.","credits_held":1,"credits_used":1,"credits_remaining":260}`)

	result, err := client.Verify(context.Background(), "slow@example.com")
	require.NoError(t, err)
	assert.True(t, result.IsPending())
	require.NotNil(t, result.CreditsUsed)
	assert.Equal(t, 1.0, *result.CreditsUsed)
	require.NotNil(t, result.CreditsHeld)
	assert.Equal(t, 1.0, *result.CreditsHeld)
	require.NotNil(t, result.CreditsRemaining)
	assert.Equal(t, 260.0, *result.CreditsRemaining)
}

// The verification is already paid for when its response is parsed; a
// wrong-typed credit figure or marker must not fail the call.
func TestVerifyWrongTypedCreditsDoNotFailThePaidResult(t *testing.T) {
	var result VerificationResult
	require.NoError(t, json.Unmarshal([]byte(`{"email":"a@b.com","status":"valid","credits_used":"1","credits_remaining":null,"credits_held":{},"idempotent_replay":"true"}`), &result))
	assert.Equal(t, StatusValid, result.Status)
	assert.Nil(t, result.CreditsUsed)
	assert.Nil(t, result.CreditsRemaining)
	assert.Nil(t, result.CreditsHeld)
	assert.Nil(t, result.IdempotentReplay)
}

func TestFindReadsAFractionalBalanceWithoutTruncating(t *testing.T) {
	client := envelopeServer(t, `{"first_name":"John","last_name":"Smith","email":"john.smith@company.com","confidence":92,"pattern":"first.last","verified":true,"status":"valid","credits_used":5,"credits_remaining":254.25}`)

	result, err := client.Find(context.Background(), "John", "Smith", "company.com")
	require.NoError(t, err)
	assert.Equal(t, 5.0, result.CreditsUsed)
	require.NotNil(t, result.CreditsRemaining)
	assert.Equal(t, 254.25, *result.CreditsRemaining)
}

func TestDomainSearchReadsAFractionalBalance(t *testing.T) {
	client := envelopeServer(t, `{"domain":"example.com","emails":[],"email_count":0,"status":"completed","from_cache":false,"credits_used":10,"credits_remaining":250.25}`)

	result, err := client.DomainSearch(context.Background(), "example.com")
	require.NoError(t, err)
	assert.Equal(t, 10.0, result.CreditsUsed)
	assert.Equal(t, 250.25, result.CreditsRemaining)
}

func TestCreditWebhooksReadFractionalAmounts(t *testing.T) {
	var low WebhookEvent
	require.NoError(t, json.Unmarshal([]byte(`{"event":"credits.low","data":{"credits_remaining":19.5,"threshold":20,"triggered_at":"2026-09-25T10:00:00.000Z"},"webhook_id":"wh_1","timestamp":"2026-09-25T10:00:01.000Z"}`), &low))
	lowData, err := low.CreditsLow()
	require.NoError(t, err)
	assert.Equal(t, 19.5, lowData.CreditsRemaining)
	assert.Equal(t, 20.0, lowData.Threshold)

	var exhausted WebhookEvent
	require.NoError(t, json.Unmarshal([]byte(`{"event":"credits.exhausted","data":{"credits_remaining":0,"triggered_at":"2026-09-25T10:00:00.000Z"},"webhook_id":"wh_1","timestamp":"2026-09-25T10:00:01.000Z"}`), &exhausted))
	exhaustedData, err := exhausted.CreditsExhausted()
	require.NoError(t, err)
	assert.Equal(t, 0.0, exhaustedData.CreditsRemaining)

	var completed WebhookEvent
	require.NoError(t, json.Unmarshal([]byte(`{"event":"verification.completed","data":{"job_id":"job_1","email":"user@example.com","status":"valid","quality_score":92,"verified_at":"2026-09-25T10:00:00.000Z","credits_used":0.5},"webhook_id":"wh_1","timestamp":"2026-09-25T10:00:01.000Z"}`), &completed))
	completedData, err := completed.VerificationCompleted()
	require.NoError(t, err)
	assert.Equal(t, 0.5, completedData.CreditsUsed)
}

// --- Idempotent verify replays ----------------------------------------------

const replayBody = `{"job_id":"job_r","email":"user@example.com","status":"pending","idempotent_replay":true,"message":"This request was already accepted under the same Idempotency-Key; nothing more was charged. Use GET /v1/jobs/{job_id} to read the result.","credits_used":0,"credits_remaining":259.75,"request_id":"req_2"}`

const completedJobBody = `{"job_id":"job_r","status":"completed","total_emails":1,"processed_emails":1,"progress_percent":100,"summary":{"valid":1,"invalid":0,"risky":0,"unknown":0},"results":[{"email":"user@example.com","status":"valid","sub_status":"mailbox_exists","quality_score":92,"flags":{"disposable":false,"role_account":true,"free_provider":false,"catch_all":false},"verification":{"mx_records":["mx.example.com"],"smtp_response":"250 OK","catch_all":false}}],"next_key":null,"has_more":false,"credits_used":1,"credits_refunded":0.5,"billing_status":"charged","completed_at":"2026-09-25T10:00:00.000Z"}`

const processingJobBody = `{"job_id":"job_r","status":"processing","total_emails":1,"processed_emails":0,"progress_percent":0,"credits_used":1,"credits_refunded":0,"billing_status":"charged"}`

type scriptedReply struct {
	status int
	body   string
}

// replayAPI answers POST /v1/verify and GET /v1/jobs/{id} from separate
// scripts (the last entry of each repeats) and records every request.
type replayAPI struct {
	mu       sync.Mutex
	posts    []scriptedReply
	gets     []scriptedReply
	requests []*http.Request
	nPost    int
	nGet     int
}

func (a *replayAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.requests = append(a.requests, r.Clone(context.Background()))
	var reply scriptedReply
	if r.Method == http.MethodPost {
		reply = a.posts[min(a.nPost, len(a.posts)-1)]
		a.nPost++
	} else {
		reply = a.gets[min(a.nGet, len(a.gets)-1)]
		a.nGet++
	}
	a.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(reply.status)
	if reply.status >= 400 {
		_, _ = w.Write([]byte(reply.body))
		return
	}
	_, _ = w.Write([]byte(`{"success":true,"data":` + reply.body + `}`))
}

func (a *replayAPI) counts() (posts, gets int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.nPost, a.nGet
}

func (a *replayAPI) getRequests() []*http.Request {
	a.mu.Lock()
	defer a.mu.Unlock()
	var gets []*http.Request
	for _, r := range a.requests {
		if r.Method == http.MethodGet {
			gets = append(gets, r)
		}
	}
	return gets
}

func newReplayClient(t *testing.T, api *replayAPI) *Client {
	t.Helper()
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	client := NewClient("test-key", WithBaseURL(srv.URL), WithMaxRetries(3))
	client.retryBaseDelay = time.Millisecond
	client.replayPollInterval = time.Millisecond
	return client
}

func TestVerifyReplayReturnsTheCompletedResult(t *testing.T) {
	api := &replayAPI{
		posts: []scriptedReply{{200, replayBody}},
		gets:  []scriptedReply{{200, completedJobBody}},
	}
	client := newReplayClient(t, api)

	result, err := client.Verify(context.Background(), "user@example.com")
	require.NoError(t, err)

	assert.Equal(t, StatusValid, result.Status)
	assert.False(t, result.IsPending())
	assert.Equal(t, "user@example.com", result.Email)
	assert.Equal(t, "mailbox_exists", result.SubStatus)
	assert.Equal(t, 92, result.Score)
	assert.True(t, result.Flags.Role)
	require.NotNil(t, result.Verification)
	assert.Equal(t, "250 OK", result.Verification.SMTPResponse)
	assert.Equal(t, "job_r", result.JobID)
	assert.Empty(t, result.Message)
	require.NotNil(t, result.IdempotentReplay)
	assert.True(t, *result.IdempotentReplay)
	// What the verification cost: charged 1, cache discount 0.5 back.
	require.NotNil(t, result.CreditsUsed)
	assert.Equal(t, 0.5, *result.CreditsUsed)
	require.NotNil(t, result.CreditsRemaining)
	assert.Equal(t, 259.75, *result.CreditsRemaining)
	assert.Nil(t, result.CreditsHeld)

	gets := api.getRequests()
	require.Len(t, gets, 1)
	assert.Equal(t, "/v1/jobs/job_r", gets[0].URL.Path)
	assert.Equal(t, "true", gets[0].URL.Query().Get("include_results"))
	assert.Empty(t, gets[0].Header.Get("Idempotency-Key"))
	assert.Equal(t, "test-key", gets[0].Header.Get("X-Api-Key"))
}

func TestVerifyReplayPollsARunningJobUntilItCompletes(t *testing.T) {
	api := &replayAPI{
		posts: []scriptedReply{{200, `{"job_id":"job_r","email":"user@example.com","status":"pending","idempotent_replay":true,"message":"already accepted","credits_used":0}`}},
		gets:  []scriptedReply{{200, processingJobBody}, {200, completedJobBody}},
	}
	client := newReplayClient(t, api)

	result, err := client.Verify(context.Background(), "user@example.com")
	require.NoError(t, err)

	assert.Equal(t, StatusValid, result.Status)
	require.NotNil(t, result.IdempotentReplay)
	assert.True(t, *result.IdempotentReplay)
	require.NotNil(t, result.CreditsUsed)
	assert.Equal(t, 0.5, *result.CreditsUsed)
	// The replay omitted the balance, so it stays unknown.
	assert.Nil(t, result.CreditsRemaining)
	_, gets := api.counts()
	assert.Equal(t, 2, gets)
}

func TestVerifyReplayStillRunningAfterTheShortPollReturnsThePendingReplay(t *testing.T) {
	api := &replayAPI{
		posts: []scriptedReply{{200, replayBody}},
		gets:  []scriptedReply{{200, processingJobBody}},
	}
	client := newReplayClient(t, api)

	result, err := client.Verify(context.Background(), "user@example.com")
	require.NoError(t, err)

	assert.True(t, result.IsPending())
	assert.Equal(t, "job_r", result.JobID)
	require.NotNil(t, result.IdempotentReplay)
	assert.True(t, *result.IdempotentReplay)
	// The replay's 0 is what the repeat cost; the verification's cost is on
	// the job, not read, so it is unknown.
	assert.Nil(t, result.CreditsUsed)
	assert.NotEmpty(t, result.Message)
	_, gets := api.counts()
	assert.Equal(t, replayPollMaxReads, gets)
}

// A key without verification:read cannot read the job. The POST succeeded
// and was paid for, so Verify must still answer, never with an error that
// would drive a retry under a fresh key.
func TestVerifyReplayJobReadRefusedReturnsThePendingReplay(t *testing.T) {
	api := &replayAPI{
		posts: []scriptedReply{{200, replayBody}},
		gets:  []scriptedReply{{403, `{"success":false,"error":{"code":"INSUFFICIENT_SCOPE","message":"This API key does not have the verification:read scope"}}`}},
	}
	client := newReplayClient(t, api)

	result, err := client.Verify(context.Background(), "user@example.com")
	require.NoError(t, err)

	assert.True(t, result.IsPending())
	assert.Equal(t, "job_r", result.JobID)
	require.NotNil(t, result.IdempotentReplay)
	assert.True(t, *result.IdempotentReplay)
	assert.Nil(t, result.CreditsUsed)
	require.NotNil(t, result.CreditsRemaining)
	assert.Equal(t, 259.75, *result.CreditsRemaining)
	_, gets := api.counts()
	assert.Equal(t, 1, gets, "a 4xx job read is not retried")
}

func TestVerifyReplayOfAFailedJobReturnsThePendingReplay(t *testing.T) {
	api := &replayAPI{
		posts: []scriptedReply{{200, replayBody}},
		gets:  []scriptedReply{{200, `{"job_id":"job_r","status":"failed","total_emails":1,"processed_emails":0,"progress_percent":0,"credits_used":1,"credits_refunded":0,"billing_status":"refund_pending","error_message":"Verification failed"}`}},
	}
	client := newReplayClient(t, api)

	result, err := client.Verify(context.Background(), "user@example.com")
	require.NoError(t, err)
	assert.True(t, result.IsPending())
	require.NotNil(t, result.IdempotentReplay)
	assert.True(t, *result.IdempotentReplay)
	_, gets := api.counts()
	assert.Equal(t, 1, gets)
}

func TestVerifyReplayCompletedWithoutAResultReturnsThePendingReplay(t *testing.T) {
	for _, job := range []string{
		`{"job_id":"job_r","status":"completed","credits_used":1}`,
		`{"job_id":"job_r","status":"completed","results":[],"credits_used":1}`,
		`{"job_id":"job_r","status":"completed","results":["valid"],"credits_used":1}`,
		`{"job_id":"job_r","status":"completed","results":[{"email":"user@example.com","status":7}],"credits_used":1}`,
	} {
		api := &replayAPI{
			posts: []scriptedReply{{200, replayBody}},
			gets:  []scriptedReply{{200, job}},
		}
		client := newReplayClient(t, api)

		result, err := client.Verify(context.Background(), "user@example.com")
		require.NoError(t, err, "job=%s", job)
		assert.True(t, result.IsPending(), "job=%s", job)
		require.NotNil(t, result.IdempotentReplay, "job=%s", job)
		assert.True(t, *result.IdempotentReplay, "job=%s", job)
	}
}

// Without a charge on the job, the cost is unknown: the replay's own 0 is what
// the repeat cost, not what the verification cost.
func TestVerifyReplayJobWithoutBillingLeavesCreditsUsedUnset(t *testing.T) {
	api := &replayAPI{
		posts: []scriptedReply{{200, replayBody}},
		gets:  []scriptedReply{{200, `{"job_id":"job_r","status":"completed","results":[{"email":"user@example.com","status":"invalid","quality_score":5}]}`}},
	}
	client := newReplayClient(t, api)

	result, err := client.Verify(context.Background(), "user@example.com")
	require.NoError(t, err)
	assert.Equal(t, StatusInvalid, result.Status)
	require.NotNil(t, result.IdempotentReplay)
	assert.True(t, *result.IdempotentReplay)
	assert.Nil(t, result.CreditsUsed)
}

func TestVerifyReplayCallerCancellationReturnsThePendingReplay(t *testing.T) {
	api := &replayAPI{
		posts: []scriptedReply{{200, replayBody}},
		gets:  []scriptedReply{{200, processingJobBody}},
	}
	client := newReplayClient(t, api)
	client.replayPollInterval = time.Hour

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	result, err := client.Verify(ctx, "user@example.com")
	require.NoError(t, err)
	assert.Less(t, time.Since(started), 10*time.Second)
	assert.True(t, result.IsPending())
	assert.Equal(t, "job_r", result.JobID)
	require.NotNil(t, result.IdempotentReplay)
	assert.True(t, *result.IdempotentReplay)
}

func TestVerifyCompleteResponseMakesNoJobRead(t *testing.T) {
	for _, body := range []string{
		`{"email":"user@example.com","status":"valid","quality_score":92,"credits_used":1,"credits_remaining":259}`,
		// A marker that is not a real boolean is not a replay.
		`{"job_id":"job_r","email":"user@example.com","status":"pending","idempotent_replay":"true","credits_used":0}`,
		// Nor is a replay without a job to read.
		`{"email":"user@example.com","status":"pending","idempotent_replay":true,"credits_used":0}`,
	} {
		api := &replayAPI{
			posts: []scriptedReply{{200, body}},
			gets:  []scriptedReply{{200, completedJobBody}},
		}
		client := newReplayClient(t, api)

		_, err := client.Verify(context.Background(), "user@example.com")
		require.NoError(t, err, "body=%s", body)
		_, gets := api.counts()
		assert.Equal(t, 0, gets, "body=%s", body)
	}
}

// The case the replay path exists for: the first attempt was accepted and
// charged but its answer was lost (here a 503), the SDK retried under the
// same key, and the API replayed. The caller still gets the verdict.
func TestVerifyRetryThatGetsAReplayReturnsTheVerdict(t *testing.T) {
	api := &replayAPI{
		posts: []scriptedReply{{503, `{"success":false,"error":{"code":"SERVICE_UNAVAILABLE","message":"try again"}}`}, {200, replayBody}},
		gets:  []scriptedReply{{200, completedJobBody}},
	}
	client := newReplayClient(t, api)

	result, err := client.Verify(context.Background(), "user@example.com")
	require.NoError(t, err)

	assert.Equal(t, StatusValid, result.Status)
	require.NotNil(t, result.IdempotentReplay)
	assert.True(t, *result.IdempotentReplay)
	require.NotNil(t, result.CreditsUsed)
	assert.Equal(t, 0.5, *result.CreditsUsed)

	posts, gets := api.counts()
	assert.Equal(t, 2, posts)
	assert.Equal(t, 1, gets)
	api.mu.Lock()
	defer api.mu.Unlock()
	key := api.requests[0].Header.Get("Idempotency-Key")
	assert.Regexp(t, uuidV4, key)
	assert.Equal(t, key, api.requests[1].Header.Get("Idempotency-Key"))
}

const discountPendingJobBody = `{"job_id":"job_r","status":"completed","total_emails":1,"processed_emails":1,"progress_percent":100,"summary":{"valid":1,"invalid":0,"risky":0,"unknown":0},"results":[{"email":"user@example.com","status":"valid","quality_score":92,"flags":{"disposable":false,"role_account":false,"free_provider":false,"catch_all":false}}],"next_key":null,"has_more":false,"credits_used":1,"credits_refunded":0,"billing_status":"charged","cache_discount_pending":true,"completed_at":"2026-09-25T10:00:00.000Z"}`

// A completed read whose cache discount is still owed is final for the
// verdict but not the bill; the re-read settles it.
func TestVerifyReplayRereadsUntilTheCacheDiscountSettles(t *testing.T) {
	api := &replayAPI{
		posts: []scriptedReply{{200, replayBody}},
		gets:  []scriptedReply{{200, discountPendingJobBody}, {200, completedJobBody}},
	}
	client := newReplayClient(t, api)

	result, err := client.Verify(context.Background(), "user@example.com")
	require.NoError(t, err)

	assert.Equal(t, StatusValid, result.Status)
	require.NotNil(t, result.IdempotentReplay)
	assert.True(t, *result.IdempotentReplay)
	require.NotNil(t, result.CreditsUsed)
	assert.Equal(t, 0.5, *result.CreditsUsed)
	_, gets := api.counts()
	assert.Equal(t, 2, gets)
}

// Still owed after the short poll: the verdict stands, the cost is not
// measured, never the pre-discount 1.
func TestVerifyReplayDiscountStillPendingLeavesCreditsUsedUnset(t *testing.T) {
	api := &replayAPI{
		posts: []scriptedReply{{200, replayBody}},
		gets:  []scriptedReply{{200, discountPendingJobBody}},
	}
	client := newReplayClient(t, api)

	result, err := client.Verify(context.Background(), "user@example.com")
	require.NoError(t, err)

	assert.Equal(t, StatusValid, result.Status)
	assert.Equal(t, "job_r", result.JobID)
	require.NotNil(t, result.IdempotentReplay)
	assert.True(t, *result.IdempotentReplay)
	assert.Nil(t, result.CreditsUsed)
	assert.Nil(t, result.CreditsHeld)
	require.NotNil(t, result.CreditsRemaining)
	assert.Equal(t, 259.75, *result.CreditsRemaining)
	_, gets := api.counts()
	assert.Equal(t, replayPollMaxReads, gets)
}

// Only a real boolean true holds the bill open.
func TestVerifyReplayNonBooleanDiscountMarkerIsNotPending(t *testing.T) {
	for _, marker := range []string{`"true"`, `1`, `null`, `false`} {
		job := `{"job_id":"job_r","status":"completed","results":[{"email":"user@example.com","status":"valid"}],"credits_used":1,"credits_refunded":0.5,"cache_discount_pending":` + marker + `}`
		api := &replayAPI{
			posts: []scriptedReply{{200, replayBody}},
			gets:  []scriptedReply{{200, job}},
		}
		client := newReplayClient(t, api)

		result, err := client.Verify(context.Background(), "user@example.com")
		require.NoError(t, err, "marker=%s", marker)
		require.NotNil(t, result.CreditsUsed, "marker=%s", marker)
		assert.Equal(t, 0.5, *result.CreditsUsed, "marker=%s", marker)
		_, gets := api.counts()
		assert.Equal(t, 1, gets, "marker=%s", marker)
	}
}

// A verdict read once is kept: a later read that fails or finds nothing
// usable must not turn it back into "pending".
func TestVerifyReplayKeepsAVerdictWhenALaterReadFails(t *testing.T) {
	api := &replayAPI{
		posts: []scriptedReply{{200, replayBody}},
		gets: []scriptedReply{
			{200, discountPendingJobBody},
			{403, `{"success":false,"error":{"code":"INSUFFICIENT_SCOPE","message":"This API key does not have the verification:read scope"}}`},
		},
	}
	client := newReplayClient(t, api)

	result, err := client.Verify(context.Background(), "user@example.com")
	require.NoError(t, err)

	assert.Equal(t, StatusValid, result.Status)
	assert.False(t, result.IsPending())
	assert.Equal(t, "job_r", result.JobID)
	require.NotNil(t, result.IdempotentReplay)
	assert.True(t, *result.IdempotentReplay)
	assert.Nil(t, result.CreditsUsed)
	assert.Nil(t, result.CreditsHeld)
	require.NotNil(t, result.CreditsRemaining)
	assert.Equal(t, 259.75, *result.CreditsRemaining)
	_, gets := api.counts()
	assert.Equal(t, 2, gets)
}

func TestVerifyReplayKeepsAVerdictOverLaterUnusableReads(t *testing.T) {
	for name, later := range map[string]scriptedReply{
		"server error":        {500, `{"success":false,"error":{"code":"INTERNAL_ERROR","message":"boom"}}`},
		"not an object":       {200, `"completed"`},
		"completed, no row":   {200, `{"job_id":"job_r","status":"completed","results":[],"credits_used":1,"credits_refunded":0.5}`},
		"failed":              {200, `{"job_id":"job_r","status":"failed","credits_used":1,"credits_refunded":0}`},
		"cancelled":           {200, `{"job_id":"job_r","status":"cancelled"}`},
		"reads run out":       {200, processingJobBody},
		"pending, no row now": {200, `{"job_id":"job_r","status":"completed","results":[],"credits_used":1,"cache_discount_pending":true}`},
	} {
		api := &replayAPI{
			posts: []scriptedReply{{200, replayBody}},
			gets:  []scriptedReply{{200, discountPendingJobBody}, later},
		}
		client := newReplayClient(t, api)
		client.maxRetries = 1

		result, err := client.Verify(context.Background(), "user@example.com")
		require.NoError(t, err, name)
		assert.Equal(t, StatusValid, result.Status, name)
		require.NotNil(t, result.IdempotentReplay, name)
		assert.True(t, *result.IdempotentReplay, name)
		assert.Nil(t, result.CreditsUsed, name)
	}
}

func TestVerifyReplayKeepsAVerdictWhenTheCallerStopsWaiting(t *testing.T) {
	api := &replayAPI{
		posts: []scriptedReply{{200, replayBody}},
		gets:  []scriptedReply{{200, discountPendingJobBody}},
	}
	client := newReplayClient(t, api)
	client.replayPollInterval = time.Hour

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result, err := client.Verify(ctx, "user@example.com")
	require.NoError(t, err)
	assert.Equal(t, StatusValid, result.Status)
	assert.Nil(t, result.CreditsUsed)
	_, gets := api.counts()
	assert.Equal(t, 1, gets)
}

// Pending discount with no usable result on the last read: the unresolved
// replay, as before.
func TestVerifyReplayDiscountPendingWithoutAResultReturnsThePendingReplay(t *testing.T) {
	api := &replayAPI{
		posts: []scriptedReply{{200, replayBody}},
		gets:  []scriptedReply{{200, `{"job_id":"job_r","status":"completed","results":[],"credits_used":1,"cache_discount_pending":true}`}},
	}
	client := newReplayClient(t, api)

	result, err := client.Verify(context.Background(), "user@example.com")
	require.NoError(t, err)
	assert.True(t, result.IsPending())
	assert.Nil(t, result.CreditsUsed)
	_, gets := api.counts()
	assert.Equal(t, replayPollMaxReads, gets)
}
