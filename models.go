package kawaa

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// VerificationStatus represents the status of an email verification.
//
// The API emits the full vocabulary below. StatusPending is only returned
// by POST /v1/verify when the synchronous poll window elapses before the
// worker finishes; poll GetJobStatus(jobID) for the final result then.
type VerificationStatus string

const (
	StatusValid      VerificationStatus = "valid"
	StatusInvalid    VerificationStatus = "invalid"
	StatusRisky      VerificationStatus = "risky"
	StatusUnknown    VerificationStatus = "unknown"
	StatusSpamTrap   VerificationStatus = "spam_trap"
	StatusDisposable VerificationStatus = "disposable"
	StatusRole       VerificationStatus = "role"
	StatusCatchAll   VerificationStatus = "catch_all"
	StatusPending    VerificationStatus = "pending"
)

// JobStatus represents the status of a batch job.
//
// JobStatusEnqueueUnknown is returned by POST /v1/verify/batch when some
// messages had an unknown enqueue outcome; credits are held pending
// reconciliation and the job should be polled via GetJobStatus.
type JobStatus string

const (
	JobStatusPending        JobStatus = "pending"
	JobStatusProcessing     JobStatus = "processing"
	JobStatusCompleted      JobStatus = "completed"
	JobStatusFailed         JobStatus = "failed"
	JobStatusCancelled      JobStatus = "cancelled"
	JobStatusEnqueueUnknown JobStatus = "enqueue_unknown"
)

// VerificationFlags contains flags indicating email characteristics.
type VerificationFlags struct {
	Disposable   bool `json:"disposable"`
	Role         bool `json:"role_account"`
	FreeProvider bool `json:"free_provider"`
	// CatchAll is true when Kawaa saw the domain accept mail for any address
	// (or the status is "catch_all"). False does not on its own mean the
	// domain was checked: it is also false when nothing measured it, for
	// example a disposable verdict, a domain with no usable mail server, or a
	// mail server that refused the mailbox or never answered. Read
	// CatchAllMeasured to tell the two apart.
	CatchAll bool `json:"catch_all"`
	SpamTrap bool `json:"spam_trap"`
	// AbuseEmail is true when the local part matched an abuse,
	// complaint-handling, feedback-loop, legal or blocklist-removal name or
	// pattern (abuse@, postmaster@, feedback@, ...), at any domain. A match on
	// the address itself, not a finding about its owner.
	AbuseEmail bool `json:"abuse_email"`
	// Complainer is a narrower AbuseEmail: a complaint-handling mailbox at a
	// reviewed anti-spam, feedback-loop or consumer-protection organization.
	// Every address with Complainer set has AbuseEmail too.
	Complainer bool `json:"complainer"`
	// Honeypot and BotGenerated are the API's flags of the same names.
	Honeypot     bool `json:"honeypot"`
	BotGenerated bool `json:"bot_generated"`
	// CatchAllMeasured is true when the API measured catch-all for this
	// address: CatchAll false then means the domain was checked and does not
	// accept every address. False means nothing measured it, so CatchAll
	// false is "unknown", not "not catch-all". Derived when the result is
	// decoded (the API states its finding as verification.catch_all and
	// leaves it out when nothing measured it), so it is not read from or
	// written to JSON.
	CatchAllMeasured bool `json:"-"`
}

// UnmarshalJSON accepts both "role_account" (current API) and legacy "role" field.
//
// The abuse_email, complainer, honeypot and bot_generated flags are read
// leniently: the verification has been charged by the time it is parsed, so
// a value that is not a boolean reads as false rather than failing the
// decode.
func (f *VerificationFlags) UnmarshalJSON(data []byte) error {
	type Alias VerificationFlags
	aux := &struct {
		*Alias
		LegacyRole   *bool           `json:"role"`
		AbuseEmail   json.RawMessage `json:"abuse_email"`
		Complainer   json.RawMessage `json:"complainer"`
		Honeypot     json.RawMessage `json:"honeypot"`
		BotGenerated json.RawMessage `json:"bot_generated"`
	}{Alias: (*Alias)(f)}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	f.AbuseEmail = isTrue(aux.AbuseEmail)
	f.Complainer = isTrue(aux.Complainer)
	f.Honeypot = isTrue(aux.Honeypot)
	f.BotGenerated = isTrue(aux.BotGenerated)
	// If role_account was not set but legacy "role" was, use the legacy value
	if !f.Role && aux.LegacyRole != nil && *aux.LegacyRole {
		f.Role = true
	}
	return nil
}

// VerificationDetails contains technical verification details.
type VerificationDetails struct {
	MXRecords []string `json:"mx_records"`
	// SMTPResponse is the mail server's reply to the mailbox probe, e.g.
	// "250 2.1.5 OK". The API sends it as verification.smtp_message (the flat
	// download row's smtp_response is DownloadRow.SMTPResponse). Empty when no
	// probe got an answer.
	SMTPResponse string `json:"smtp_message,omitempty"`
	// SMTPCode is the reply's numeric code (verification.smtp_code), e.g. 250.
	// Nil when no probe got an answer.
	SMTPCode *int `json:"smtp_code,omitempty"`
	// CatchAll is verification.catch_all. The API leaves it out when nothing
	// measured it, which reads as false here: use
	// VerificationResult.Flags.CatchAllMeasured to tell the two apart.
	CatchAll bool `json:"catch_all,omitempty"`

	// catchAllStated records whether verification.catch_all was a boolean.
	catchAllStated bool
}

// UnmarshalJSON reads the SMTP reply from smtp_message, where the API sends
// it. Reading smtp_response, which only the flat download rows carry, left
// the reply empty on every verification and every job result row; it is
// still read when smtp_message is absent. Both SMTP fields are read
// leniently: the verification has been charged by the time it is parsed, and
// a wrong-typed value is "not stated", never an error that fails the decode.
// catch_all is read the same way, and whether it was stated at all is kept:
// the API leaves it out when nothing measured it.
func (d *VerificationDetails) UnmarshalJSON(data []byte) error {
	// The alias drops this method; the shallower fields shadow its own.
	type Alias VerificationDetails
	aux := struct {
		*Alias
		SMTPMessage  json.RawMessage `json:"smtp_message"`
		SMTPResponse json.RawMessage `json:"smtp_response"`
		SMTPCode     json.RawMessage `json:"smtp_code"`
		CatchAll     json.RawMessage `json:"catch_all"`
	}{Alias: (*Alias)(d)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	catchAll := optionalBool(aux.CatchAll)
	d.CatchAll = catchAll != nil && *catchAll
	d.catchAllStated = catchAll != nil
	d.SMTPResponse = ""
	if message := optionalString(aux.SMTPMessage); message != nil {
		d.SMTPResponse = *message
	} else if response := optionalString(aux.SMTPResponse); response != nil {
		d.SMTPResponse = *response
	}
	d.SMTPCode = optionalInt(aux.SMTPCode)
	return nil
}

// MarshalJSON writes catch_all only when the API stated it (or it is true), so
// a round trip through JSON keeps a measured false and never turns an
// unmeasured one into a finding.
func (d VerificationDetails) MarshalJSON() ([]byte, error) {
	// The alias drops this method; the shallower field shadows its own.
	type Alias VerificationDetails
	aux := struct {
		Alias
		CatchAll *bool `json:"catch_all,omitempty"`
	}{Alias: Alias(d)}
	if d.catchAllStated || d.CatchAll {
		stated := d.CatchAll
		aux.CatchAll = &stated
	}
	return json.Marshal(aux)
}

// optionalString reads a JSON string, or nil when raw is absent, null or not
// a string.
func optionalString(raw json.RawMessage) *string {
	if len(raw) == 0 {
		return nil
	}
	var decoded any
	if json.Unmarshal(raw, &decoded) != nil {
		return nil
	}
	s, ok := decoded.(string)
	if !ok {
		return nil
	}
	return &s
}

// optionalInt reads a JSON integer, or nil when raw is absent, null or not an
// integer.
//
// A JSON null is checked for first: `json.Unmarshal` treats null as a no-op
// and returns no error, so decoding it straight into an int would report 0
// for a value the API never stated.
func optionalInt(raw json.RawMessage) *int {
	if len(raw) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return nil
	}
	var n int
	if json.Unmarshal(raw, &n) != nil {
		return nil
	}
	return &n
}

// isTrue reports whether raw is the JSON boolean true. Absent, null and any
// other type read as false.
func isTrue(raw json.RawMessage) bool {
	b := optionalBool(raw)
	return b != nil && *b
}

// VerificationResult represents the result of a single email verification.
type VerificationResult struct {
	Email  string             `json:"email"`
	Status VerificationStatus `json:"status"`
	// SubStatus is a machine-readable reason explaining how Status was
	// reached (e.g. "mailbox_reject", "policy_block").
	SubStatus    string               `json:"sub_status,omitempty"`
	Score        int                  `json:"quality_score"`
	Flags        VerificationFlags    `json:"flags"`
	Suggestion   string               `json:"suggestion,omitempty"`
	Verification *VerificationDetails `json:"verification,omitempty"`
	Reason       string               `json:"reason,omitempty"`
	// JobID is the polling handle; present when Status is StatusPending.
	JobID string `json:"job_id,omitempty"`
	// Message is a human-readable note (present when Status is StatusPending).
	Message string `json:"message,omitempty"`

	// CreditsUsed is what this verification cost, from the API rather than
	// the price list: 1 for a fresh check, 0.5 for a cached one, so it is a
	// float64, never an int. Nil when the response carried no figure (the
	// rows of a batch job's Results never do).
	CreditsUsed *float64 `json:"credits_used,omitempty"`
	// CreditsRemaining is the balance after the charge. Nil means the API
	// omitted it (a keyed replay whose ledger snapshot could not be safely
	// read omits it), never zero.
	CreditsRemaining *float64 `json:"credits_remaining,omitempty"`
	// CreditsHeld is the credit held rather than settled while Status is
	// StatusPending: the worker has not finished, or the enqueue failed and
	// the refund is still reconciling.
	CreditsHeld *float64 `json:"credits_held,omitempty"`

	// IdempotentReplay is true when this response repeated a request already
	// accepted under the same Idempotency-Key, the SDK's own retry after a
	// lost response (Verify sends a key on every call) or a caller key used
	// again, and therefore charged nothing more.
	//
	// The API answers such a repeat with the pending shape and the original
	// job's id. Verify reads that job back (GET /v1/jobs/{id}, briefly polling
	// while it is still running) and returns its result, so a verification
	// that had already finished is not reported as pending. CreditsUsed then
	// reports what that original verification cost, read from the job (the
	// same way FindResult.CreditsUsed reports what a replayed search cost),
	// so summing CreditsUsed across calls that reuse one key over-counts
	// unless this is checked. CreditsUsed is nil when the job's cache
	// discount was still being applied after the short poll (the job read
	// said cache_discount_pending), or when the job read carried no charge:
	// the cost is not known, so read the job by JobID (its credits_used less
	// credits_refunded) for the final charge.
	// If the result could not be read back (the job
	// was still running, or the read failed: a key without
	// verification:read, for example), Status is StatusPending with
	// CreditsUsed nil: poll GetJobStatus(JobID) for the result and its
	// charge. The replay's own credits_used 0 is what the repeat cost, not
	// what the verification cost, so it is never reported as the cost.
	//
	// Nil means the API said nothing either way; only a real boolean sets it.
	IdempotentReplay *bool `json:"idempotent_replay,omitempty"`

	// FromCache is true when the API answered from its verification cache
	// (charged 0.5) instead of checking the mailbox again.
	FromCache bool `json:"from_cache,omitempty"`
	// CacheAgeSeconds is how old a cached result is, in seconds. Set on
	// every cache hit, beside FromCache; nil otherwise. Without it a result
	// reused from days ago reads exactly like one measured this second.
	CacheAgeSeconds *int `json:"cache_age_seconds,omitempty"`
	// VerifiedAt is when the verdict was measured (RFC 3339). On a cache hit
	// it is the time of the original check, not of this call.
	VerifiedAt string `json:"verified_at,omitempty"`
	// Enrichment holds the name, gender and country hints the API attaches
	// when the request set VerifyOptions.Enrich and the plan includes data
	// enrichment (Business and up). Nil when the request did not ask for it,
	// and when the API knows nothing about the address, which is not a
	// judgement about the address.
	Enrichment *Enrichment `json:"enrichment,omitempty"`
	// EmailUnicode is Email with an internationalized domain written back in
	// its standard Unicode spelling ("info@müller.de" where Email is
	// "info@xn--mller-kva.de"), the same as Email for every other address
	// (email_unicode). The API checks and returns the ASCII form, so this is
	// what to match a row to your own list by, ignoring case. Set on job result rows (GetJobStatus with results, WaitForJob)
	// (every row from November 17, 2026); empty on older rows and on a single Verify answer.
	EmailUnicode string `json:"email_unicode,omitempty"`
}

// Enrichment is the data enrichment the API attaches to a verification when
// VerifyOptions.Enrich is set. Each field is empty when the API has no hint
// for it.
type Enrichment struct {
	FirstName   string `json:"first_name,omitempty"`
	LastName    string `json:"last_name,omitempty"`
	FullName    string `json:"full_name,omitempty"`
	Gender      string `json:"gender,omitempty"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
}

// optionalEnrichment reads the enrichment object leniently: nil when raw is
// absent, null or not an object, and a field that is not a string reads as
// empty rather than failing the decode of a charged verification.
func optionalEnrichment(raw json.RawMessage) *Enrichment {
	if len(raw) == 0 {
		return nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil
	}
	text := func(name string) string {
		if s := optionalString(fields[name]); s != nil {
			return *s
		}
		return ""
	}
	return &Enrichment{
		FirstName:   text("first_name"),
		LastName:    text("last_name"),
		FullName:    text("full_name"),
		Gender:      text("gender"),
		Country:     text("country"),
		CountryCode: text("country_code"),
	}
}

// UnmarshalJSON derives Flags.CatchAll from verification.catch_all or
// status == "catch_all" when the flags object omits it (flags.catch_all is
// optional on the wire; those are the authoritative locations).
//
// The credit figures and the replay marker are read leniently: a
// verification has already been charged by the time its response is parsed,
// and a wrong-typed hint about how to count that charge must not fail the
// whole decode; the natural response to a parse error is a retry, which
// under a fresh key is a second charge. Absent, null or non-numeric figures
// read as nil (unknown), never zero.
func (r *VerificationResult) UnmarshalJSON(data []byte) error {
	// The alias drops this method, so the embedded value decodes normally.
	// The shallower fields shadow the embedded ones of the same name.
	type Alias VerificationResult
	aux := struct {
		*Alias
		CreditsUsed      json.RawMessage `json:"credits_used"`
		CreditsRemaining json.RawMessage `json:"credits_remaining"`
		CreditsHeld      json.RawMessage `json:"credits_held"`
		IdempotentReplay json.RawMessage `json:"idempotent_replay"`
		FromCache        json.RawMessage `json:"from_cache"`
		CacheAgeSeconds  json.RawMessage `json:"cache_age_seconds"`
		VerifiedAt       json.RawMessage `json:"verified_at"`
		Enrichment       json.RawMessage `json:"enrichment"`
		EmailUnicode     json.RawMessage `json:"email_unicode"`
	}{Alias: (*Alias)(r)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	r.CreditsUsed = optionalNumber(aux.CreditsUsed)
	r.CreditsRemaining = optionalNumber(aux.CreditsRemaining)
	r.CreditsHeld = optionalNumber(aux.CreditsHeld)
	r.IdempotentReplay = optionalBool(aux.IdempotentReplay)
	r.FromCache = isTrue(aux.FromCache)
	r.CacheAgeSeconds = optionalInt(aux.CacheAgeSeconds)
	r.VerifiedAt = ""
	if verifiedAt := optionalString(aux.VerifiedAt); verifiedAt != nil {
		r.VerifiedAt = *verifiedAt
	}
	r.Enrichment = optionalEnrichment(aux.Enrichment)
	r.EmailUnicode = ""
	if emailUnicode := optionalString(aux.EmailUnicode); emailUnicode != nil {
		r.EmailUnicode = *emailUnicode
	}
	if !r.Flags.CatchAll {
		if (r.Verification != nil && r.Verification.CatchAll) || r.Status == StatusCatchAll {
			r.Flags.CatchAll = true
		}
	}
	// Measured: a positive signal, or a verification.catch_all the API
	// stated. A flags.catch_all of false is not a measurement: the API does
	// not send that key, and a stored row from an older worker could carry
	// it unmeasured.
	r.Flags.CatchAllMeasured = r.Flags.CatchAll ||
		(r.Verification != nil && r.Verification.catchAllStated)
	if r.Status == StatusDisposable {
		r.Flags.Disposable = true
	}
	if r.Status == StatusRole {
		r.Flags.Role = true
	}
	if r.Status == StatusSpamTrap {
		r.Flags.SpamTrap = true
	}
	return nil
}

// IsValid returns true if the email is valid.
func (r *VerificationResult) IsValid() bool {
	return r.Status == StatusValid
}

// IsDeliverable returns true only when status is valid.
func (r *VerificationResult) IsDeliverable() bool {
	return r.Status == StatusValid
}

// IsPending returns true when POST /v1/verify timed out and returned a job
// handle (poll GetJobStatus(JobID) for the final result).
func (r *VerificationResult) IsPending() bool {
	return r.Status == StatusPending
}

// optionalNumber reads a JSON number, or nil when raw is absent, null or not
// a number. Whole and fractional numbers both read: credit amounts are
// routinely fractional (a cached verification costs 0.5, an activity lookup
// 0.25), and decoding them into an int failed the whole response.
func optionalNumber(raw json.RawMessage) *float64 {
	if len(raw) == 0 {
		return nil
	}
	var decoded any
	if json.Unmarshal(raw, &decoded) != nil {
		return nil
	}
	n, ok := decoded.(float64)
	if !ok {
		return nil
	}
	return &n
}

// optionalBool reads a JSON boolean, or nil when raw is absent, null or any
// other type.
//
// Decoded into `any` and type-asserted, not into a bool: `json.Unmarshal`
// treats a JSON null as a no-op and returns NO error, so unmarshalling null
// into a bool leaves it at false, which, for a replay marker, would publish
// "you were charged" for a marker the API never stated.
func optionalBool(raw json.RawMessage) *bool {
	if len(raw) == 0 {
		return nil
	}
	var decoded any
	if json.Unmarshal(raw, &decoded) != nil {
		return nil
	}
	b, ok := decoded.(bool)
	if !ok {
		return nil
	}
	return &b
}

// BatchJobResult represents the result of creating a batch verification job.
//
// Credit figures are float64: a batch's charge and the balance after it are
// fractional whenever part of the account's spend was (cached verifications
// cost 0.5), and an int field failed the decode AFTER the batch had been
// charged, losing the job id, so a retry under a new key paid again.
type BatchJobResult struct {
	JobID             string    `json:"job_id"`
	Status            JobStatus `json:"status"`
	TotalSubmitted    int       `json:"total_submitted"`
	DuplicatesRemoved int       `json:"duplicates_removed"`
	UniqueEmails      int       `json:"unique_emails"`
	// CreditsUsed is what the batch was charged when the API accepted it.
	// Nil when it is not known: the response carried no number, or the
	// response was an idempotent replay (see IdempotentReplay).
	CreditsUsed *float64 `json:"credits_used,omitempty"`
	// CreditsRemaining is the balance after the original charge. Nil means
	// the API omitted it (a replay whose ledger snapshot could not be safely
	// read), never zero.
	CreditsRemaining *float64 `json:"credits_remaining,omitempty"`
	// CreditsHeld is the credit held pending reconciliation of an ambiguous
	// enqueue (Status JobStatusEnqueueUnknown). Nil when none is held.
	CreditsHeld *float64 `json:"credits_held,omitempty"`
	// IdempotentReplay is true when this response repeated a batch the API
	// had already accepted under the same Idempotency-Key: this client's own
	// retry after a lost response, or a caller key used again. Nothing more
	// was charged. The API answers such a repeat with credits_used 0, which
	// is what the repeat cost, not what the batch cost, so CreditsUsed is
	// left nil. The batch's charge and refunds are on its job: read
	// GetJobStatus(JobID) for CreditsCharged and CreditsRefunded.
	//
	// Nil means the API said nothing either way; only a real boolean sets it.
	IdempotentReplay *bool  `json:"idempotent_replay,omitempty"`
	Message          string `json:"message,omitempty"`
	// InvalidEmailsSkipped is how many submitted addresses the API refused as
	// malformed and never verified or charged: the job's results are that
	// much shorter than the list you sent. Nil when the API did not report it.
	InvalidEmailsSkipped *int `json:"invalid_emails_skipped,omitempty"`
	// EnqueueUnknown is how many queue sends could not be confirmed. Their
	// credits are in CreditsHeld, not spent: poll the job until it
	// reconciles. Nil means the API did not report a count, not that every
	// send was confirmed: a replay of a batch still in that state carries
	// the status but no count. Status JobStatusEnqueueUnknown, or a positive
	// count, is what says some sends are unconfirmed.
	EnqueueUnknown *int `json:"enqueue_unknown,omitempty"`
}

// UnmarshalJSON reads the credit figures and the replay marker leniently, as
// VerificationResult does: the batch has been charged by the time its
// response is parsed, and a wrong-typed figure must not fail the decode.
// Absent, null or non-numeric figures read as nil (unknown), never zero.
//
// A replay's credits_used is not read as the batch's cost: see
// IdempotentReplay.
func (r *BatchJobResult) UnmarshalJSON(data []byte) error {
	type Alias BatchJobResult
	aux := struct {
		*Alias
		CreditsUsed          json.RawMessage `json:"credits_used"`
		CreditsRemaining     json.RawMessage `json:"credits_remaining"`
		CreditsHeld          json.RawMessage `json:"credits_held"`
		IdempotentReplay     json.RawMessage `json:"idempotent_replay"`
		InvalidEmailsSkipped json.RawMessage `json:"invalid_emails_skipped"`
		EnqueueUnknown       json.RawMessage `json:"enqueue_unknown"`
	}{Alias: (*Alias)(r)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	r.CreditsUsed = optionalNumber(aux.CreditsUsed)
	r.CreditsRemaining = optionalNumber(aux.CreditsRemaining)
	r.CreditsHeld = optionalNumber(aux.CreditsHeld)
	r.IdempotentReplay = optionalBool(aux.IdempotentReplay)
	r.InvalidEmailsSkipped = optionalInt(aux.InvalidEmailsSkipped)
	r.EnqueueUnknown = optionalInt(aux.EnqueueUnknown)
	if r.IdempotentReplay != nil && *r.IdempotentReplay {
		r.CreditsUsed = nil
	}
	return nil
}

// JobSummary contains the per-status counts for a job. Risky includes
// catch_all/role/spam_trap results; invalid includes disposable ones.
type JobSummary struct {
	Valid   int `json:"valid"`
	Invalid int `json:"invalid"`
	Risky   int `json:"risky"`
	Unknown int `json:"unknown"`
}

// JobStatusResult represents the status of a batch verification job.
//
// Counts are sourced from the API's nested `summary` object; the flat
// *Count fields are populated from it for convenience (with legacy
// flat-field fallback for older API builds).
type JobStatusResult struct {
	JobID           string      `json:"job_id"`
	Status          JobStatus   `json:"status"`
	TotalEmails     int         `json:"total_emails"`
	ProcessedEmails int         `json:"processed_emails"`
	Summary         *JobSummary `json:"summary,omitempty"`
	ValidCount      int         `json:"valid_count"`
	InvalidCount    int         `json:"invalid_count"`
	RiskyCount      int         `json:"risky_count"`
	UnknownCount    int         `json:"unknown_count"`
	ProgressPercent float64     `json:"progress_percent"`
	CreatedAt       string      `json:"created_at,omitempty"`
	CompletedAt     string      `json:"completed_at,omitempty"`
	// BillingStatus is where the money stands: "charged", "refund_pending",
	// "refunded" or "refund_failed". Empty on a job whose bill the API has
	// not published.
	BillingStatus string `json:"billing_status,omitempty"`
	// CacheDiscountPending is set only when a read tried to apply the
	// per-address cache discount and could not, almost always because the
	// results index had not caught up. The next read retries it, and until
	// then the bill is not final.
	CacheDiscountPending bool `json:"cache_discount_pending,omitempty"`
	// ErrorMessage is why a job ended as it did, in the API's own words
	// (error_message), for example on a failed job. Empty when the API gave
	// no reason.
	ErrorMessage string `json:"error_message,omitempty"`
	// CreditsCharged is what the job was charged (or held) when it was
	// accepted, and CreditsRefunded what has come back since: for failed or
	// unqueued addresses, a cancellation, or the cache discount. The job's
	// net cost is CreditsCharged - CreditsRefunded, both from this read; the
	// acceptance response's CreditsUsed is already net of refunds made at
	// submission, so subtracting CreditsRefunded from it counts those twice.
	// Both are fractional whenever a cached result was discounted, and nil
	// when the API did not report them.
	CreditsCharged  *float64 `json:"credits_used,omitempty"`
	CreditsRefunded *float64 `json:"credits_refunded,omitempty"`
	// Results holds one page of results when include_results is requested
	// (the API pages 100 at a time; NextKey/HasMore describe further pages).
	// Use DownloadResults to fetch everything.
	Results []VerificationResult `json:"results,omitempty"`
	NextKey string               `json:"next_key,omitempty"`
	HasMore bool                 `json:"has_more,omitempty"`
}

// UnmarshalJSON populates the flat *Count fields from the nested summary
// object (the API never sends flat counts; they are kept as a fallback for
// older builds). The fallback is PER FIELD: a summary object that is
// present but carries a null/absent bucket must not zero that bucket while
// a legacy count is available.
func (r *JobStatusResult) UnmarshalJSON(data []byte) error {
	type Alias JobStatusResult
	aux := (*Alias)(r)
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	if r.Summary != nil {
		// Re-decode just the summary with pointer fields to distinguish
		// null/absent buckets from a legitimate 0.
		var wire struct {
			Summary struct {
				Valid   *int `json:"valid"`
				Invalid *int `json:"invalid"`
				Risky   *int `json:"risky"`
				Unknown *int `json:"unknown"`
			} `json:"summary"`
		}
		if err := json.Unmarshal(data, &wire); err == nil {
			if wire.Summary.Valid != nil {
				r.ValidCount = *wire.Summary.Valid
			}
			if wire.Summary.Invalid != nil {
				r.InvalidCount = *wire.Summary.Invalid
			}
			if wire.Summary.Risky != nil {
				r.RiskyCount = *wire.Summary.Risky
			}
			if wire.Summary.Unknown != nil {
				r.UnknownCount = *wire.Summary.Unknown
			}
		}
	}
	return nil
}

// IsCompleted returns true if the job is completed.
func (r *JobStatusResult) IsCompleted() bool {
	return r.Status == JobStatusCompleted
}

// IsFailed returns true if the job failed.
func (r *JobStatusResult) IsFailed() bool {
	return r.Status == JobStatusFailed
}

// IsCancelled returns true if the job was cancelled.
func (r *JobStatusResult) IsCancelled() bool {
	return r.Status == JobStatusCancelled
}

// IsSettled reports whether the job's BILL is final.
//
// Completed and failed imply it. A cancelled job does not: its verdicts are
// final the moment it reads "cancelled", because the worker commits every
// result under a condition on the running statuses and the cancel moves the
// job out of them, but the refund for the addresses it never checked waits
// for the in-flight ones to time out, a few minutes later. CompletedAt is
// the API's own "the books are closed" marker: a cancel leaves it empty, and
// every path that settles the job sets it.
//
// Results do not need this; act on them as soon as the status is terminal.
// Read this only if you are reconciling the charge.
// A refund the API has not applied yet is money still owed, whatever the
// status says: a stale single verification is reconciled to "failed" with
// billing_status "refund_pending", and the credit comes back on a LATER
// read. So the billing status has a veto here.
func (r *JobStatusResult) IsSettled() bool {
	if r.BillingStatus == "refund_pending" || r.CacheDiscountPending {
		return false
	}
	if r.IsCompleted() || r.IsFailed() {
		return true
	}
	return r.IsCancelled() && r.CompletedAt != ""
}

// DownloadRow is a single flat row from GET /v1/jobs/{id}/download (the
// download endpoint exports flat rows, not the nested VerificationResult
// shape): {email, status, score, disposable, role, free_provider,
// catch_all, suggestion, mx_records, smtp_response, verified_at, sub_status,
// email_unicode}.
type DownloadRow struct {
	Email        string             `json:"email"`
	Status       VerificationStatus `json:"status"`
	Score        int                `json:"score"`
	Disposable   bool               `json:"disposable"`
	Role         bool               `json:"role"`
	FreeProvider bool               `json:"free_provider"`
	// CatchAll is true when a probe found an accept-everything domain. The
	// export leaves catch_all out when nothing measured it, which reads as
	// false here: CatchAllMeasured tells the two apart.
	CatchAll bool `json:"catch_all"`
	// CatchAllMeasured is true when the row stated catch_all (true or false)
	// or its status is "catch_all". Derived when the row is decoded.
	CatchAllMeasured bool     `json:"-"`
	Suggestion       string   `json:"suggestion,omitempty"`
	MXRecords        []string `json:"mx_records,omitempty"`
	SMTPResponse     string   `json:"smtp_response,omitempty"`
	VerifiedAt       string   `json:"verified_at,omitempty"`
	// SubStatus is the reason code behind Status (e.g. "mailbox_reject"), the
	// download's last column. Empty when the result has none, as on a
	// disposable or spam-trap verdict whose DNS lookups answered; one whose
	// lookup failed carries "temporary_failure".
	SubStatus string `json:"sub_status,omitempty"`
	// EmailUnicode is Email with an internationalized domain written back in
	// its standard Unicode spelling ("info@müller.de" where Email is
	// "info@xn--mller-kva.de"), the same as Email for every other address
	// (email_unicode). The API checks and returns the ASCII form, so this is
	// what to match a row to your own list by, ignoring case. Set on download rows
	// (every row from November 17, 2026); empty on older rows.
	EmailUnicode string `json:"email_unicode,omitempty"`
}

// UnmarshalJSON reads catch_all leniently and records whether the row stated
// it: the export leaves it out when nothing measured it.
func (r *DownloadRow) UnmarshalJSON(data []byte) error {
	// The alias drops this method; the shallower field shadows its own.
	type Alias DownloadRow
	aux := struct {
		*Alias
		CatchAll     json.RawMessage `json:"catch_all"`
		EmailUnicode json.RawMessage `json:"email_unicode"`
	}{Alias: (*Alias)(r)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	r.EmailUnicode = ""
	if emailUnicode := optionalString(aux.EmailUnicode); emailUnicode != nil {
		r.EmailUnicode = *emailUnicode
	}
	catchAll := optionalBool(aux.CatchAll)
	r.CatchAll = (catchAll != nil && *catchAll) || r.Status == StatusCatchAll
	r.CatchAllMeasured = catchAll != nil || r.CatchAll
	return nil
}

// MarshalJSON writes catch_all only when it was measured, as the export does,
// so a round trip through JSON keeps CatchAllMeasured.
func (r DownloadRow) MarshalJSON() ([]byte, error) {
	// The alias drops this method; the shallower field shadows its own.
	type Alias DownloadRow
	aux := struct {
		Alias
		CatchAll *bool `json:"catch_all,omitempty"`
	}{Alias: Alias(r)}
	if r.CatchAllMeasured || r.CatchAll {
		measured := r.CatchAll
		aux.CatchAll = &measured
	}
	return json.Marshal(aux)
}

// IsValid returns true if the row's status is valid.
func (r *DownloadRow) IsValid() bool {
	return r.Status == StatusValid
}

// DownloadResult represents the result of downloading job results.
//
// For jobs with more than 1000 results the API responds with a presigned
// DownloadURL instead of inline rows; the SDK fetches it transparently so
// Results is always populated.
type DownloadResult struct {
	JobID            string        `json:"job_id"`
	ResultCount      int           `json:"result_count"`
	Results          []DownloadRow `json:"results,omitempty"`
	DownloadURL      string        `json:"download_url,omitempty"`
	ExpiresInSeconds int           `json:"expires_in_seconds,omitempty"`
	// Complete is true only when the API compared this export with the job's
	// processed row count. Nil means the comparison could not be made.
	Complete     *bool  `json:"complete"`
	ExpectedRows *int   `json:"expected_rows"`
	RowsMissing  *int   `json:"rows_missing"`
	Message      string `json:"message,omitempty"`
}

// AllowanceBasis says whether an account's credit allowance renews, and so
// what AccountInfo.CreditsUsed and AccountInfo.MonthlyAllowance mean. The API
// names both "monthly" on every plan because a paid subscription is the common
// case; only AllowanceBillingPeriod actually renews.
//
// It is a string type rather than a closed enum so a value a newer API adds
// still decodes. Treat any value other than AllowanceBillingPeriod, including
// one this release does not name and the empty string (not reported), as not
// renewing.
type AllowanceBasis string

const (
	// AllowanceBillingPeriod: CreditsUsed is spend in the current billing
	// period, and NextReset says when the allowance refills. Take it as
	// renewing only when NextReset is set too: an API build from before
	// 2026-09-30 sent it for a paid plan with no billing period on file.
	AllowanceBillingPeriod AllowanceBasis = "billing_period"
	// AllowanceNoBillingPeriod: a paid plan with no billing period on file.
	// Nothing resets CreditsUsed on a schedule, so it is cumulative.
	AllowanceNoBillingPeriod AllowanceBasis = "no_billing_period"
	// AllowanceOneTimeGrant: the Free plan. Its credits are granted once and
	// never reset, so CreditsUsed is everything spent since the grant and
	// MonthlyAllowance is the size of that grant, not a monthly figure.
	AllowanceOneTimeGrant AllowanceBasis = "one_time_grant"
	// AllowanceProviderAllocation: a white-label sub-account spending the pool
	// its provider allocated. It never renews on a schedule.
	AllowanceProviderAllocation AllowanceBasis = "provider_allocation"
)

// AccountInfo represents user account information, flattened from
// GET /v1/account's nested {account: {...}, credits: {...}} response.
// (Parsing is handled by the custom UnmarshalJSON; the tags below only
// affect marshalling.)
//
// Credit figures are float64: the balance is fractional whenever part of the
// spend was (a cached verification costs 0.5, an activity lookup 0.25), and
// decoding it into an int failed GetAccount outright.
//
// Read AllowanceBasis before describing CreditsUsed or MonthlyAllowance as
// monthly: on the Free plan they are a one-time grant and the spend against
// it, and nothing resets them.
type AccountInfo struct {
	UserID           string  `json:"user_id"`
	Email            string  `json:"email"`
	Name             string  `json:"name,omitempty"`
	Plan             string  `json:"plan"`
	Status           string  `json:"status,omitempty"`
	CreditsRemaining float64 `json:"credits_remaining"`
	// CreditsUsed is spend in the current billing period only when
	// AllowanceBasis is AllowanceBillingPeriod; otherwise it is cumulative.
	// Nil when the API did not send the figure: it withholds usage from a key
	// without the analytics:read scope, and UsageWithheld is then true. Never
	// 0 for "not reported": 0 reads as "spent nothing".
	CreditsUsed *float64 `json:"credits_used,omitempty"`
	// MonthlyAllowance is the plan's credit allowance (credits.monthly_allowance).
	// It renews each billing period only when AllowanceBasis is
	// AllowanceBillingPeriod; on Free it is the one-time grant.
	MonthlyAllowance float64 `json:"monthly_allowance,omitempty"`
	// NextReset is when the allowance next refills; empty when nothing does.
	NextReset string `json:"next_reset,omitempty"`
	// AllowanceBasis is credits.allowance_basis. The API sends none for a
	// white-label sub-account, so for plan "sub_account" it is
	// AllowanceProviderAllocation. Empty when the API did not say (a build
	// predating the field): unknown, not renewing.
	AllowanceBasis AllowanceBasis `json:"allowance_basis,omitempty"`
	CreatedAt      string         `json:"created_at"`
	// UsageWithheld is true when the API withheld CreditsUsed because this
	// key is not scoped for usage (withheld.usage in the response).
	// CreditsUsed is nil then.
	UsageWithheld bool `json:"usage_withheld,omitempty"`
	// FreeGrant is "withheld" on the Free plan when another account had
	// already received this mailbox's one-time free credits
	// (credits.free_grant), so MonthlyAllowance was not given to this
	// account. Empty otherwise.
	FreeGrant string `json:"free_grant,omitempty"`
}

// UnmarshalJSON maps the nested account/credits payload onto the flat
// AccountInfo fields (with legacy flat-payload fallback).
func (a *AccountInfo) UnmarshalJSON(data []byte) error {
	var raw struct {
		Account *struct {
			UserID    string `json:"user_id"`
			Email     string `json:"email"`
			Name      string `json:"name"`
			Plan      string `json:"plan"`
			Status    string `json:"status"`
			CreatedAt string `json:"created_at"`
		} `json:"account"`
		Credits *struct {
			Balance float64 `json:"balance"`
			// Pointers distinguish "absent" from a legitimate zero: a main
			// account with used_this_month == 0 must NOT fall back to the
			// sub-account-only credits_used field.
			UsedThisMonth    *float64        `json:"used_this_month"`
			CreditsUsed      *float64        `json:"credits_used"`
			MonthlyAllowance float64         `json:"monthly_allowance"`
			NextReset        string          `json:"next_reset"`
			AllowanceBasis   string          `json:"allowance_basis"`
			FreeGrant        json.RawMessage `json:"free_grant"`
		} `json:"credits"`
		// Sections the API left out because the key is not scoped for them.
		Withheld *struct {
			Usage json.RawMessage `json:"usage"`
		} `json:"withheld"`
		// Legacy flat fallback fields
		UserID           string   `json:"user_id"`
		Email            string   `json:"email"`
		Plan             string   `json:"plan"`
		CreditsRemaining float64  `json:"credits_remaining"`
		CreditsUsed      *float64 `json:"credits_used"`
		CreatedAt        string   `json:"created_at"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if raw.Account != nil {
		a.UserID = raw.Account.UserID
		a.Email = raw.Account.Email
		a.Name = raw.Account.Name
		a.Plan = raw.Account.Plan
		a.Status = raw.Account.Status
		a.CreatedAt = raw.Account.CreatedAt
	} else {
		a.UserID = raw.UserID
		a.Email = raw.Email
		a.Plan = raw.Plan
		a.CreatedAt = raw.CreatedAt
	}
	if a.Plan == "" {
		a.Plan = "free"
	}

	if raw.Credits != nil {
		a.CreditsRemaining = raw.Credits.Balance
		// Sub-accounts report credits_used instead of used_this_month.
		// Presence (not zero-ness) decides which field applies: zero is a
		// legitimate value for a main account that has used nothing. No 0
		// fallback when neither is present: the API omits the figure for a
		// key that is not scoped for usage, and a 0 would make "spent
		// nothing" and "not allowed to see it" the same answer.
		switch {
		case raw.Credits.UsedThisMonth != nil:
			a.CreditsUsed = raw.Credits.UsedThisMonth
		case raw.Credits.CreditsUsed != nil:
			a.CreditsUsed = raw.Credits.CreditsUsed
		case raw.CreditsUsed != nil:
			a.CreditsUsed = raw.CreditsUsed
		}
		a.MonthlyAllowance = raw.Credits.MonthlyAllowance
		a.NextReset = raw.Credits.NextReset
		a.AllowanceBasis = AllowanceBasis(raw.Credits.AllowanceBasis)
		if grant := optionalString(raw.Credits.FreeGrant); grant != nil {
			a.FreeGrant = *grant
		}
	} else {
		a.CreditsRemaining = raw.CreditsRemaining
		a.CreditsUsed = raw.CreditsUsed
	}
	if a.CreditsUsed == nil && raw.Withheld != nil {
		withheld := optionalBool(raw.Withheld.Usage)
		a.UsageWithheld = withheld != nil && *withheld
	}
	// A sub-account's credits block carries only balance, credits_used and
	// allocated, so the API sends no basis for it. Its plan is the declared
	// literal "sub_account", and its allowance is its provider's allocation.
	if a.AllowanceBasis == "" && a.Plan == "sub_account" {
		a.AllowanceBasis = AllowanceProviderAllocation
	}

	return nil
}

// FindResult represents the result of an email finder request.
//
// Matches POST /v1/find's response fields exactly: first_name, last_name,
// email, confidence, pattern, verified, status, message?, credits_used,
// credits_remaining, idempotent_replay?.
type FindResult struct {
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
	Email      string `json:"email,omitempty"`
	Confidence int    `json:"confidence"`
	Pattern    string `json:"pattern,omitempty"`
	Verified   bool   `json:"verified"`
	Status     string `json:"status"`
	// CreditsUsed is what the search cost. float64 like every credit figure:
	// the price is whole today, but credit amounts are not in general.
	CreditsUsed float64 `json:"credits_used"`
	// The post-charge balance. A nil pointer means the API omitted it (a
	// keyed replay whose ledger snapshot could not be safely read omits it
	// rather than publish a stale figure), so nil means unknown, never zero.
	// Fractional whenever part of the account's spend was.
	CreditsRemaining *float64 `json:"credits_remaining,omitempty"`
	Message          string   `json:"message,omitempty"`

	// IdempotentReplay is true when this repeated a search that had already
	// been charged, and therefore charged nothing.
	//
	// POST /v1/find honours an Idempotency-Key (Find sends one on every call):
	// a repeat under the same key replays the stored result for the key's
	// 30-day receipt, and without one an identical search is still
	// de-duplicated against a fixed two-minute bucket. Either way, CreditsUsed
	// still reports what the SEARCH cost (5); it has always meant that, so
	// this is the only way to tell a second charge from a free repeat. Summing
	// CreditsUsed across responses without checking it over-counts by exactly
	// what the de-duplication saved.
	//
	// A nil pointer means the API said nothing either way (a build predating
	// the field, or a value this client could not read). It does not mean the
	// call was charged.
	IdempotentReplay *bool `json:"idempotent_replay,omitempty"`
}

// UnmarshalJSON reads a FindResult without failing on a wrong-typed replay
// marker.
//
// encoding/json refuses the WHOLE object when a field's type does not match,
// so `"idempotent_replay": "true"` made Find return `failed to parse response`
// and no result at all, discarding the address the caller had just paid 5
// credits for, in order to object to a hint about how to count them. Worse,
// the natural response to a parse error is a retry, which is a second search.
//
// Actual booleans only. A non-boolean leaves the pointer nil, which reads as
// "not stated" and never as "charged": here false is itself the claim that the
// call was charged, so a coercion would invert the signal rather than degrade
// it. The five SDKs without a typed decoder already behave this way.
func (r *FindResult) UnmarshalJSON(data []byte) error {
	// The alias drops this method, so the embedded value decodes normally.
	// The shallower fields shadow the embedded ones for `idempotent_replay`
	// and `credits_remaining`.
	type alias FindResult
	aux := struct {
		*alias
		IdempotentReplay json.RawMessage `json:"idempotent_replay"`
		CreditsRemaining json.RawMessage `json:"credits_remaining"`
	}{alias: (*alias)(r)}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Only a real boolean sets the marker (see optionalBool): null leaves it
	// nil rather than false, which would publish "you were charged" for a
	// marker the API never stated.
	r.IdempotentReplay = optionalBool(aux.IdempotentReplay)

	// Same discipline for the balance: a wrong-typed value would fail the
	// whole decode, so it is read from the raw message instead. Absent or
	// unreadable stays nil; only a real number (whole or fractional, never
	// truncated) is published.
	r.CreditsRemaining = optionalNumber(aux.CreditsRemaining)
	return nil
}

// Found reports whether the address is confirmed: true only when Email is
// set and Verified is true (a "valid" verdict). On a catch-all, risky or role
// result the API still returns its best guess as Email, with Verified false;
// that guess is not a find, however high its Confidence.
func (r *FindResult) Found() bool {
	return r.Email != "" && r.Verified
}

// DomainSearchEmail is a single discovered mailbox from GET /v1/domain/{domain}.
type DomainSearchEmail struct {
	Email         string `json:"email"`
	Status        string `json:"status"`
	QualityScore  int    `json:"quality_score"`
	IsRoleAccount bool   `json:"is_role_account"`
	IsCatchAll    bool   `json:"is_catch_all"`
	FromCache     bool   `json:"from_cache"`
}

// DomainSearchResult represents the result of a domain search
// (GET /v1/domain/{domain}).
//
// The first uncached call starts an async discovery job and returns
// Status == "processing" with an empty Emails list. Re-call DomainSearch
// to poll until Status is "completed" (IsProcessing()).
type DomainSearchResult struct {
	Domain     string              `json:"domain"`
	Emails     []DomainSearchEmail `json:"emails"`
	EmailCount int                 `json:"email_count"`
	// Status is "processing" while the async discovery job runs, "completed"
	// when done; empty on legacy cached rows (treat as completed).
	Status           string  `json:"status,omitempty"`
	ProgressPercent  float64 `json:"progress_percent,omitempty"`
	JobID            string  `json:"job_id,omitempty"`
	PatternsChecked  int     `json:"patterns_checked,omitempty"`
	CompletionReason string  `json:"completion_reason,omitempty"`
	CatchAllDomain   bool    `json:"catch_all_domain,omitempty"`
	FromCache        bool    `json:"from_cache"`
	CachedAt         string  `json:"cached_at,omitempty"`
	CreditsUsed      float64 `json:"credits_used"`
	// CreditsRefunded is set only on the poll, by the account that started
	// the search, that completes a partial search (CompletionReason
	// "time_limit_reached"): the credits given back for the candidates it
	// could not check. CreditsRemaining already includes them.
	CreditsRefunded  float64 `json:"credits_refunded,omitempty"`
	CreditsRemaining float64 `json:"credits_remaining"`
	Message          string  `json:"message,omitempty"`
}

// IsProcessing returns true while the async discovery job is still running;
// re-call DomainSearch to poll until it completes.
func (r *DomainSearchResult) IsProcessing() bool {
	return r.Status == "processing"
}

// Canonical webhook event names delivered to registered webhooks.
const (
	EventVerificationCompleted = "verification.completed"
	EventVerificationFailed    = "verification.failed"
	EventJobCompleted          = "job.completed"
	EventJobFailed             = "job.failed"
	EventCreditsLow            = "credits.low"
	EventCreditsExhausted      = "credits.exhausted"
	EventBlacklistDetected     = "blacklist.detected"
	EventDmarcFailure          = "dmarc.failure"
)

// WebhookJobSummary contains the per-status counts for a completed bulk job.
type WebhookJobSummary struct {
	Valid   int `json:"valid"`
	Invalid int `json:"invalid"`
	Risky   int `json:"risky"`
	Unknown int `json:"unknown"`
}

// VerificationCompletedData is the data payload of a verification.completed event.
type VerificationCompletedData struct {
	JobID        string `json:"job_id"`
	Email        string `json:"email,omitempty"`
	Status       string `json:"status,omitempty"`
	SubStatus    string `json:"sub_status,omitempty"`
	QualityScore int    `json:"quality_score,omitempty"`
	VerifiedAt   string `json:"verified_at,omitempty"`
	// CreditsUsed is what the verification cost: 1 fresh, 0.5 when a cached
	// result was served.
	CreditsUsed float64 `json:"credits_used,omitempty"`
}

// VerificationFailedData is the data payload of a verification.failed event.
type VerificationFailedData struct {
	JobID    string `json:"job_id"`
	Error    string `json:"error,omitempty"`
	FailedAt string `json:"failed_at,omitempty"`
}

// JobCompletedData is the data payload of a job.completed event (also
// synthesized from the legacy flat per-job callback body).
//
// TotalEmails and ProcessedEmails count the addresses that were checked.
// RequestedEmails is how many were submitted (and charged for); when some
// were never checked, Partial is true and the difference has no result and
// was refunded.
type JobCompletedData struct {
	JobID           string `json:"job_id"`
	Status          string `json:"status,omitempty"`
	TotalEmails     int    `json:"total_emails,omitempty"`
	ProcessedEmails int    `json:"processed_emails,omitempty"`
	// RequestedEmails is nil only on a payload that predates the field.
	RequestedEmails *int `json:"requested_emails,omitempty"`
	// Partial is true when some submitted addresses were never checked; nil
	// only on a payload that predates the field.
	Partial *bool `json:"partial,omitempty"`
	// CreditsRefunded is every credit returned for the job, including the
	// cached-result discount (the same figure as on the job), so it can be
	// fractional.
	CreditsRefunded *float64 `json:"credits_refunded,omitempty"`
	// CacheDiscountPending is true while the cached-result discount has not
	// been applied yet, so CreditsRefunded will still grow. The API sends it
	// only while true, so its absence decodes as false (settled). It is nil
	// when the payload carried something other than a boolean, null
	// included: whether the discount is settled is then unknown.
	CacheDiscountPending *bool              `json:"cache_discount_pending,omitempty"`
	Summary              *WebhookJobSummary `json:"summary,omitempty"`
	CreatedAt            string             `json:"created_at,omitempty"`
	CompletedAt          string             `json:"completed_at,omitempty"`
	DownloadURL          string             `json:"download_url,omitempty"`
}

// UnmarshalJSON applies cache_discount_pending's documented default (false
// when absent) without letting a null or a non-boolean pass as that default.
func (d *JobCompletedData) UnmarshalJSON(data []byte) error {
	type plain JobCompletedData
	aux := struct {
		*plain
		CacheDiscountPending json.RawMessage `json:"cache_discount_pending"`
	}{plain: (*plain)(d)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.CacheDiscountPending == nil {
		settled := false
		d.CacheDiscountPending = &settled
	} else {
		d.CacheDiscountPending = optionalBool(aux.CacheDiscountPending)
	}
	return nil
}

// JobFailedData is the data payload of a job.failed event.
type JobFailedData struct {
	JobID           string   `json:"job_id"`
	Status          string   `json:"status,omitempty"`
	TotalEmails     int      `json:"total_emails,omitempty"`
	ProcessedEmails int      `json:"processed_emails,omitempty"`
	RequestedEmails *int     `json:"requested_emails,omitempty"`
	CreditsRefunded *float64 `json:"credits_refunded,omitempty"`
	Error           string   `json:"error,omitempty"`
	FailedAt        string   `json:"failed_at,omitempty"`
}

// CreditsLowData is the data payload of a credits.low event.
//
// CreditsRemaining is the balance that crossed the threshold, and is
// fractional whenever part of the spend was.
//
// On an account with white-label sub-accounts, the event about a
// sub-account's balance goes to the parent's webhooks with AccountType
// "sub_account" and the sub-account's id, name and allocation. On an event
// about the account's own balance AccountType, SubAccountID and
// SubAccountName are empty and CreditsAllocated is nil.
type CreditsLowData struct {
	AccountType    string `json:"account_type,omitempty"`
	SubAccountID   string `json:"sub_account_id,omitempty"`
	SubAccountName string `json:"sub_account_name,omitempty"`
	// CreditsAllocated is the sub-account's allocation; its threshold is a
	// share of it.
	CreditsAllocated *float64 `json:"credits_allocated,omitempty"`
	CreditsRemaining float64  `json:"credits_remaining"`
	Threshold        float64  `json:"threshold,omitempty"`
	TriggeredAt      string   `json:"triggered_at,omitempty"`
}

// CreditsExhaustedData is the data payload of a credits.exhausted event. It
// carries the same sub-account fields as CreditsLowData when the balance is
// a sub-account's.
type CreditsExhaustedData struct {
	AccountType      string   `json:"account_type,omitempty"`
	SubAccountID     string   `json:"sub_account_id,omitempty"`
	SubAccountName   string   `json:"sub_account_name,omitempty"`
	CreditsAllocated *float64 `json:"credits_allocated,omitempty"`
	CreditsRemaining float64  `json:"credits_remaining"`
	TriggeredAt      string   `json:"triggered_at,omitempty"`
}

// BlacklistDetectedData is the data payload of a blacklist.detected event.
type BlacklistDetectedData struct {
	MonitorID   string                   `json:"monitor_id,omitempty"`
	Domain      string                   `json:"domain,omitempty"`
	Target      string                   `json:"target,omitempty"`
	Type        string                   `json:"type,omitempty"`
	Blacklists  []string                 `json:"blacklists,omitempty"`
	ListedOn    []map[string]interface{} `json:"listed_on,omitempty"`
	TotalListed int                      `json:"total_listed,omitempty"`
	// Summary holds severity counts (e.g. {critical, high, medium, low}).
	Summary    map[string]interface{} `json:"summary,omitempty"`
	DetectedAt string                 `json:"detected_at,omitempty"`
}

// DmarcComponentStatus is the SPF/DKIM/DMARC component status inside a
// dmarc.failure payload. Policy is only set on the DMARC component.
type DmarcComponentStatus struct {
	Status string  `json:"status,omitempty"`
	Score  float64 `json:"score,omitempty"`
	Policy string  `json:"policy,omitempty"`
}

// DmarcFailureData is the data payload of a dmarc.failure event.
type DmarcFailureData struct {
	MonitorID       string                `json:"monitor_id,omitempty"`
	Domain          string                `json:"domain,omitempty"`
	AlertType       string                `json:"alert_type,omitempty"`
	Issue           string                `json:"issue,omitempty"`
	ComplianceScore float64               `json:"compliance_score,omitempty"`
	Compliant       bool                  `json:"compliant,omitempty"`
	SPF             *DmarcComponentStatus `json:"spf,omitempty"`
	DKIM            *DmarcComponentStatus `json:"dkim,omitempty"`
	DMARC           *DmarcComponentStatus `json:"dmarc,omitempty"`
	Recommendations []interface{}         `json:"recommendations,omitempty"`
	DetectedAt      string                `json:"detected_at,omitempty"`
}

// WebhookEvent is the envelope delivered to registered webhooks
// (POST /v1/webhooks, Settings -> Webhooks):
//
//	{
//	  "event": "job.completed",
//	  "data": { "job_id": "...", "summary": { "valid": 80, ... }, ... },
//	  "webhook_id": "wh_...",
//	  "timestamp": "2026-01-01T00:00:00Z"
//	}
//
// The event-specific fields live under Data; decode them with the typed
// accessors (JobCompleted, VerificationCompleted, ...). Test deliveries set
// Test and may omit some data fields. The legacy flat per-job webhook_url
// callback body ({event, job_id, status, results:{...}, requested_emails,
// ...}) is normalized into the same envelope on unmarshal (with empty
// WebhookID/Timestamp). RawPayload keeps the body exactly as received.
type WebhookEvent struct {
	Event     string          `json:"event"`
	Data      json.RawMessage `json:"data,omitempty"`
	WebhookID string          `json:"webhook_id,omitempty"`
	Timestamp string          `json:"timestamp,omitempty"`
	Test      bool            `json:"test,omitempty"`
	// RawPayload is the complete JSON body as received.
	RawPayload json.RawMessage `json:"-"`
}

// UnmarshalJSON normalizes the legacy flat per-job callback body (`data`
// absent or null, top-level `job_id`) into the envelope.
func (e *WebhookEvent) UnmarshalJSON(data []byte) error {
	type Alias WebhookEvent
	aux := (*Alias)(e)
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	e.RawPayload = append(json.RawMessage(nil), data...)
	if len(e.Data) > 0 && string(e.Data) != "null" {
		return nil
	}

	// The presence of a top-level job_id KEY (even null) gates the legacy
	// fallback, matching the other SDKs.
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil
	}
	if _, hasJobID := keys["job_id"]; !hasJobID {
		// Not a legacy flat callback: leave Data empty.
		return nil
	}

	// Every field but event and results moves under Data as it is (a
	// failure's error and failed_at, requested_emails, partial,
	// credits_refunded, ...); results becomes the envelope's total_emails,
	// processed_emails and summary.
	synthesized := make(map[string]json.RawMessage, len(keys)+3)
	for key, value := range keys {
		if key == "event" || key == "data" || key == "results" {
			continue
		}
		synthesized[key] = value
	}
	var results map[string]json.RawMessage
	if json.Unmarshal(keys["results"], &results) == nil && results != nil {
		if total, ok := results["total"]; ok {
			synthesized["total_emails"] = total
		}
		if processed, ok := results["processed"]; ok {
			synthesized["processed_emails"] = processed
		}
		summary, err := json.Marshal(WebhookJobSummary{
			Valid:   summaryCount(results["valid"]),
			Invalid: summaryCount(results["invalid"]),
			Risky:   summaryCount(results["risky"]),
			Unknown: summaryCount(results["unknown"]),
		})
		if err != nil {
			return err
		}
		synthesized["summary"] = summary
	}
	raw, err := json.Marshal(synthesized)
	if err != nil {
		return err
	}
	e.Data = raw
	if e.Event == "" {
		e.Event = EventJobCompleted
	}
	// Legacy per-job callbacks carry no subscription metadata; force the
	// envelope-only fields empty even if stray keys were present, matching
	// the other SDKs' legacy normalization.
	e.WebhookID = ""
	e.Timestamp = ""
	e.Test = false
	return nil
}

// summaryCount reads one of a flat callback's results counts, 0 when it is
// absent or not a whole number.
func summaryCount(raw json.RawMessage) int {
	var n int
	if json.Unmarshal(raw, &n) != nil {
		return 0
	}
	return n
}

// decodeData decodes Data into v after checking the event name matches.
func (e *WebhookEvent) decodeData(expected string, v interface{}) error {
	if e.Event != expected {
		return fmt.Errorf("webhook event is %q, not %q", e.Event, expected)
	}
	if len(e.Data) == 0 {
		return fmt.Errorf("webhook payload has no data object")
	}
	return json.Unmarshal(e.Data, v)
}

// VerificationCompleted decodes Data for a verification.completed event.
func (e *WebhookEvent) VerificationCompleted() (*VerificationCompletedData, error) {
	var d VerificationCompletedData
	if err := e.decodeData(EventVerificationCompleted, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// VerificationFailed decodes Data for a verification.failed event.
func (e *WebhookEvent) VerificationFailed() (*VerificationFailedData, error) {
	var d VerificationFailedData
	if err := e.decodeData(EventVerificationFailed, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// JobCompleted decodes Data for a job.completed event.
func (e *WebhookEvent) JobCompleted() (*JobCompletedData, error) {
	var d JobCompletedData
	if err := e.decodeData(EventJobCompleted, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// JobFailed decodes Data for a job.failed event.
func (e *WebhookEvent) JobFailed() (*JobFailedData, error) {
	var d JobFailedData
	if err := e.decodeData(EventJobFailed, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// CreditsLow decodes Data for a credits.low event.
func (e *WebhookEvent) CreditsLow() (*CreditsLowData, error) {
	var d CreditsLowData
	if err := e.decodeData(EventCreditsLow, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// CreditsExhausted decodes Data for a credits.exhausted event.
func (e *WebhookEvent) CreditsExhausted() (*CreditsExhaustedData, error) {
	var d CreditsExhaustedData
	if err := e.decodeData(EventCreditsExhausted, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// BlacklistDetected decodes Data for a blacklist.detected event.
func (e *WebhookEvent) BlacklistDetected() (*BlacklistDetectedData, error) {
	var d BlacklistDetectedData
	if err := e.decodeData(EventBlacklistDetected, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// DmarcFailure decodes Data for a dmarc.failure event.
func (e *WebhookEvent) DmarcFailure() (*DmarcFailureData, error) {
	var d DmarcFailureData
	if err := e.decodeData(EventDmarcFailure, &d); err != nil {
		return nil, err
	}
	return &d, nil
}
