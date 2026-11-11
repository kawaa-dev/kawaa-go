# Kawaa Go SDK

Go client for the [Kawaa](https://kawaa.com) email verification API.

## Features

- Verify single emails or batch lists
- Domain search (find all emails at a domain)
- Email finder (find email by name + company; Starter plan and up)
- Automatic retries with exponential backoff for rate limits (every method), for connection failures before a request is sent (DNS lookup or dial failed, every method), and for requests that are safe to repeat: GETs that charge nothing, and `Verify`/`VerifyBatch`/`Find`, which send one `Idempotency-Key` per call and reuse it after a timeout, dropped response or 5xx so a retry is not charged twice (set `VerifyOptions.IdempotencyKey` / `FindOptions.IdempotencyKey` to supply your own). `DomainSearch` is a GET that charges 10 credits and takes no key, so it is never re-sent after a 5xx or a timeout. Nothing is retried when the API says a retry may charge again (`APIError.RetryMayChargeAgain`) or that the request is not retryable (`retryable: false`). A `409` with `retryable: true` on a keyed call means a copy under the same key is still running: it is retried with the same key. When the API names a wait (`Retry-After`), it is honoured up to `kawaa.MaxRetryAfter` (60 seconds). `WithMaxRetries(n)` allows `n` retries after the first attempt, so `WithMaxRetries(0)` sends each request once. When retries run out, the error carries the key (see [Error Handling](#error-handling)) so you can repeat the call with it
- Context support for cancellation and timeouts
- Webhook signature verification
- Comprehensive error handling

## Requirements

- Go 1.21 or higher

## Installation

```bash
go get kawaa.com/go/kawaa
```

The import path is `kawaa.com/go/kawaa` and the package name is `kawaa`.

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    "kawaa.com/go/kawaa"
)

func main() {
    // Create client with your API key
    client := kawaa.NewClient("your-api-key")
    ctx := context.Background()

    // Verify a single email
    result, err := client.Verify(ctx, "john@example.com")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Status: %s\n", result.Status)  // valid, invalid, risky, unknown, spam_trap, disposable, role, catch_all (or pending on sync timeout)
    fmt.Printf("Score: %d\n", result.Score)    // 0-100 quality score

    if result.IsValid() {
        fmt.Println("Email is valid!")
    }

    if result.Flags.Disposable {
        fmt.Println("Warning: disposable email")
    }
}
```

## Single Email Verification

```go
client := kawaa.NewClient("your-api-key")
ctx := context.Background()

// Basic verification
result, err := client.Verify(ctx, "user@example.com")
if err != nil {
    log.Fatal(err)
}

// Access results
fmt.Printf("Email: %s\n", result.Email)
fmt.Printf("Status: %s\n", result.Status)
fmt.Printf("Score: %d\n", result.Score)
fmt.Printf("Disposable: %t\n", result.Flags.Disposable)
fmt.Printf("Role: %t\n", result.Flags.Role)
fmt.Printf("Free Provider: %t\n", result.Flags.FreeProvider)
fmt.Printf("Catch-all: %t\n", result.Flags.CatchAll)                  // true when the domain was seen to accept any address
fmt.Printf("Catch-all measured: %t\n", result.Flags.CatchAllMeasured) // false when nothing measured it

// Kawaa measures catch-all only after the mail server accepts the mailbox.
// When nothing measured it (a disposable address, no usable mail server, a
// server that refused the mailbox or never answered), CatchAll is false but
// means "unknown", so test both fields before treating an address as not
// catch-all.
if result.Flags.CatchAllMeasured && !result.Flags.CatchAll {
    fmt.Println("Checked: the domain does not accept every address")
}

// AI-suggested correction (if typo detected)
if result.Suggestion != "" {
    fmt.Printf("Did you mean: %s\n", result.Suggestion)
}

// Customize verification options (the real API options). A field you leave
// out is not sent, so the API's default applies: deep verification and AI on.
result, err = client.Verify(ctx, "user@example.com", kawaa.VerifyOptions{
    DeepVerify: kawaa.Bool(false), // Turn off deep (SMTP-level) verification
    IncludeAI:  kawaa.Bool(false), // Turn off AI typo detection / catch-all confidence
    Enrich:     false,             // Opt-in data enrichment (name, gender, country); Business plan and up
    TimeoutMs:  24000,             // How long Verify waits for a synchronous result (ms); Verify only
    SkipCache:  false,             // Bypass the verification cache
})

// What it cost: 1 for a fresh check, 0.5 for a cached one. Credit figures
// are float64 throughout the SDK, so print them with %g, not %d.
if result.CreditsUsed != nil {
    fmt.Printf("Credits used: %g\n", *result.CreditsUsed)
}
```

`Enrich` needs the Business plan or higher. On a lower plan the API refuses the whole request with `403 PLAN_UPGRADE_REQUIRED` and charges nothing, so leave it out there.

A `pending` result means the synchronous window elapsed before the worker
finished: poll `GetJobStatus(ctx, result.JobID, true)` for the verdict.

Every `Verify` call carries an `Idempotency-Key`, and a retry after a timeout
or 5xx reuses it. If an earlier attempt had already been accepted, the API
answers the retry with a replay that says only `pending` and the original job's
id; `Verify` reads that job back (up to three reads, two seconds apart) and
returns its finished result with `IdempotentReplay` set, so a completed
verification is never reported as pending. `CreditsUsed` then reports what the
original verification cost (charged once). `CreditsUsed` is nil when the job's
cache discount was still being applied after the short poll; read the job by
`JobID` (its `CreditsCharged` less `CreditsRefunded`) for the final charge. It
is nil too when the job read carries no charge. If the job is still running
after the short poll, or cannot be read (a key without `verification:read`), you
get the replay itself: `pending`, `CreditsUsed` nil, and the `JobID` to poll.
The API answers a replay with `credits_used` 0, which is what the repeat cost,
not what the verification cost, so it is never reported as the cost.

## Domain Search

Find all email addresses at a company domain:

```go
result, err := client.DomainSearch(ctx, "stripe.com")
if err != nil {
    log.Fatal(err)
}

// The first uncached call returns Status == "processing" with no emails yet;
// re-call DomainSearch until result.IsProcessing() is false.
fmt.Printf("Found %d emails at %s\n", result.EmailCount, result.Domain)
fmt.Printf("Patterns checked: %d\n", result.PatternsChecked)

for _, email := range result.Emails {
    fmt.Printf("  %s: %s\n", email.Email, email.Status)
}
```

## Email Finder

Find someone's email by name and company. The email finder needs the Starter plan or higher. On the Free plan the API refuses it with `403 PLAN_UPGRADE_REQUIRED` before anything is charged.

```go
result, err := client.Find(ctx, "John", "Smith", "company.com")
if err != nil {
    log.Fatal(err)
}

if result.Found() {
    fmt.Printf("Found: %s\n", result.Email)
    fmt.Printf("Confidence: %d%%\n", result.Confidence)
    fmt.Printf("Pattern: %s\n", result.Pattern)  // e.g., "first.last"
} else if result.Email != "" {
    fmt.Printf("Best guess, not confirmed: %s (%s)\n", result.Email, result.Status)
} else {
    fmt.Println("Email not found")
}
```

`Found()` is true only for a confirmed address (`Verified`, a `valid`
verdict). On a catch-all, risky or role result the API still returns its
best guess in `Email`, with `Verified` false; treat that as a guess, not as
this person's address.

## Batch Verification

For verifying many emails at once:

```go
emails := []string{
    "john@example.com",
    "jane@example.com",
    "support@example.com",
}

// Start batch job
job, err := client.VerifyBatch(ctx, emails)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Job ID: %s\n", job.JobID)
fmt.Printf("Duplicates removed: %d\n", job.DuplicatesRemoved)
if job.CreditsUsed != nil { // nil on a replay of a batch already accepted
    fmt.Printf("Credits used: %g\n", *job.CreditsUsed) // float64: cached checks cost 0.5
}

// Wait for completion
result, err := client.WaitForJob(ctx, job.JobID, 2*time.Second, 5*time.Minute)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Valid: %d\n", result.ValidCount)
fmt.Printf("Invalid: %d\n", result.InvalidCount)
fmt.Printf("Risky: %d\n", result.RiskyCount)

// result.Results is the first page only (up to 100 results). For every
// result, download them (see Download Results below).
all, err := client.DownloadResults(ctx, job.JobID)
if err != nil {
    log.Fatal(err)
}
for _, r := range all.Results {
    fmt.Printf("%s: %s (score: %d)\n", r.Email, r.Status, r.Score)
}
```

### One-liner with wait

```go
// Start job and wait for completion in one call. Like WaitForJob, it returns
// the first page of results (up to 100); call DownloadResults for all of them.
result, err := client.VerifyBatchAndWait(ctx, emails, 2*time.Second, 10*time.Minute)
```

### Using webhooks

```go
// Get notified when job completes. Verification options you leave out keep
// the API's defaults (deep verification and AI on).
job, err := client.VerifyBatch(ctx, emails, kawaa.BatchOptions{
    WebhookURL:    "https://hooks.example.com/kawaa",
    WebhookSecret: "your-secret",  // Optional, for signature verification
})
```

## Download Results

```go
// Download as JSON
results, err := client.DownloadResults(ctx, jobID)
if err != nil {
    log.Fatal(err)
}

for _, r := range results.Results {
    fmt.Printf("%s: %s\n", r.Email, r.Status)
}

// Download as CSV
csvData, err := client.DownloadResultsCSV(ctx, jobID)
if err != nil {
    log.Fatal(err)
}
fmt.Println(csvData)

// For large result sets, you'll get a presigned URL
if results.DownloadURL != "" {
    fmt.Printf("Download from: %s\n", results.DownloadURL)
}
```

Every JSON response and presigned-URL export carries a completeness verdict.
The SDK returns those exports only when the API reports `complete: true`. A
measured-short or unverifiable export returns `*kawaa.IncompleteExportError`
with `Complete`, `ExpectedRows`, and `RowsMissing`. Retry after a few seconds
only when `err.Retryable()` is true; a nil `Complete` is not a successful
verdict. A small inline CSV is raw CSV and carries no verdict; the API refuses
a measured-short inline CSV, but use JSON when you require a positive
completeness proof.
If the API refuses a measured-short inline CSV before it can return an
envelope, the same typed error has `Complete` pointing to false,
`StatusCode == 409`, and nil row counts; retry it in the same way.

## Webhook Handling

Registered webhooks (`POST /v1/webhooks`, Settings → Webhooks) deliver an
**envelope**: the event-specific fields are nested under `data`:

```json
{
  "event": "job.completed",
  "data": {
    "job_id": "job_abc123",
    "summary": { "valid": 800, "invalid": 150, "risky": 40, "unknown": 10 },
    "download_url": "https://api.kawaa.com/v1/jobs/job_abc123/download"
  },
  "webhook_id": "wh_abc123",
  "timestamp": "2026-01-01T00:30:01Z"
}
```

Supported events: `verification.completed`, `verification.failed`,
`job.completed`, `job.failed`, `credits.low`, `credits.exhausted`,
`blacklist.detected`, `dmarc.failure` (constants `kawaa.EventJobCompleted`,
etc.). `WebhookEvent` carries the raw `Data` (`json.RawMessage`) and the
whole body as received (`RawPayload`), plus typed accessor methods
(`JobCompleted()`, `VerificationCompleted()`, ...) that decode it when
`Event` matches, else return an error. The legacy per-job `WebhookURL`
callback (flat body) is automatically normalized into the same envelope.

The helpers check the `X-Kawaa-Signature-V2` header by default. `HTTPHandler`
and `ParseRequest` read it from the request; `Parse` and `ParseWebhook` take
its value. The header's `t` must be within 300 seconds of your server clock,
so a captured delivery cannot be replayed later (see
[Replay protection](#replay-protection-x-kawaa-signature-v2)). To change the
window, pass `kawaa.WithWebhookTolerance(10*time.Minute)` to
`NewWebhookHandler` or `ParseWebhook`; a negative tolerance panics in
`NewWebhookHandler` and is an error from `ParseWebhook`.

A request signed only with the legacy `X-Kawaa-Signature` header is refused
(401) unless you pass `kawaa.WithLegacyWebhookSignature()`. That header signs
no time, so a request accepted through it can be a replay of any delivery
ever captured: turn it on only for a sender that cannot send
`X-Kawaa-Signature-V2`. Every Kawaa delivery sends both headers, and a
request that carries `X-Kawaa-Signature-V2` is always checked against it,
with or without the opt-in.

Verification fails closed. `NewWebhookHandler` panics when the secret is
empty or only whitespace, so an unset `KAWAA_WEBHOOK_SECRET` stops the server
at startup instead of accepting forged requests. `Parse`, `ParseRequest`,
`HTTPHandler` and `ParseWebhook` always check the signature: a missing
signature header or an empty secret is an error (401 from `HTTPHandler`),
never a reason to skip the check. The low-level verifiers return false for
an empty secret.

A per-job `WebhookURL` callback created without a `WebhookSecret` is sent
unsigned. To read one, call `kawaa.ParseWebhookUnverified(body)`, and
remember that anyone who knows the URL can send a body that parses. Prefer
passing a `WebhookSecret` with the batch.

```go
import "kawaa.com/go/kawaa"

// Create webhook handler (panics if the secret is empty). It checks the
// X-Kawaa-Signature-V2 header and its 300-second window.
handler := kawaa.NewWebhookHandler(os.Getenv("KAWAA_WEBHOOK_SECRET"))

// Use as HTTP handler
http.HandleFunc("/webhook", handler.HTTPHandler(func(event *kawaa.WebhookEvent) error {
    switch event.Event {
    case kawaa.EventJobCompleted:
        data, err := event.JobCompleted()
        if err != nil {
            return err
        }
        fmt.Printf("Job %s completed!\n", data.JobID)
        if data.Summary != nil {
            fmt.Printf("Valid: %d, Invalid: %d\n", data.Summary.Valid, data.Summary.Invalid)
        }
        fmt.Printf("Download: %s\n", data.DownloadURL)
    case kawaa.EventCreditsLow:
        data, err := event.CreditsLow()
        if err != nil {
            return err
        }
        fmt.Printf("Credits low: %g remaining\n", data.CreditsRemaining)
    default:
        fmt.Printf("Unhandled event %s: %s\n", event.Event, string(event.Data))
    }
    return nil
}))

http.ListenAndServe(":8080", nil)
```

### Manual webhook handling

```go
var handler = kawaa.NewWebhookHandler(os.Getenv("KAWAA_WEBHOOK_SECRET"))

func webhookHandler(w http.ResponseWriter, r *http.Request) {
    // Checks the X-Kawaa-Signature-V2 header against the body and its window.
    event, err := handler.ParseRequest(r)
    if err != nil {
        // Missing, wrong or stale signature, or a body that is not JSON: refuse it.
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }

    // Process event
    if data, err := event.JobCompleted(); err == nil && data.Summary != nil {
        log.Printf("Job %s completed with %d valid emails\n", data.JobID, data.Summary.Valid)
    }

    w.WriteHeader(http.StatusOK)
}
```

### Parse a body you already read

```go
// Pass the X-Kawaa-Signature-V2 header value, not X-Kawaa-Signature.
event, err := kawaa.ParseWebhook(body, r.Header.Get("X-Kawaa-Signature-V2"), secret)

// With a wider window:
event, err = kawaa.ParseWebhook(body, r.Header.Get("X-Kawaa-Signature-V2"), secret,
    kawaa.WithWebhookTolerance(10*time.Minute))
```

### Verify signature manually

```go
// False when the header is missing or malformed, the signature is wrong,
// t is more than 300 s from now, or the secret is empty.
isValid := kawaa.VerifyWebhookSignatureV2(body, r.Header.Get("X-Kawaa-Signature-V2"), secret)
```

### Replay protection (X-Kawaa-Signature-V2)

Signed deliveries also carry an `X-Kawaa-Signature-V2` header,
`t=<unix seconds>,v1=<hex HMAC-SHA256>`, keyed with the same secret. The
signature covers the timestamp as well as the body, so a captured delivery
cannot be resent later with a new date. `VerifyWebhookSignatureV2` returns
true only when the signature matches and `t` is within 300 seconds
(`kawaa.DefaultWebhookTolerance`) of your server clock, so a delivery replayed
after that window is rejected (one replayed inside it still verifies, so keep
your handler idempotent). Every attempt (automatic retry, a retry from the delivery
log, a test delivery) is signed again with a fresh `t`, so a legitimate retry
still verifies. Keep the server clock in sync (NTP), and pass the raw request
body exactly as received, never re-encoded JSON.

```go
var secret = os.Getenv("KAWAA_WEBHOOK_SECRET")

func webhookHandler(w http.ResponseWriter, r *http.Request) {
    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "unreadable body", http.StatusBadRequest)
        return
    }
    // False when the header is missing or malformed, the signature is wrong,
    // t is more than 300 s from now, or the secret is empty.
    if !kawaa.VerifyWebhookSignatureV2(body, r.Header.Get("X-Kawaa-Signature-V2"), secret) {
        http.Error(w, "invalid or stale signature", http.StatusUnauthorized)
        return
    }
    // The signature is already checked, so parse the same bytes.
    event, err := kawaa.ParseWebhookUnverified(body)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    log.Printf("Received %s", event.Event)
    w.WriteHeader(http.StatusOK)
}
```

`handler.VerifySignatureV2(body, header)` does the same with a
`WebhookHandler`'s secret and window. For a different window use
`kawaa.VerifyWebhookSignatureV2WithTolerance(body, header, secret, 10*time.Minute)`
(truncated to whole seconds; a negative tolerance returns false). A header may
carry more than one `v1` entry; it verifies when any of them matches.

`Parse`, `ParseRequest`, `HTTPHandler` and `ParseWebhook` check this header
and window by default, as described above. The legacy `X-Kawaa-Signature`
header does not cover a timestamp, so it does not protect against a replayed
delivery: those helpers accept it only with `kawaa.WithLegacyWebhookSignature()`,
and only when the request has no `X-Kawaa-Signature-V2` header.
`VerifyWebhookSignature` still checks it on its own; prefer
`VerifyWebhookSignatureV2`. A per-job callback created without a
`WebhookSecret` carries neither header.

## Account Information

```go
account, err := client.GetAccount(ctx)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Credits remaining: %g\n", account.CreditsRemaining) // e.g. 260.25
fmt.Printf("Plan: %s\n", account.Plan)

if account.AllowanceBasis == kawaa.AllowanceBillingPeriod && account.NextReset != "" {
    fmt.Printf("Used %g of %g this billing period\n", account.CreditsUsed, account.MonthlyAllowance)
} else {
    fmt.Printf("Used %g in total\n", account.CreditsUsed) // nothing resets this on a schedule
}
```

`AllowanceBasis` says whether the allowance renews. `AllowanceBillingPeriod`
means `CreditsUsed` is spend in the current billing period and `NextReset`
says when it refills. `AllowanceOneTimeGrant` (the Free plan's credits,
granted once), `AllowanceNoBillingPeriod` (a paid plan with no billing period
on file) and `AllowanceProviderAllocation` (a white-label sub-account) mean
nothing resets it on a schedule, so `CreditsUsed` is cumulative and
`MonthlyAllowance` is not a monthly figure. The API sends the field for
ordinary accounts; for a sub-account it sends none, so the SDK supplies
`AllowanceProviderAllocation` from `Plan == "sub_account"`. An empty value
means the API did not say: treat it as unknown, not as renewing. Take `AllowanceBillingPeriod` as renewing only when `NextReset` is set too: an API build from
before 2026-09-30 reported a paid plan with no billing period on file as
`AllowanceBillingPeriod` with no `NextReset`.

## Error Handling

An error the API returned is an `*kawaa.APIError`; a timeout, dropped
connection or ended context is an `*kawaa.RequestError` wrapping the cause. Use
`errors.As` to reach either (a type assertion on `*kawaa.APIError` also works,
because it is returned as is).

```go
import (
    "errors"

    "kawaa.com/go/kawaa"
)

client := kawaa.NewClient("your-api-key")

result, err := client.Verify(ctx, "user@example.com")
if err != nil {
    var apiErr *kawaa.APIError
    if errors.As(err, &apiErr) {
        switch {
        case apiErr.IsAuthenticationError():
            log.Fatal("Invalid API key")
        case apiErr.IsRateLimitError():
            log.Printf("Rate limited. Retry after %d seconds\n", apiErr.RetryAfter)
        case apiErr.IsInsufficientCreditsError():
            // The message carries the amounts, e.g.
            // "Insufficient credits. Required: 3, Available: 2.5".
            log.Printf("Not enough credits: %s\n", apiErr.Message)
        case apiErr.IsValidationError():
            log.Printf("Invalid request: %s\n", apiErr.Message)
        case apiErr.IsNotFoundError():
            log.Fatal("Resource not found")
        case apiErr.IsServerError():
            log.Fatal("Server error, try again later")
        default:
            log.Fatalf("API error: %s\n", apiErr.Message)
        }
    } else {
        log.Fatalf("Error: %v\n", err)
    }
}
```

`APIError` also carries the API's retry guidance:

| Field | Type | Meaning |
|-------|------|---------|
| `Code`, `RequestID` | string | The stable error code, and the id to quote to support |
| `Retryable` | *bool | Whether the same request can succeed after a wait. Nil when the API did not say |
| `RetryAfter` | int | Seconds the API asked you to wait (0 when it named none). Automatic retries wait at most `kawaa.MaxRetryAfter` |
| `RetryRequiresSameIdempotencyKey` | bool | Repeat this call only with the same key (`IdempotencyKey`); a new key pays again |
| `RetryMayChargeAgain` | bool | The call charges, had no key to replay, and may already have been charged. Check the balance before repeating it |
| `IdempotencyKey` | string | The key `Verify`, `VerifyBatch` or `Find` sent on every attempt ("" for other calls) |
| `Attempts` | int | How many requests the call sent before giving up |

### Repeating a charged call after the client gave up

`Verify`, `VerifyBatch` and `Find` send one `Idempotency-Key` on every attempt.
When the client stops retrying (retries ran out on a 5xx, a timeout or an
in-flight `409`), the error carries that key, whatever its type. Repeat the call
with it and the API replays the attempt that was charged instead of charging
again:

```go
result, err := client.Find(ctx, "Ada", "Lovelace", "example.org")
if err != nil {
    if key := kawaa.IdempotencyKeyOf(err); key != "" {
        // The same key, so the attempt that was charged is replayed, not bought again.
        result, err = client.Find(ctx, "Ada", "Lovelace", "example.org", kawaa.FindOptions{IdempotencyKey: key})
    }
}
```

## Configuration

```go
client := kawaa.NewClient("your-api-key",
    kawaa.WithBaseURL("https://api.kawaa.com"),  // Custom API URL
    kawaa.WithTimeout(30 * time.Second),          // Request timeout
    kawaa.WithMaxRetries(3),                      // Retries after the first attempt (0 = send once)
    kawaa.WithHTTPClient(&http.Client{...}),      // Custom HTTP client
)
```

The options can come in any order. `WithTimeout` applies to a client given
with `WithHTTPClient` too, before or after it, and never changes the
`*http.Client` you pass: the SDK uses a copy with that timeout.

API requests never follow a redirect, whatever client you pass. Each one
carries your API key in `X-Api-Key`, and Go's `net/http` keeps that header when
it follows a redirect to another host, so following one would send the key to
wherever it points. The Kawaa API never redirects: a `3xx` answer is returned
as an `*APIError` with that status, which names the redirect's origin and is
not retried. Check the base URL when you see one (an `http://` address, for
example). The copy the SDK makes of your client is where this is set, so your
own `CheckRedirect` is not changed.

## Context Support

All methods accept a context for cancellation and timeouts:

```go
// With timeout
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

result, err := client.Verify(ctx, "user@example.com")
```

## Types Reference

### VerificationResult

| Field | Type | Description |
|-------|------|-------------|
| `Email` | string | The verified email |
| `Status` | VerificationStatus | valid, invalid, risky, unknown, spam_trap, disposable, role, catch_all, pending |
| `Score` | int | Quality score 0-100 |
| `Flags` | VerificationFlags | Email characteristics |
| `Suggestion` | string | AI-suggested correction |
| `Verification` | *VerificationDetails | Technical details |
| `JobID` | string | Job to poll when `Status` is pending |
| `CreditsUsed` | *float64 | What the verification cost (1 fresh, 0.5 cached). Nil when the response carried no figure |
| `CreditsRemaining` | *float64 | Balance after the charge. Nil means the API omitted it, not zero |
| `CreditsHeld` | *float64 | Credit held while `Status` is pending |
| `IdempotentReplay` | *bool | True when this answered a repeat of a request already accepted under the same key, and charged nothing more. `CreditsUsed` then reports what the original verification cost, read back from its job, or nil if the job's cache discount was still being applied |

### VerificationFlags

| Field | Type | Description |
|-------|------|-------------|
| `Disposable` | bool | Temporary email service |
| `Role` | bool | Role account (info@, support@) |
| `FreeProvider` | bool | Free email provider |
| `CatchAll` | bool | `true` when the domain was seen to accept mail for any address (or the status is `catch_all`). `false` also when nothing measured it: read `CatchAllMeasured` |
| `CatchAllMeasured` | bool | Whether catch-all was measured. `false` means `CatchAll` is unknown, not "not catch-all": no probe ran (a disposable address, no usable mail server, a server that refused the mailbox or never answered). Derived when the result is decoded; `DownloadRow` has the same pair |

### JobStatusResult

| Field | Type | Description |
|-------|------|-------------|
| `JobID` | string | Unique job identifier |
| `Status` | JobStatus | pending, processing, completed, failed, cancelled, enqueue_unknown (accepted, but some queue sends had an unknown outcome; keep polling) |
| `TotalEmails` | int | Total emails in job |
| `ProcessedEmails` | int | Emails processed so far |
| `ValidCount` | int | Valid email count |
| `InvalidCount` | int | Invalid email count |
| `RiskyCount` | int | Risky email count |
| `ProgressPercent` | float64 | Completion percentage |
| `Results` | []VerificationResult | The first page of results (up to 100). `HasMore` is true when there are more; `DownloadResults` returns them all |
| `CreditsCharged` | *float64 | Charged (or held) at acceptance |
| `CreditsRefunded` | *float64 | Returned since; net cost is `CreditsCharged - CreditsRefunded` |

### DomainSearchResult

| Field | Type | Description |
|-------|------|-------------|
| `Domain` | string | Searched domain |
| `EmailCount` | int | Number of emails found |
| `Emails` | []DomainSearchEmail | Discovered mailboxes (Email, Status, QualityScore, IsRoleAccount, IsCatchAll, FromCache) |
| `Status` | string | "processing" while the async discovery job runs (re-poll), "completed" when done |
| `PatternsChecked` | int | Number of patterns tested |
| `CreditsUsed` | float64 | Credits consumed |
| `CreditsRemaining` | float64 | Balance after the charge |
| `FromCache` | bool | Whether result was served from cache |

### FindResult

| Field | Type | Description |
|-------|------|-------------|
| `Email` | string | Found email address |
| `Confidence` | int | Confidence score 0-100 |
| `Pattern` | string | Email pattern used |
| `Verified` | bool | Whether email was verified |
| `CreditsUsed` | float64 | What the SEARCH cost (5). Not what this call charged: see `IdempotentReplay` |
| `CreditsRemaining` | *float64 | Balance after the charge (fractional when part of the spend was). Nil means the API omitted it, not zero |
| `IdempotentReplay` | *bool | True when this repeated an identical search already charged for, so this call cost nothing. Nil means the API said nothing this client could read (an older build, or a value that was not a boolean), and NOT that it charged. A wrong-typed marker leaves the rest of the result intact rather than failing the call |

## Running Tests

```bash
go test -v ./...
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- Documentation: https://kawaa.com/docs
- Email: support@kawaa.com
- Support: https://kawaa.com/support
