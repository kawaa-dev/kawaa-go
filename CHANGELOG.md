# Changelog

All notable changes to this SDK are documented in this file. It was started at 0.2.0 and does not
yet list every change made since 0.1.1.

## [Unreleased]

## [0.3.4] - 2026-11-18

### Added

- `DownloadRow.AbuseEmail`, `DownloadRow.Complainer` and `DownloadRow.BotGenerated`: the download
  gained these risk flags as its last three columns, after `email_unicode`. Each is a `*bool`,
  nil when the row does not state it (a result stored before the column existed has none), so an
  unstated flag never reads as a confident `false`. A value that is not a boolean reads as nil
  and does not fail the decode. There is no honeypot column. `DownloadResultsCSV` returns the
  new columns as sent.
- The reason `ip_address_mx` (a `risky` result: the mailbox was accepted at an MX record that
  names an IP address) reaches `SubStatus` as sent. `SubStatus` is an open string, so a reason
  added later passes through the same way.

## [0.3.3] - 2026-11-18

### Added

- `VerificationResult.EmailUnicode` and `DownloadRow.EmailUnicode`: a job result row
  (`GetJobStatus` with results, `WaitForJob`) and a download row (`DownloadResults`) now carry
  the API's `email_unicode`, the address with an internationalized domain written back in
  Unicode (`info@müller.de` where `Email` is `info@xn--mller-kva.de`), the same as `Email` for
  every other address. The API checks and returns the ASCII form, so this is the field to match
  a row to your own list by. Before, the client dropped it. The API sends it on every row it
  serves, including rows of older jobs. A value that is not a string reads as empty and does not
  fail the decode.

## [0.3.2] - 2026-11-17

### Changed

- A call the API answers with a delay longer than `MaxRetryAfter` (60 seconds) in `Retry-After`
  or the body's `retry_after_seconds` now returns its `*APIError` at once, with that delay in
  `RetryAfter`. Up to v0.3.1 the client waited 60 seconds and tried again, up to
  `WithMaxRetries` times, so a refusal that lasts an hour (the API edge answers a blocked address
  with `Retry-After: 3900`) held each call for about three minutes before returning the same
  error. A delay of 60 seconds or less is waited and retried as before.

## [0.3.1] - 2026-11-16

### Fixed

- README samples now run as copied or say what to replace. The client options sample did not
  compile (`&http.Client{...}`); it now passes `&http.Client{Timeout: 60 * time.Second}`. The
  batch sample says `CreditsUsed` is the up-front charge of 1 per address (a cached address is
  refunded to 0.5 when the job completes), the webhook sample names the endpoint you must
  supply, and the `Find` sample says `example.org` is refused. The only code change is
  `SDKVersion`, which the User-Agent sends.

## [0.3.0] - 2026-11-16

### Breaking changes

- `AccountInfo.CreditsUsed` is now a `*float64`, nil when the API did not send the figure. The
  API withholds usage from a key without the `analytics:read` scope, and 0.2.0 reported that as
  `CreditsUsed: 0`, which reads as "spent nothing". Check for nil before reading it;
  `AccountInfo.UsageWithheld` is true when the API said it withheld the figure.

### Added

- `AccountInfo.UsageWithheld` (from `withheld.usage`) and `AccountInfo.FreeGrant`
  (`credits.free_grant`, `"withheld"` when another account had already received this mailbox's
  one-time Free credits).
- `VerificationResult.Enrichment`: the name, gender and country hints the API attaches when
  `VerifyOptions.Enrich` is set on a plan with data enrichment. 0.2.0 sent the option and
  dropped the answer.
- `VerificationResult.FromCache`, `CacheAgeSeconds` and `VerifiedAt`, so a cached verdict says
  how old it is.
- `VerificationFlags.AbuseEmail`, `Complainer`, `Honeypot` and `BotGenerated`. The API lowers
  the score for each without changing the status, so these say why a score is low.
- `BatchJobResult.InvalidEmailsSkipped` (malformed addresses refused and not charged) and
  `BatchJobResult.EnqueueUnknown` (queue sends that could not be confirmed; nil means not
  reported, so read `Status` for whether any are unconfirmed).
- `JobStatusResult.ErrorMessage`, the API's reason a job ended as it did. `WaitForJob` includes
  it in the error for a failed job.

### Fixed

- A JSON `null` in a field read as an optional integer (such as `verification.smtp_code`) now
  reads as nil, not as 0.

## [0.2.0] - 2026-11-11

### Changed

- The module path is now `kawaa.com/go/kawaa`, on Kawaa's own domain, so the import path
  stays the same wherever the source is hosted. Code that imports the SDK from a source checkout
  needs the new path; the package name is still `kawaa`.

### Added

- `VerificationFlags.CatchAllMeasured` and `DownloadRow.CatchAllMeasured` say whether the API
  measured catch-all for the address. Kawaa measures it only after the mail server accepts the
  mailbox, and the API leaves its finding out when nothing measured it: a disposable address, a
  domain with no usable mail server, a server that refused the mailbox or never answered.
  `CatchAll` is `false` in those cases too, so on its own it could not tell "checked, not
  catch-all" from "not checked". Treat an address as not catch-all only when `CatchAllMeasured`
  is `true` and `CatchAll` is `false`. `CatchAll` itself is unchanged, except that a download row
  with the `catch_all` status now has it `true`, as a verification result already did.
- `verification.catch_all` and a download row's `catch_all` are read leniently: a value that is
  not a boolean is "not stated" instead of an error that fails the whole decode. Both are written
  back only when they were stated (or are `true`), so a JSON round trip keeps a measured `false`
  and never turns an unmeasured one into a finding. A `DownloadRow` no longer writes
  `"catch_all": false` for a row nothing measured.

### Security

- API requests never follow a redirect. `net/http` follows them by default and keeps
  `X-Api-Key` when the redirect goes to another host, so a redirect from the API's address sent
  the API key to wherever it pointed. The Kawaa API never redirects; a `3xx` answer is now
  returned as an `*APIError` with that status, naming the redirect's origin, and is not retried.
  This holds for a client passed to `WithHTTPClient` too: the SDK sets `CheckRedirect` on its own
  copy, so your client is not changed. The presigned download of a large export, which carries
  no key, still follows redirects.

- **Breaking:** `ParseWebhook` and a `WebhookHandler`'s `Parse`, `ParseRequest` and `HTTPHandler`
  now verify the `X-Kawaa-Signature-V2` header by default, and its `t` must be within 300 seconds
  of the current time, so a captured delivery can no longer be replayed through them. Set the
  window with `kawaa.WithWebhookTolerance(d)`, passed to `NewWebhookHandler` or `ParseWebhook`
  (a negative tolerance panics in `NewWebhookHandler` and is an error from `ParseWebhook`). A
  request or value signed only with the legacy `X-Kawaa-Signature` header is refused (401 from
  `HTTPHandler`) unless you pass `kawaa.WithLegacyWebhookSignature()`. That header signs no time,
  so a request accepted through it can be a replay of any delivery ever captured. A request that
  carries an `X-Kawaa-Signature-V2` header is always checked against it, with or without the
  opt-in. To migrate, pass the `X-Kawaa-Signature-V2` header value instead of `X-Kawaa-Signature`
  to `Parse` and `ParseWebhook`; `ParseRequest` and `HTTPHandler` read the right header
  themselves. `VerifyWebhookSignature` keeps its behaviour (it already returns false for a
  non-hex or non-ASCII signature), and `(*WebhookHandler).VerifySignatureV2` now uses the
  handler's window.

### Breaking changes

- The `AuthenticationError`, `RateLimitError`, `InsufficientCreditsError`, `ValidationError` and
  `NotFoundError` types are gone. The client never returned them, so `errors.As` on any of them
  never matched. An error the API sends is an `*APIError`: check it with
  `IsAuthenticationError()`, `IsRateLimitError()`, `IsInsufficientCreditsError()`,
  `IsValidationError()` or `IsNotFoundError()`, as the README's error handling section shows.
- `FindResult.Found()` is true only for a confirmed address: `Email` set and `Verified` true (a
  `valid` verdict). It used to be true for any `Email` with a `Confidence` above 0, so a
  catch-all, risky or role result, where the API returns its best guess with `Verified` false,
  read as found. Check `result.Email` and `result.Status` to use such a guess knowingly.
- `VerifyOptions.DeepVerify` and `VerifyOptions.IncludeAI` are `*bool`, and a nil value is not
  sent, so the API's default (on) applies. As plain `bool` fields, any `VerifyOptions` or
  `BatchOptions` that did not set them, such as `BatchOptions{WebhookURL: url}`, sent
  `deep_verify: false` and `include_ai: false` and turned both checks off. Write
  `kawaa.Bool(false)` to turn one off, and `kawaa.Bool(true)` or nothing to keep it on.
- `BatchJobResult.CreditsUsed` is a `*float64`, and nil when the cost is not known. A replay of
  a batch already accepted under the same `Idempotency-Key` (most often this client's own retry
  after a lost answer) used to report `0`, the API's figure for what the repeat cost, as if the
  batch had cost nothing. It is now nil on a replay, and the new
  `BatchJobResult.IdempotentReplay` says the response was one. The batch's charge and refunds
  are on its job: `GetJobStatus(JobID)` reports `CreditsCharged` and `CreditsRefunded`. Write
  `*job.CreditsUsed` after checking for nil.

### Fixed

- `VerifyBatch` keeps the API's `idempotent_replay` marker (`BatchJobResult.IdempotentReplay`)
  instead of dropping it, and reads the batch's credit figures leniently: a figure that is not
  a number is nil (unknown) rather than an error after the batch was charged.
- `Verify` no longer reports a replay's `credits_used` of `0` as the verification's cost. When
  the job behind a replay cannot be read back, or its read carries no charge, `CreditsUsed` is
  nil, and `GetJobStatus(JobID)` has the charge.
- A response with a success status whose body says `"success": false` is returned as an
  `*APIError` carrying the call's key, even without an `error` object. It used to be mapped as
  data into an empty result.

- `WithTimeout` holds whatever its order with `WithHTTPClient`. Given before it (the order the
  README showed), the timeout was set on the default client that `WithHTTPClient` then
  replaced, so it was lost; given after it, it changed the `*http.Client` you passed. The client
  now uses a copy of yours with the timeout. `WithHTTPClient(nil)` is ignored instead of
  leaving a client that panics on its first request.
