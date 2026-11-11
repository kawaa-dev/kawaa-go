package kawaa

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// WebhookHandler handles incoming webhooks from Kawaa.
//
// Build one with NewWebhookHandler. Its Parse, ParseRequest and HTTPHandler
// check the X-Kawaa-Signature-V2 header and its replay window; the legacy
// X-Kawaa-Signature header is accepted only when the handler was built with
// WithLegacyWebhookSignature.
type WebhookHandler struct {
	secret  string
	options webhookOptions
}

// WebhookOption configures how NewWebhookHandler and ParseWebhook check a
// webhook signature. See WithWebhookTolerance and WithLegacyWebhookSignature.
type WebhookOption func(*webhookOptions)

// webhookOptions is the resolved configuration of the verifying helpers.
type webhookOptions struct {
	tolerance   time.Duration
	allowLegacy bool
}

// defaultWebhookOptions checks X-Kawaa-Signature-V2 with the 300-second
// window and refuses a request signed only with the legacy header.
func defaultWebhookOptions() webhookOptions {
	return webhookOptions{tolerance: DefaultWebhookTolerance}
}

// WithWebhookTolerance sets how far the t= timestamp of an
// X-Kawaa-Signature-V2 header may be from the current time, in either
// direction. The default is DefaultWebhookTolerance (300 seconds). d is
// truncated to whole seconds, a timestamp exactly d away still passes, and 0
// accepts only the current second. A negative d is a programming error:
// NewWebhookHandler panics and ParseWebhook returns an error.
func WithWebhookTolerance(d time.Duration) WebhookOption {
	return func(o *webhookOptions) {
		o.tolerance = d
	}
}

// WithLegacyWebhookSignature also accepts a request signed only with the
// legacy X-Kawaa-Signature header. It is off by default.
//
// The legacy header signs no time, so a request accepted through it can be a
// replay of any delivery ever captured. Turn it on only for a sender that
// cannot send X-Kawaa-Signature-V2; every Kawaa delivery sends both headers.
// A request that carries an X-Kawaa-Signature-V2 header is always checked
// against that header and its window, whatever this option says.
func WithLegacyWebhookSignature() WebhookOption {
	return func(o *webhookOptions) {
		o.allowLegacy = true
	}
}

// resolveWebhookOptions applies opts to the defaults. A nil option or a
// negative tolerance is a programming error, never a reason to fall back to
// the defaults.
func resolveWebhookOptions(opts []WebhookOption) (webhookOptions, error) {
	options := defaultWebhookOptions()
	for _, opt := range opts {
		if opt == nil {
			return webhookOptions{}, errors.New("kawaa: a nil WebhookOption cannot configure the webhook signature check")
		}
		opt(&options)
	}
	if options.tolerance < 0 {
		return webhookOptions{}, fmt.Errorf("kawaa: WithWebhookTolerance needs a webhook signature tolerance of zero or more, got %s", options.tolerance)
	}
	return options, nil
}

// errWebhookSecretMissing is returned instead of skipping verification.
var errWebhookSecretMissing = errors.New("webhook secret is missing or blank, so the signature cannot be checked; " +
	"pass the signing secret for this webhook, or call ParseWebhookUnverified for a per-job callback " +
	"that was sent without a webhook_secret")

// The signature errors of the verifying helpers. Every one says "signature",
// so HTTPHandler answers 401 for it.
var (
	errWebhookSignatureMissing          = errors.New("webhook signature missing")
	errInvalidWebhookSignature          = errors.New("invalid webhook signature")
	errInvalidOrExpiredWebhookSignature = errors.New("invalid or expired webhook signature")
	errLegacyWebhookSignatureValue      = errors.New("webhook signature is a legacy X-Kawaa-Signature value, which signs no time " +
		"and can be replayed. Pass the X-Kawaa-Signature-V2 header instead, or pass WithLegacyWebhookSignature() " +
		"to accept the legacy header")
	errLegacyOnlyWebhookRequest = errors.New("missing X-Kawaa-Signature-V2 header. The legacy X-Kawaa-Signature header " +
		"alone is accepted only with WithLegacyWebhookSignature(), because it can be replayed")
)

// webhookSecretIsSet reports whether secret can key an HMAC that a forger
// could not compute: an empty or whitespace-only key is public knowledge.
func webhookSecretIsSet(secret string) bool {
	return strings.TrimSpace(secret) != ""
}

// NewWebhookHandler creates a new webhook handler.
//
// The handler checks the X-Kawaa-Signature-V2 header, and its t= timestamp
// must be within 300 seconds of the current time (change that with
// WithWebhookTolerance). A request signed only with the legacy
// X-Kawaa-Signature header is refused unless you pass
// WithLegacyWebhookSignature, which accepts replayable requests.
//
// It panics if secret is empty or only whitespace. A handler without a secret
// could not check any signature, so an unset KAWAA_WEBHOOK_SECRET stops the
// server at startup instead of letting forged webhooks through. It also
// panics on a nil option or a negative tolerance, so a bad configuration
// fails at startup too.
func NewWebhookHandler(secret string, opts ...WebhookOption) *WebhookHandler {
	if !webhookSecretIsSet(secret) {
		panic("kawaa: NewWebhookHandler needs a non-empty webhook secret; a handler without one would accept forged webhooks")
	}
	options, err := resolveWebhookOptions(opts)
	if err != nil {
		panic(err.Error())
	}
	return &WebhookHandler{secret: secret, options: options}
}

// VerifySignature verifies a legacy X-Kawaa-Signature value with the
// handler's secret. See VerifyWebhookSignature: that header signs no time
// and can be replayed, so prefer VerifySignatureV2. It returns false when the
// signature is missing or the handler's secret is empty.
func (h *WebhookHandler) VerifySignature(payload []byte, signature string) bool {
	return verifyWebhookSignature(payload, signature, h.secret)
}

func verifyWebhookSignature(payload []byte, signature, secret string) bool {
	if signature == "" || !webhookSecretIsSet(secret) {
		return false
	}

	// Strip "sha256=" prefix if present
	sig := signature
	if len(sig) > 7 && sig[:7] == "sha256=" {
		sig = sig[7:]
	}

	// The lowercase hex digest is compared byte for byte, so any other input
	// (non-hex, non-ASCII, trailing characters) is a mismatch, never a panic.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(sig))
}

// isLegacyWebhookSignatureValue reports whether value is shaped like the
// legacy X-Kawaa-Signature header: it starts with "sha256=", or it is exactly
// 64 hex characters. Nothing is trimmed.
func isLegacyWebhookSignatureValue(value string) bool {
	if strings.HasPrefix(value, "sha256=") {
		return true
	}
	if len(value) != sha256.Size*2 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return false
		}
	}
	return true
}

// Parse verifies the signature and parses a webhook payload. Pass the value
// of the X-Kawaa-Signature-V2 header: it is checked against the body, and
// its t= timestamp must be within the handler's window (300 seconds unless
// it was built WithWebhookTolerance). A legacy X-Kawaa-Signature value
// ("sha256=<hex>" or 64 bare hex characters) is refused unless the handler
// was built WithLegacyWebhookSignature.
//
// It always checks the signature: a missing signature or an empty secret is
// an error, never a reason to skip the check.
func (h *WebhookHandler) Parse(payload []byte, signature string) (*WebhookEvent, error) {
	return parseVerifiedWebhook(payload, signature, h.secret, h.options)
}

func parseVerifiedWebhook(payload []byte, signature, secret string, options webhookOptions) (*WebhookEvent, error) {
	if !webhookSecretIsSet(secret) {
		return nil, errWebhookSecretMissing
	}
	if signature == "" {
		return nil, errWebhookSignatureMissing
	}
	if isLegacyWebhookSignatureValue(signature) {
		if !options.allowLegacy {
			return nil, errLegacyWebhookSignatureValue
		}
		if !verifyWebhookSignature(payload, signature, secret) {
			return nil, errInvalidWebhookSignature
		}
	} else if !verifyWebhookSignatureV2(payload, signature, secret, options.tolerance, time.Now()) {
		return nil, errInvalidOrExpiredWebhookSignature
	}

	return ParseWebhookUnverified(payload)
}

// checkRequestSignature checks the signature headers of a request. A request
// with an X-Kawaa-Signature-V2 header (any value, even empty) is checked
// against it alone; the legacy X-Kawaa-Signature header is read only when
// that header is absent and the handler accepts legacy signatures.
func (h *WebhookHandler) checkRequestSignature(payload []byte, header http.Header) error {
	if !webhookSecretIsSet(h.secret) {
		return errWebhookSecretMissing
	}
	if len(header.Values("X-Kawaa-Signature-V2")) > 0 {
		if !verifyWebhookSignatureV2(payload, header.Get("X-Kawaa-Signature-V2"), h.secret, h.options.tolerance, time.Now()) {
			return errInvalidOrExpiredWebhookSignature
		}
		return nil
	}

	legacy := header.Get("X-Kawaa-Signature")
	if legacy == "" {
		return errWebhookSignatureMissing
	}
	if !h.options.allowLegacy {
		return errLegacyOnlyWebhookRequest
	}
	if !verifyWebhookSignature(payload, legacy, h.secret) {
		return errInvalidWebhookSignature
	}
	return nil
}

// ParseWebhookUnverified parses a webhook payload WITHOUT checking its
// signature. Use it only for a per-job WebhookURL callback created without a
// WebhookSecret (Kawaa sends those unsigned), or for a body whose signature
// you already checked with VerifyWebhookSignature or VerifyWebhookSignatureV2.
// Anyone who knows your endpoint URL can send a body that parses here.
func ParseWebhookUnverified(payload []byte) (*WebhookEvent, error) {
	var event WebhookEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return nil, fmt.Errorf("failed to parse webhook payload: %w", err)
	}

	return &event, nil
}

// ParseRequest verifies and parses a webhook from an HTTP request.
//
// The request is checked against its X-Kawaa-Signature-V2 header, and the
// header's t= timestamp must be within the handler's window (300 seconds
// unless it was built WithWebhookTolerance), so a captured delivery cannot
// be replayed later. A request with only the legacy X-Kawaa-Signature header
// is refused unless the handler was built WithLegacyWebhookSignature; a
// request that carries an X-Kawaa-Signature-V2 header is checked against it
// alone, whatever that option says.
func (h *WebhookHandler) ParseRequest(r *http.Request) (*WebhookEvent, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}
	defer r.Body.Close()

	if err := h.checkRequestSignature(body, r.Header); err != nil {
		return nil, err
	}
	return ParseWebhookUnverified(body)
}

// HTTPHandler returns an http.HandlerFunc that processes webhooks. It checks
// each request exactly as ParseRequest does and answers 401 when the
// signature check fails, 400 for a body that is not a webhook, and 500 when
// handler returns an error.
func (h *WebhookHandler) HTTPHandler(handler func(*WebhookEvent) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		event, err := h.ParseRequest(r)
		if err != nil {
			if isSignatureError(err) {
				http.Error(w, err.Error(), http.StatusUnauthorized)
			} else {
				http.Error(w, err.Error(), http.StatusBadRequest)
			}
			return
		}

		if err := handler(event); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}
}

// VerifyWebhookSignature verifies a legacy X-Kawaa-Signature value
// ("sha256=<hex HMAC-SHA256 of the body>", or the bare hex). It returns false
// when the signature is missing or wrong, or the secret is empty or only
// whitespace.
//
// The legacy header is an HMAC of the body alone. It signs no time, so a
// captured delivery verifies here forever: anyone who records one request
// can replay it. Prefer VerifyWebhookSignatureV2, which every Kawaa delivery
// also carries. The verifying helpers (ParseWebhook, and a WebhookHandler's
// Parse, ParseRequest and HTTPHandler) use this check only with
// WithLegacyWebhookSignature.
func VerifyWebhookSignature(payload []byte, signature, secret string) bool {
	return verifyWebhookSignature(payload, signature, secret)
}

// ParseWebhook verifies the signature and parses a webhook. Pass the value
// of the X-Kawaa-Signature-V2 header: it is checked against the body, and its
// t= timestamp must be within 300 seconds of the current time (change that
// with WithWebhookTolerance), so a captured delivery cannot be replayed
// later.
//
// A legacy X-Kawaa-Signature value ("sha256=<hex>" or 64 bare hex
// characters) is refused unless you pass WithLegacyWebhookSignature. That
// header signs no time, so a request accepted through it can be a replay.
//
// It returns an error when the secret is empty or only whitespace, the
// signature is missing, wrong, outside the window or a refused legacy value,
// the body is not JSON, or an option is nil or a negative tolerance. For an
// unsigned per-job callback use ParseWebhookUnverified.
func ParseWebhook(payload []byte, signature, secret string, opts ...WebhookOption) (*WebhookEvent, error) {
	options, err := resolveWebhookOptions(opts)
	if err != nil {
		return nil, err
	}
	return parseVerifiedWebhook(payload, signature, secret, options)
}

// webhookSignatureErrors are the errors the signature check itself returns.
var webhookSignatureErrors = []error{
	errWebhookSecretMissing,
	errWebhookSignatureMissing,
	errInvalidWebhookSignature,
	errInvalidOrExpiredWebhookSignature,
	errLegacyWebhookSignatureValue,
	errLegacyOnlyWebhookRequest,
}

// isSignatureError returns true if the error is related to signature/auth verification.
func isSignatureError(err error) bool {
	for _, target := range webhookSignatureErrors {
		if errors.Is(err, target) {
			return true
		}
	}
	msg := err.Error()
	return strings.Contains(msg, "signature") || strings.Contains(msg, "secret")
}

// DefaultWebhookTolerance is how far the t= timestamp of an
// X-Kawaa-Signature-V2 header may be from the current time (in either
// direction) when VerifyWebhookSignatureV2, ParseWebhook or a WebhookHandler
// checks it without WithWebhookTolerance.
const DefaultWebhookTolerance = 300 * time.Second

// VerifySignatureV2 verifies the X-Kawaa-Signature-V2 header with the
// handler's secret and window: 300 seconds unless the handler was built
// WithWebhookTolerance. See VerifyWebhookSignatureV2.
func (h *WebhookHandler) VerifySignatureV2(payload []byte, header string) bool {
	return verifyWebhookSignatureV2(payload, header, h.secret, h.options.tolerance, time.Now())
}

// VerifyWebhookSignatureV2 verifies the X-Kawaa-Signature-V2 header
// ("t=<unix seconds>,v1=<hex HMAC-SHA256>") of a webhook delivery, which
// protects against replay as well as forgery. payload is the raw request body
// exactly as received (never re-serialized JSON), header is the
// X-Kawaa-Signature-V2 value and secret is the same webhook secret that signs
// the legacy X-Kawaa-Signature header.
//
// It returns true only when the header is well formed, its timestamp is
// within DefaultWebhookTolerance (300 seconds) of the current time, and one
// of its v1 signatures is the HMAC-SHA256 of "<t>.<payload>" keyed with
// secret. It returns false for a missing or malformed header, a stale or
// future timestamp, a wrong signature, or an empty or whitespace-only secret.
//
// Every delivery attempt (automatic retry, manual retry or test delivery) is
// signed with a fresh timestamp, so a legitimate retry still verifies. A
// delivery captured and replayed after the window is rejected.
func VerifyWebhookSignatureV2(payload []byte, header, secret string) bool {
	return verifyWebhookSignatureV2(payload, header, secret, DefaultWebhookTolerance, time.Now())
}

// VerifyWebhookSignatureV2WithTolerance is VerifyWebhookSignatureV2 with a
// custom window. tolerance is truncated to whole seconds, and a timestamp
// exactly tolerance away from the current time still passes. A negative
// tolerance is a programming error: it returns false for every header.
func VerifyWebhookSignatureV2WithTolerance(payload []byte, header, secret string, tolerance time.Duration) bool {
	return verifyWebhookSignatureV2(payload, header, secret, tolerance, time.Now())
}

func verifyWebhookSignatureV2(payload []byte, header, secret string, tolerance time.Duration, now time.Time) bool {
	if tolerance < 0 || !webhookSecretIsSet(secret) {
		return false
	}
	timestamp, literal, signatures, ok := parseWebhookSignatureV2(header)
	if !ok {
		return false
	}

	toleranceSeconds := int64(tolerance / time.Second)
	nowSeconds := now.Unix()
	// timestamp has at most 15 digits, so neither difference can overflow.
	if nowSeconds-timestamp > toleranceSeconds || timestamp-nowSeconds > toleranceSeconds {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(literal))
	mac.Write([]byte{'.'})
	mac.Write(payload)
	expected := mac.Sum(nil)

	matched := false
	for _, signature := range signatures {
		// Check every entry so the time taken does not depend on which matched.
		if hmac.Equal(expected, signature) {
			matched = true
		}
	}
	return matched
}

// parseWebhookSignatureV2 splits an X-Kawaa-Signature-V2 header into its
// timestamp (parsed and as the literal that was signed) and its decoded v1
// signatures. ok is false when the header is malformed: a part without "=",
// no t or more than one, a t that is not 1 to 15 ASCII digits, no v1, or a v1
// that is not 64 hex characters. Other keys are ignored.
func parseWebhookSignatureV2(header string) (timestamp int64, literal string, signatures [][]byte, ok bool) {
	// Only ASCII space and tab (HTTP's optional whitespace) are trimmed, the
	// same in every Kawaa SDK, so they accept and reject the same headers.
	header = strings.Trim(header, " \t")
	if header == "" {
		return 0, "", nil, false
	}

	seenTimestamp := false
	for _, part := range strings.Split(header, ",") {
		key, value, found := strings.Cut(strings.Trim(part, " \t"), "=")
		if !found {
			return 0, "", nil, false
		}
		switch key {
		case "t":
			if seenTimestamp || !isWebhookTimestamp(value) {
				return 0, "", nil, false
			}
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return 0, "", nil, false
			}
			seenTimestamp = true
			timestamp, literal = parsed, value
		case "v1":
			if len(value) != sha256.Size*2 {
				return 0, "", nil, false
			}
			decoded, err := hex.DecodeString(value)
			if err != nil {
				return 0, "", nil, false
			}
			signatures = append(signatures, decoded)
		}
	}

	if !seenTimestamp || len(signatures) == 0 {
		return 0, "", nil, false
	}
	return timestamp, literal, signatures, true
}

// isWebhookTimestamp reports whether value is 1 to 15 ASCII digits.
func isWebhookTimestamp(value string) bool {
	if len(value) == 0 || len(value) > 15 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}
