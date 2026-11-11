package kawaa

// The verifying helpers (ParseWebhook, and a WebhookHandler's Parse,
// ParseRequest and HTTPHandler) check X-Kawaa-Signature-V2 and its replay
// window by default. The legacy X-Kawaa-Signature, which signs no time, is
// accepted only with WithLegacyWebhookSignature, and never in place of a V2
// header the request carries.
//
// Headers are signed with crypto/hmac directly (signWebhook and
// signWebhookV2), never with the verifier under test.

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	helpersSecret       = "whsec_helpers-v2"
	helpersV2Header     = "X-Kawaa-Signature-V2"
	helpersLegacyHeader = "X-Kawaa-Signature"
)

var (
	helpersBody     = []byte(`{"event":"job.completed","data":{"job_id":"job_v2_helpers","status":"completed","note":"Zoë"},"webhook_id":"wh_helpers","timestamp":"2026-10-06T00:00:00.000Z"}`)
	helpersTampered = bytes.Replace(helpersBody, []byte("job_v2_helpers"), []byte("job_v2_hijacked"), 1)
)

// signV2Offset signs body with a t offsetSeconds from now.
func signV2Offset(body []byte, secret string, offsetSeconds int64) string {
	return signWebhookV2(body, secret, time.Now().Unix()+offsetSeconds)
}

// helperOutcomes is what each helper made of one request: "ok", "401" for a
// signature error, or anything else (a panic, a 400, a non-signature error),
// which every test here treats as a failure.
type helperOutcomes struct {
	ParseWebhook string
	HandlerParse string
	ParseRequest string
	HTTPHandler  string
}

var (
	allAccepted = helperOutcomes{"ok", "ok", "ok", "ok"}
	allRefused  = helperOutcomes{"401", "401", "401", "401"}
)

// outcomeOf runs fn and names its result; a panic is reported, not raised.
func outcomeOf(fn func() error) (outcome string) {
	defer func() {
		if r := recover(); r != nil {
			outcome = fmt.Sprintf("panic: %v", r)
		}
	}()
	err := fn()
	switch {
	case err == nil:
		return "ok"
	case isSignatureError(err):
		return "401"
	default:
		return "error: " + err.Error()
	}
}

// runWebhookHelpers sends one request through every helper. A key in
// headers is sent even when its value is empty. The parse functions take one
// value: the V2 header when the request has one, else the legacy header.
func runWebhookHelpers(t *testing.T, body []byte, headers map[string]string, opts ...WebhookOption) helperOutcomes {
	t.Helper()
	value, hasV2 := headers[helpersV2Header]
	if !hasV2 {
		value = headers[helpersLegacyHeader]
	}
	newRequest := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
		for name, v := range headers {
			req.Header.Set(name, v)
		}
		return req
	}
	handler := NewWebhookHandler(helpersSecret, opts...)

	var out helperOutcomes
	out.ParseWebhook = outcomeOf(func() error {
		_, err := ParseWebhook(body, value, helpersSecret, opts...)
		return err
	})
	out.HandlerParse = outcomeOf(func() error {
		_, err := handler.Parse(body, value)
		return err
	})
	out.ParseRequest = outcomeOf(func() error {
		_, err := handler.ParseRequest(newRequest())
		return err
	})
	out.HTTPHandler = outcomeOf(func() error {
		rec := httptest.NewRecorder()
		handler.HTTPHandler(func(*WebhookEvent) error { return nil })(rec, newRequest())
		switch rec.Code {
		case http.StatusOK:
			return nil
		case http.StatusUnauthorized:
			return errInvalidWebhookSignature
		default:
			return fmt.Errorf("status %d: %s", rec.Code, rec.Body.String())
		}
	})
	return out
}

func v2Only(value string) map[string]string { return map[string]string{helpersV2Header: value} }

func legacyOnly(value string) map[string]string {
	return map[string]string{helpersLegacyHeader: value}
}

func TestWebhookHelpersAcceptAFreshV2Delivery(t *testing.T) {
	assert.Equal(t, allAccepted, runWebhookHelpers(t, helpersBody, v2Only(signV2Offset(helpersBody, helpersSecret, 0))))
}

func TestWebhookHelpersAcceptAV2DeliverySignedInsideTheWindow(t *testing.T) {
	assert.Equal(t, allAccepted, runWebhookHelpers(t, helpersBody, v2Only(signV2Offset(helpersBody, helpersSecret, -290))),
		"290 s old is inside the 300 s window")
}

func TestWebhookHelpersRefuseAV2DeliveryOutsideTheWindow(t *testing.T) {
	assert.Equal(t, allRefused, runWebhookHelpers(t, helpersBody, v2Only(signV2Offset(helpersBody, helpersSecret, -310))),
		"310 s old is a replay")
	assert.Equal(t, allRefused, runWebhookHelpers(t, helpersBody, v2Only(signV2Offset(helpersBody, helpersSecret, 310))),
		"310 s ahead")

	_, err := ParseWebhook(helpersBody, signV2Offset(helpersBody, helpersSecret, -310), helpersSecret)
	require.Error(t, err)
	assert.Equal(t, "invalid or expired webhook signature", err.Error())
}

func TestWebhookHelpersRefuseATamperedBodyOrAWrongSecret(t *testing.T) {
	assert.Equal(t, allRefused, runWebhookHelpers(t, helpersTampered, v2Only(signV2Offset(helpersBody, helpersSecret, 0))))
	assert.Equal(t, allRefused, runWebhookHelpers(t, helpersBody, v2Only(signV2Offset(helpersBody, "whsec_other", 0))))
}

func TestWebhookHelpersHonourAConfiguredTolerance(t *testing.T) {
	stale := v2Only(signV2Offset(helpersBody, helpersSecret, -310))
	assert.Equal(t, allAccepted, runWebhookHelpers(t, helpersBody, stale, WithWebhookTolerance(600*time.Second)))

	recent := v2Only(signV2Offset(helpersBody, helpersSecret, -20))
	assert.Equal(t, allRefused, runWebhookHelpers(t, helpersBody, recent, WithWebhookTolerance(10*time.Second)))

	// The handler's own V2 check uses its window too.
	wide := NewWebhookHandler(helpersSecret, WithWebhookTolerance(600*time.Second))
	assert.True(t, wide.VerifySignatureV2(helpersBody, stale[helpersV2Header]))
	assert.False(t, NewWebhookHandler(helpersSecret).VerifySignatureV2(helpersBody, stale[helpersV2Header]))
}

func TestWebhookHelpersRefuseARequestCarryingOnlyTheLegacyHeader(t *testing.T) {
	legacy := legacyOnly(signWebhook(helpersBody, helpersSecret))
	assert.Equal(t, allRefused, runWebhookHelpers(t, helpersBody, legacy))

	// So is a bare-hex legacy value.
	bare := strings.TrimPrefix(signWebhook(helpersBody, helpersSecret), "sha256=")
	assert.Equal(t, allRefused, runWebhookHelpers(t, helpersBody, legacyOnly(bare)))
}

func TestWebhookHelpersExplainHowToOptInWhenALegacyValueIsRefused(t *testing.T) {
	legacy := signWebhook(helpersBody, helpersSecret)

	_, err := ParseWebhook(helpersBody, legacy, helpersSecret)
	require.Error(t, err)
	assert.Equal(t, "webhook signature is a legacy X-Kawaa-Signature value, which signs no time and can be replayed. "+
		"Pass the X-Kawaa-Signature-V2 header instead, or pass WithLegacyWebhookSignature() to accept the legacy header", err.Error())

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(helpersBody))
	req.Header.Set(helpersLegacyHeader, legacy)
	_, err = NewWebhookHandler(helpersSecret).ParseRequest(req)
	require.Error(t, err)
	assert.Equal(t, "missing X-Kawaa-Signature-V2 header. The legacy X-Kawaa-Signature header alone is accepted only "+
		"with WithLegacyWebhookSignature(), because it can be replayed", err.Error())

	req = httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(helpersBody))
	req.Header.Set(helpersLegacyHeader, legacy)
	rec := httptest.NewRecorder()
	NewWebhookHandler(helpersSecret).HTTPHandler(func(*WebhookEvent) error { return nil })(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "WithLegacyWebhookSignature")
}

func TestWebhookHelpersKeepTheMissingSignatureError(t *testing.T) {
	for _, headers := range []map[string]string{{}, legacyOnly("")} {
		for _, opts := range [][]WebhookOption{nil, {WithLegacyWebhookSignature()}} {
			assert.Equal(t, allRefused, runWebhookHelpers(t, helpersBody, headers, opts...))

			req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(helpersBody))
			for name, value := range headers {
				req.Header.Set(name, value)
			}
			_, err := NewWebhookHandler(helpersSecret, opts...).ParseRequest(req)
			require.Error(t, err)
			assert.Equal(t, "webhook signature missing", err.Error())
		}
	}
}

func TestWebhookHelpersKeepTheBadBodyStatus(t *testing.T) {
	notJSON := []byte("not json")
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(notJSON))
	req.Header.Set(helpersV2Header, signV2Offset(notJSON, helpersSecret, 0))
	rec := httptest.NewRecorder()
	ran := false
	NewWebhookHandler(helpersSecret).HTTPHandler(func(*WebhookEvent) error {
		ran = true
		return nil
	})(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "a signed body that is not JSON is still a 400")
	assert.False(t, ran)

	_, err := ParseWebhook(notJSON, signV2Offset(notJSON, helpersSecret, 0), helpersSecret)
	require.Error(t, err)
	assert.False(t, isSignatureError(err))
}

func TestWebhookHelpersWithLegacyOptInAcceptAValidLegacyHeader(t *testing.T) {
	legacy := signWebhook(helpersBody, helpersSecret)
	assert.Equal(t, allAccepted, runWebhookHelpers(t, helpersBody, legacyOnly(legacy), WithLegacyWebhookSignature()))

	bare := strings.TrimPrefix(legacy, "sha256=")
	assert.Equal(t, allAccepted, runWebhookHelpers(t, helpersBody, legacyOnly(bare), WithLegacyWebhookSignature()))
}

func TestWebhookHelpersWithLegacyOptInStillRefuseAWrongLegacySignatureOrTamperedBody(t *testing.T) {
	assert.Equal(t, allRefused,
		runWebhookHelpers(t, helpersBody, legacyOnly(signWebhook(helpersBody, "whsec_other")), WithLegacyWebhookSignature()))
	assert.Equal(t, allRefused,
		runWebhookHelpers(t, helpersTampered, legacyOnly(signWebhook(helpersBody, helpersSecret)), WithLegacyWebhookSignature()))

	_, err := ParseWebhook(helpersTampered, signWebhook(helpersBody, helpersSecret), helpersSecret, WithLegacyWebhookSignature())
	require.Error(t, err)
	assert.Equal(t, "invalid webhook signature", err.Error())
}

func TestWebhookHelpersWithLegacyOptInStillCheckAV2HeaderAndNeverFallBack(t *testing.T) {
	legacy := signWebhook(helpersBody, helpersSecret)
	for name, v2 := range map[string]string{
		"stale":     signV2Offset(helpersBody, helpersSecret, -310),
		"ahead":     signV2Offset(helpersBody, helpersSecret, 310),
		"malformed": "garbage",
		"empty":     "",
		"wrong key": signV2Offset(helpersBody, "whsec_other", 0),
	} {
		headers := map[string]string{helpersV2Header: v2, helpersLegacyHeader: legacy}
		assert.Equal(t, allRefused, runWebhookHelpers(t, helpersBody, headers, WithLegacyWebhookSignature()),
			"%s V2 header beside a valid legacy one", name)
	}

	// The parse functions: a stale V2 value is refused with the opt-in too.
	_, err := ParseWebhook(helpersBody, signV2Offset(helpersBody, helpersSecret, -310), helpersSecret, WithLegacyWebhookSignature())
	require.Error(t, err)
	assert.Equal(t, "invalid or expired webhook signature", err.Error())
	_, err = NewWebhookHandler(helpersSecret, WithLegacyWebhookSignature()).Parse(helpersBody, signV2Offset(helpersBody, helpersSecret, -310))
	require.Error(t, err)
}

func TestWebhookHelpersWithLegacyOptInAcceptAFreshV2Delivery(t *testing.T) {
	fresh := signV2Offset(helpersBody, helpersSecret, 0)
	assert.Equal(t, allAccepted, runWebhookHelpers(t, helpersBody, v2Only(fresh), WithLegacyWebhookSignature()))
	headers := map[string]string{helpersV2Header: fresh, helpersLegacyHeader: "sha256=" + strings.Repeat("0", 64)}
	assert.Equal(t, allAccepted, runWebhookHelpers(t, helpersBody, headers, WithLegacyWebhookSignature()),
		"a valid V2 header is enough; the legacy one is not read")
}

// malformedWebhookSignatures are non-ASCII or otherwise malformed values.
func malformedWebhookSignatures() []string {
	validHex := strings.TrimPrefix(signWebhook(helpersBody, helpersSecret), "sha256=")
	return []string{
		"sha256=é" + strings.Repeat("a", 63),
		"sha256=" + strings.Repeat("é", 64),
		"t=1790000000,v1=" + strings.Repeat("é", 64),
		"t=１７９０００００００,v1=" + strings.Repeat("a", 64),
		"\U0001F600",
		"sha256=" + validHex + "zz",
		validHex + "zz",
		"sha256=",
		"sha256=" + validHex[:63] + "é",
		"t=" + strconv.FormatInt(time.Now().Unix(), 10) + ",v1=" + validHex[:63] + "é",
	}
}

func TestVerifyWebhookSignatureReturnsFalseForAMalformedSignature(t *testing.T) {
	handler := NewWebhookHandler(helpersSecret)
	for _, signature := range malformedWebhookSignatures() {
		assert.NotPanics(t, func() {
			assert.False(t, VerifyWebhookSignature(helpersBody, signature, helpersSecret), "%q", signature)
			assert.False(t, handler.VerifySignature(helpersBody, signature), "%q", signature)
			assert.False(t, VerifyWebhookSignatureV2(helpersBody, signature, helpersSecret), "%q", signature)
		}, "%q", signature)
	}
}

func TestWebhookHelpersRefuseAMalformedSignatureInEitherHeader(t *testing.T) {
	for _, signature := range malformedWebhookSignatures() {
		for _, opts := range [][]WebhookOption{nil, {WithLegacyWebhookSignature()}} {
			assert.Equal(t, allRefused, runWebhookHelpers(t, helpersBody, v2Only(signature), opts...),
				"V2 header %q, opt-in %v", signature, len(opts) > 0)
			assert.Equal(t, allRefused, runWebhookHelpers(t, helpersBody, legacyOnly(signature), opts...),
				"legacy header %q, opt-in %v", signature, len(opts) > 0)
		}
	}
}

func TestWebhookHelperOptionsAreCheckedUpFront(t *testing.T) {
	bad := map[string][]WebhookOption{
		"negative tolerance":            {WithWebhookTolerance(-time.Second)},
		"negative nanosecond tolerance": {WithWebhookTolerance(-time.Nanosecond)},
		"nil option":                    {nil},
		"nil option after a good one":   {WithLegacyWebhookSignature(), nil},
	}
	fresh := signV2Offset(helpersBody, helpersSecret, 0)
	for name, opts := range bad {
		assert.Panics(t, func() { NewWebhookHandler(helpersSecret, opts...) }, "%s: the handler is refused when built", name)

		var err error
		assert.NotPanics(t, func() { _, err = ParseWebhook(helpersBody, fresh, helpersSecret, opts...) }, name)
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), "kawaa: ", name)
	}

	assert.PanicsWithValue(t,
		"kawaa: WithWebhookTolerance needs a webhook signature tolerance of zero or more, got -1s",
		func() { NewWebhookHandler(helpersSecret, WithWebhookTolerance(-time.Second)) })

	// Zero is a valid window: only the current second.
	assert.NotPanics(t, func() { NewWebhookHandler(helpersSecret, WithWebhookTolerance(0)) })
	_, err := ParseWebhook(helpersBody, signV2Offset(helpersBody, helpersSecret, -20), helpersSecret, WithWebhookTolerance(0))
	require.Error(t, err)
}
