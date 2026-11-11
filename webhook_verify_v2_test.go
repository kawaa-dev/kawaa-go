package kawaa

// X-Kawaa-Signature-V2: t=<unix seconds>,v1=<hex HMAC-SHA256 of
// "<t>.<raw body>">. The known-answer vectors in
// testdata/signatures/webhook-signature-v2.json are shared by every SDK,
// so all of them accept and refuse the same headers.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type webhookSignatureV2Fixture struct {
	Secret                          string   `json:"secret"`
	Body                            string   `json:"body"`
	Timestamp                       int64    `json:"timestamp"`
	ToleranceSecondsForFixedVectors int64    `json:"tolerance_seconds_for_fixed_vectors"`
	Header                          string   `json:"header"`
	LegacyHeader                    string   `json:"legacy_header"`
	ValidHeaders                    []string `json:"valid_headers"`
	InvalidHeaders                  []string `json:"invalid_headers"`
}

func readWebhookSignatureV2Fixture(t *testing.T) webhookSignatureV2Fixture {
	t.Helper()
	raw, err := os.ReadFile(sharedFixture("signatures", "webhook-signature-v2.json"))
	require.NoError(t, err)
	var fixture webhookSignatureV2Fixture
	require.NoError(t, json.Unmarshal(raw, &fixture))
	require.NotEmpty(t, fixture.ValidHeaders)
	require.NotEmpty(t, fixture.InvalidHeaders)
	return fixture
}

// fixedVectorTolerance is the fixture's window for its fixed timestamps.
func (f webhookSignatureV2Fixture) fixedVectorTolerance() time.Duration {
	return time.Duration(f.ToleranceSecondsForFixedVectors) * time.Second
}

// signWebhookV2 builds a header with the HMAC primitives directly, not with
// the code under test.
func signWebhookV2(payload []byte, secret string, timestamp int64) string {
	literal := strconv.FormatInt(timestamp, 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(literal + "."))
	mac.Write(payload)
	return "t=" + literal + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

func TestWebhookSignatureV2FixtureSignerMatchesTheVectors(t *testing.T) {
	fixture := readWebhookSignatureV2Fixture(t)
	assert.Equal(t, fixture.Header, signWebhookV2([]byte(fixture.Body), fixture.Secret, fixture.Timestamp))
	assert.True(t, strings.Contains(fixture.Body, "Zoë"), "the body carries a non-ASCII character")
}

func TestVerifyWebhookSignatureV2AcceptsEveryValidVector(t *testing.T) {
	fixture := readWebhookSignatureV2Fixture(t)
	body := []byte(fixture.Body) // UTF-8, as sent
	for _, header := range fixture.ValidHeaders {
		assert.True(t, VerifyWebhookSignatureV2WithTolerance(body, header, fixture.Secret, fixture.fixedVectorTolerance()),
			"valid header %q", header)
	}
}

func TestVerifyWebhookSignatureV2RejectsEveryInvalidVector(t *testing.T) {
	fixture := readWebhookSignatureV2Fixture(t)
	body := []byte(fixture.Body)
	for _, header := range fixture.InvalidHeaders {
		assert.False(t, VerifyWebhookSignatureV2WithTolerance(body, header, fixture.Secret, fixture.fixedVectorTolerance()),
			"invalid header %q", header)
	}
}

func TestVerifyWebhookSignatureV2DefaultWindow(t *testing.T) {
	fixture := readWebhookSignatureV2Fixture(t)
	body := []byte(fixture.Body)
	now := time.Now().Unix()

	assert.Equal(t, 300*time.Second, DefaultWebhookTolerance)

	fresh := signWebhookV2(body, fixture.Secret, now)
	assert.True(t, VerifyWebhookSignatureV2(body, fresh, fixture.Secret))
	assert.True(t, NewWebhookHandler(fixture.Secret).VerifySignatureV2(body, fresh))

	stale := signWebhookV2(body, fixture.Secret, now-600)
	assert.False(t, VerifyWebhookSignatureV2(body, stale, fixture.Secret), "a delivery replayed 600 s later")
	assert.False(t, NewWebhookHandler(fixture.Secret).VerifySignatureV2(body, stale))
	assert.True(t, VerifyWebhookSignatureV2WithTolerance(body, stale, fixture.Secret, time.Hour),
		"the tolerance argument widens the window")

	future := signWebhookV2(body, fixture.Secret, now+600)
	assert.False(t, VerifyWebhookSignatureV2(body, future, fixture.Secret), "a timestamp 600 s ahead")
	assert.True(t, VerifyWebhookSignatureV2WithTolerance(body, future, fixture.Secret, time.Hour))
}

func TestVerifyWebhookSignatureV2WindowEdgesAtAFixedClock(t *testing.T) {
	// The clock is injected, so the exact edges are deterministic here.
	fixture := readWebhookSignatureV2Fixture(t)
	body := []byte(fixture.Body)
	now := time.Unix(fixture.Timestamp, 0)
	header := fixture.Header

	for _, offset := range []int64{-300, 300} {
		at := now.Add(time.Duration(offset) * time.Second)
		assert.True(t, verifyWebhookSignatureV2(body, header, fixture.Secret, DefaultWebhookTolerance, at),
			"exactly the tolerance away (%d s) passes", offset)
	}
	for _, offset := range []int64{-301, 301} {
		at := now.Add(time.Duration(offset) * time.Second)
		assert.False(t, verifyWebhookSignatureV2(body, header, fixture.Secret, DefaultWebhookTolerance, at),
			"one second past the tolerance (%d s) fails", offset)
	}

	// The tolerance is truncated to whole seconds: 300.9 s is a 300 s window.
	late := now.Add(301 * time.Second)
	assert.False(t, verifyWebhookSignatureV2(body, header, fixture.Secret, 300*time.Second+900*time.Millisecond, late))
	assert.True(t, verifyWebhookSignatureV2(body, header, fixture.Secret, 301*time.Second, late))

	// A zero window accepts only the same second.
	assert.True(t, verifyWebhookSignatureV2(body, header, fixture.Secret, 0, now))
	assert.False(t, verifyWebhookSignatureV2(body, header, fixture.Secret, 0, now.Add(time.Second)))
}

func TestVerifyWebhookSignatureV2TimestampLiteralAndDigitCap(t *testing.T) {
	fixture := readWebhookSignatureV2Fixture(t)
	body := []byte(fixture.Body)
	signLiteral := func(literal string) string {
		mac := hmac.New(sha256.New, []byte(fixture.Secret))
		mac.Write([]byte(literal + "."))
		mac.Write(body)
		return "t=" + literal + ",v1=" + hex.EncodeToString(mac.Sum(nil))
	}

	// The signed bytes start with t exactly as written, leading zeros included.
	padded := "000" + strconv.FormatInt(fixture.Timestamp, 10)
	at := time.Unix(fixture.Timestamp, 0)
	assert.True(t, verifyWebhookSignatureV2(body, signLiteral(padded), fixture.Secret, 0, at))
	reformatted := "t=" + padded + ",v1=" + strings.SplitN(fixture.Header, "v1=", 2)[1]
	assert.False(t, verifyWebhookSignatureV2(body, reformatted, fixture.Secret, 0, at),
		"a signature over the unpadded t does not cover the padded one")

	// t has at most 15 digits, even when the clock agrees with it.
	fifteen := int64(123456789012345)
	assert.True(t, verifyWebhookSignatureV2(body, signLiteral(strconv.FormatInt(fifteen, 10)), fixture.Secret, 0, time.Unix(fifteen, 0)))
	sixteen := int64(1234567890123456)
	assert.False(t, verifyWebhookSignatureV2(body, signLiteral(strconv.FormatInt(sixteen, 10)), fixture.Secret, 0, time.Unix(sixteen, 0)))
}

func TestVerifyWebhookSignatureV2RejectsWrongSecretTamperedBodyAndBlankSecret(t *testing.T) {
	fixture := readWebhookSignatureV2Fixture(t)
	body := []byte(fixture.Body)
	header := signWebhookV2(body, fixture.Secret, time.Now().Unix())
	require.True(t, VerifyWebhookSignatureV2(body, header, fixture.Secret))

	assert.False(t, VerifyWebhookSignatureV2(body, header, fixture.Secret+"x"), "wrong secret")

	tampered := append([]byte(nil), body...)
	tampered[len(tampered)-2] ^= 0x01
	assert.False(t, VerifyWebhookSignatureV2(tampered, header, fixture.Secret), "one byte changed")

	for _, secret := range blankSecrets {
		emptyKey := signWebhookV2(body, secret, time.Now().Unix())
		assert.False(t, VerifyWebhookSignatureV2(body, emptyKey, secret), "an HMAC keyed with %q", secret)
		assert.False(t, VerifyWebhookSignatureV2(body, header, secret), "blank secret %q", secret)
	}

	// A handler built without NewWebhookHandler has no secret.
	assert.False(t, (&WebhookHandler{}).VerifySignatureV2(body, signWebhookV2(body, "", time.Now().Unix())))

	assert.False(t, VerifyWebhookSignatureV2(body, "", fixture.Secret), "missing header")
}

func TestVerifyWebhookSignatureV2RejectsATimestampChangedAfterSigning(t *testing.T) {
	fixture := readWebhookSignatureV2Fixture(t)
	body := []byte(fixture.Body)
	now := time.Now().Unix()
	header := signWebhookV2(body, fixture.Secret, now)
	moved := strings.Replace(header, "t="+strconv.FormatInt(now, 10), "t="+strconv.FormatInt(now+1, 10), 1)
	require.NotEqual(t, header, moved)
	assert.False(t, VerifyWebhookSignatureV2(body, moved, fixture.Secret))
}

func TestVerifyWebhookSignatureV2MalformedEntryBesideAValidOneRejectsTheHeader(t *testing.T) {
	fixture := readWebhookSignatureV2Fixture(t)
	body := []byte(fixture.Body)
	header := signWebhookV2(body, fixture.Secret, time.Now().Unix())
	require.True(t, VerifyWebhookSignatureV2(body, header, fixture.Secret))

	for _, extra := range []string{
		"v1=" + strings.Repeat("ab", 33), // 66 hex characters
		"v1=" + strings.Repeat("ab", 31), // 62 hex characters
		"v1=" + strings.Repeat("g", 64),
		"v1=",
		"t=" + strconv.FormatInt(time.Now().Unix(), 10), // a second t
		"junk",
		"",
	} {
		assert.False(t, VerifyWebhookSignatureV2(body, header+","+extra, fixture.Secret), "%q after", extra)
		assert.False(t, VerifyWebhookSignatureV2(body, extra+","+header, fixture.Secret), "%q before", extra)
	}

	// Unknown keys are ignored, and surrounding spaces and tabs are trimmed.
	assert.True(t, VerifyWebhookSignatureV2(body, "v2=whatever, "+header+" ,v0=", fixture.Secret))
	assert.True(t, VerifyWebhookSignatureV2(body, " \t"+strings.Replace(header, ",", " , ", 1)+"\t", fixture.Secret))
	// Only spaces and tabs: other whitespace is part of the value, as in every SDK.
	assert.False(t, VerifyWebhookSignatureV2(body, header+"\n", fixture.Secret))
	assert.False(t, VerifyWebhookSignatureV2(body, "\r"+header, fixture.Secret))
}

func TestVerifyWebhookSignatureV2NegativeToleranceReturnsFalse(t *testing.T) {
	fixture := readWebhookSignatureV2Fixture(t)
	body := []byte(fixture.Body)
	header := signWebhookV2(body, fixture.Secret, time.Now().Unix())
	require.True(t, VerifyWebhookSignatureV2WithTolerance(body, header, fixture.Secret, time.Minute))
	assert.False(t, VerifyWebhookSignatureV2WithTolerance(body, header, fixture.Secret, -time.Second))
	assert.False(t, VerifyWebhookSignatureV2WithTolerance(body, header, fixture.Secret, -time.Nanosecond))
}

func TestLegacyWebhookSignatureStillVerifiesTheFixture(t *testing.T) {
	fixture := readWebhookSignatureV2Fixture(t)
	body := []byte(fixture.Body)
	assert.True(t, VerifyWebhookSignature(body, fixture.LegacyHeader, fixture.Secret))
	assert.True(t, NewWebhookHandler(fixture.Secret).VerifySignature(body, fixture.LegacyHeader))
	assert.Equal(t, fixture.LegacyHeader, signWebhook(body, fixture.Secret))

	// The two headers are not interchangeable.
	assert.False(t, VerifyWebhookSignature(body, fixture.Header, fixture.Secret))
	assert.False(t, VerifyWebhookSignatureV2WithTolerance(body, fixture.LegacyHeader, fixture.Secret, fixture.fixedVectorTolerance()))
}
