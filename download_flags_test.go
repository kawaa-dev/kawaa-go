package kawaa

// Download rows carry three risk flags, and a new reason code passes through.
//
// The download gained abuse_email, complainer and bot_generated as its last
// columns (after email_unicode). A result stored without them gets an empty
// CSV cell and no JSON key, so a row that does not state a flag must leave it
// nil, never false. There is no honeypot column. The API also added the
// reason ip_address_mx (risky: a mailbox accepted at an MX record that names
// an IP address); SubStatus is an open string.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const flagsJobID = "2e31e0ec-c747-4aec-9b37-1a24c184ee7b"

func flagsRow(extra string) string {
	return `{"email": "abuse@example.org", "status": "valid", "score": 40, "disposable": false, "role": true,
		"free_provider": false, "suggestion": null, "mx_records": ["mx.example.org"], "smtp_response": "250 2.1.5 OK",
		"verified_at": "2026-11-18T02:56:58.165Z", "sub_status": "mailbox_exists", "email_unicode": "abuse@example.org"` + extra + `}`
}

func decodeRow(t *testing.T, body string) DownloadRow {
	t.Helper()
	var row DownloadRow
	require.NoError(t, json.Unmarshal([]byte(body), &row))
	return row
}

func TestDownloadRowCarriesTheThreeRiskFlags(t *testing.T) {
	row := decodeRow(t, flagsRow(`, "abuse_email": true, "complainer": false, "bot_generated": false`))

	require.NotNil(t, row.AbuseEmail)
	require.NotNil(t, row.Complainer)
	require.NotNil(t, row.BotGenerated)
	assert.True(t, *row.AbuseEmail)
	assert.False(t, *row.Complainer)
	assert.False(t, *row.BotGenerated)
}

func TestDownloadRowLeavesAnUnstatedOrWrongTypedFlagNil(t *testing.T) {
	for _, extra := range []string{
		``,
		`, "abuse_email": null, "complainer": null, "bot_generated": null`,
		`, "abuse_email": "true", "complainer": 1, "bot_generated": "no"`,
	} {
		row := decodeRow(t, flagsRow(extra))
		assert.Nil(t, row.AbuseEmail, extra)
		assert.Nil(t, row.Complainer, extra)
		assert.Nil(t, row.BotGenerated, extra)
	}
}

func TestDownloadRowRoundTripKeepsStatedAndUnstatedFlags(t *testing.T) {
	stated := decodeRow(t, flagsRow(`, "abuse_email": true, "complainer": false, "bot_generated": false`))
	encoded, err := json.Marshal(stated)
	require.NoError(t, err)
	again := decodeRow(t, string(encoded))
	require.NotNil(t, again.Complainer)
	assert.False(t, *again.Complainer)
	assert.True(t, *again.AbuseEmail)

	unstated := decodeRow(t, flagsRow(``))
	encoded, err = json.Marshal(unstated)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "abuse_email")
	assert.Nil(t, decodeRow(t, string(encoded)).BotGenerated)
}

func TestDownloadResultsCarryTheFlagsAndTheNewReason(t *testing.T) {
	body := `{"job_id": "` + flagsJobID + `", "status": "completed", "result_count": 2, "complete": true,
		"expected_rows": 2, "rows_missing": 0, "results": [` +
		flagsRow(`, "abuse_email": true, "complainer": true, "bot_generated": false`) + `, ` +
		`{"email": "user@example.org", "status": "risky", "score": 40, "disposable": false, "role": false,
		  "free_provider": false, "sub_status": "ip_address_mx", "email_unicode": "user@example.org"}]}`
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer api.Close()
	client := NewClient("test-api-key", WithBaseURL(api.URL))

	download, err := client.DownloadResults(context.Background(), flagsJobID)

	require.NoError(t, err)
	require.Len(t, download.Results, 2)
	assert.True(t, *download.Results[0].Complainer)
	assert.Equal(t, VerificationStatus("risky"), download.Results[1].Status)
	assert.Equal(t, "ip_address_mx", download.Results[1].SubStatus)
	assert.Nil(t, download.Results[1].AbuseEmail)
}

func TestIPAddressMXPassesThroughOnAVerification(t *testing.T) {
	var result VerificationResult
	require.NoError(t, json.Unmarshal([]byte(`{"email": "user@example.org", "status": "risky", "sub_status": "ip_address_mx",
		"quality_score": 40, "flags": {"disposable": false, "role_account": false, "free_provider": false},
		"verification": {"syntax_valid": true, "domain_exists": true, "mx_found": true}}`), &result))

	assert.Equal(t, VerificationStatus("risky"), result.Status)
	assert.Equal(t, "ip_address_mx", result.SubStatus)
}
