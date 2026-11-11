package kawaa

// The fields the API actually sends survive parsing.
//
// The fixtures in testdata/responses are production response bodies
// (captured 2026-10-01 with test accounts and test addresses). A
// verification's SMTP reply is verification.smtp_message and
// verification.smtp_code; VerificationDetails read smtp_response, which only
// the flat download rows carry, so every single verification and every job
// result row parsed with an empty SMTPResponse.

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readResponseFixture(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(sharedFixture("responses", name))
	require.NoError(t, err)
	return body
}

func TestLiveVerifyResponseKeepsTheSMTPReply(t *testing.T) {
	var envelope struct {
		Data VerificationResult `json:"data"`
	}
	require.NoError(t, json.Unmarshal(readResponseFixture(t, "verify-catch-all.json"), &envelope))
	result := envelope.Data

	assert.Equal(t, StatusCatchAll, result.Status)
	assert.Equal(t, "catch_all", result.SubStatus)
	assert.True(t, result.Flags.Role)
	require.NotNil(t, result.Verification)
	assert.Equal(t, []string{"smtp.google.com"}, result.Verification.MXRecords)
	assert.Equal(t, "250 2.1.5 OK d75a77b69052e-53398dad470si11368041cf.274 - gsmtp", result.Verification.SMTPResponse)
	require.NotNil(t, result.Verification.SMTPCode)
	assert.Equal(t, 250, *result.Verification.SMTPCode)
}

func TestLiveJobResultRowsKeepTheSMTPReply(t *testing.T) {
	var envelope struct {
		Data JobStatusResult `json:"data"`
	}
	require.NoError(t, json.Unmarshal(readResponseFixture(t, "job-completed-with-results.json"), &envelope))
	require.Len(t, envelope.Data.Results, 2)
	disposable, catchAll := envelope.Data.Results[0], envelope.Data.Results[1]

	// No mailbox probe ran for the disposable address: nothing to report.
	require.NotNil(t, disposable.Verification)
	assert.Equal(t, []string{"mail2.mailinator.com", "mail.mailinator.com"}, disposable.Verification.MXRecords)
	assert.Empty(t, disposable.Verification.SMTPResponse)
	assert.Nil(t, disposable.Verification.SMTPCode)

	assert.Equal(t, "catch_all", catchAll.SubStatus)
	require.NotNil(t, catchAll.Verification)
	assert.Equal(t, "250 2.1.5 OK 6a1803df08f44-917edbc1a7fsi7030706d6.537 - gsmtp", catchAll.Verification.SMTPResponse)
	require.NotNil(t, catchAll.Verification.SMTPCode)
	assert.Equal(t, 250, *catchAll.Verification.SMTPCode)
}

// The API states its catch-all finding as verification.catch_all (a flat
// download row: catch_all) and leaves it out when nothing measured it: a
// disposable verdict, no usable mail server, a refused or unanswered mailbox.
// Flags.CatchAll reads that absence as false; CatchAllMeasured tells the two
// apart.
func TestLiveRowsSayWhetherCatchAllWasMeasured(t *testing.T) {
	var single struct {
		Data VerificationResult `json:"data"`
	}
	require.NoError(t, json.Unmarshal(readResponseFixture(t, "verify-catch-all.json"), &single))
	assert.True(t, single.Data.Flags.CatchAll)
	assert.True(t, single.Data.Flags.CatchAllMeasured)

	var job struct {
		Data JobStatusResult `json:"data"`
	}
	require.NoError(t, json.Unmarshal(readResponseFixture(t, "job-completed-with-results.json"), &job))
	require.Len(t, job.Data.Results, 2)
	assert.False(t, job.Data.Results[0].Flags.CatchAll)
	assert.False(t, job.Data.Results[0].Flags.CatchAllMeasured, "the disposable row was never probed")
	assert.True(t, job.Data.Results[1].Flags.CatchAll)
	assert.True(t, job.Data.Results[1].Flags.CatchAllMeasured)

	var download DownloadResult
	require.NoError(t, json.Unmarshal(readResponseFixture(t, "download-json.json"), &download))
	require.Len(t, download.Results, 2)
	assert.False(t, download.Results[0].CatchAll)
	assert.False(t, download.Results[0].CatchAllMeasured, "the disposable row has no catch_all value")
	assert.True(t, download.Results[1].CatchAll)
	assert.True(t, download.Results[1].CatchAllMeasured)
}

func TestCatchAllMeasuredOnlyWhenStated(t *testing.T) {
	cases := []struct {
		name               string
		body               string
		catchAll, measured bool
	}{
		{"stated false", `{"status":"valid","verification":{"smtp_check":true,"catch_all":false}}`, false, true},
		{"stated true", `{"status":"catch_all","verification":{"catch_all":true}}`, true, true},
		{"catch_all status alone", `{"status":"catch_all","verification":{}}`, true, true},
		{"omitted", `{"status":"unknown","verification":{"syntax_valid":true}}`, false, false},
		{"no verification", `{"status":"unknown"}`, false, false},
		{"pending", `{"status":"pending","job_id":"job-1"}`, false, false},
		{"flags false is not a measurement", `{"status":"unknown","flags":{"catch_all":false},"verification":{}}`, false, false},
		{"null", `{"status":"unknown","verification":{"catch_all":null}}`, false, false},
		{"wrong-typed is not stated", `{"status":"unknown","verification":{"catch_all":"no"}}`, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var result VerificationResult
			require.NoError(t, json.Unmarshal([]byte(tc.body), &result))
			assert.Equal(t, tc.catchAll, result.Flags.CatchAll)
			assert.Equal(t, tc.measured, result.Flags.CatchAllMeasured)
		})
	}

	var rows []DownloadRow
	require.NoError(t, json.Unmarshal([]byte(`[
		{"email":"a@example.com","status":"valid","catch_all":false},
		{"email":"b@example.com","status":"unknown"},
		{"email":"c@example.com","status":"catch_all"}
	]`), &rows))
	require.Len(t, rows, 3)
	assert.False(t, rows[0].CatchAll)
	assert.True(t, rows[0].CatchAllMeasured)
	assert.False(t, rows[1].CatchAll)
	assert.False(t, rows[1].CatchAllMeasured)
	assert.True(t, rows[2].CatchAll)
	assert.True(t, rows[2].CatchAllMeasured)
}

func TestAJSONRoundTripKeepsWhatWasMeasured(t *testing.T) {
	cases := []struct {
		body               string
		catchAll, measured bool
	}{
		{`{"email":"a@example.com","status":"unknown","verification":{"syntax_valid":true}}`, false, false},
		{`{"email":"a@example.com","status":"valid","verification":{"smtp_check":true,"catch_all":false}}`, false, true},
		{`{"email":"a@example.com","status":"catch_all","verification":{"catch_all":true}}`, true, true},
	}
	for _, tc := range cases {
		var result VerificationResult
		require.NoError(t, json.Unmarshal([]byte(tc.body), &result))
		written, err := json.Marshal(result)
		require.NoError(t, err)
		var again VerificationResult
		require.NoError(t, json.Unmarshal(written, &again))
		assert.Equal(t, tc.catchAll, again.Flags.CatchAll, string(written))
		assert.Equal(t, tc.measured, again.Flags.CatchAllMeasured, string(written))
	}

	rowCases := []struct {
		body               string
		catchAll, measured bool
	}{
		{`{"email":"a@example.com","status":"unknown"}`, false, false},
		{`{"email":"a@example.com","status":"valid","catch_all":false}`, false, true},
		{`{"email":"a@example.com","status":"catch_all","catch_all":true}`, true, true},
	}
	for _, tc := range rowCases {
		var row DownloadRow
		require.NoError(t, json.Unmarshal([]byte(tc.body), &row))
		written, err := json.Marshal(row)
		require.NoError(t, err)
		var again DownloadRow
		require.NoError(t, json.Unmarshal(written, &again))
		assert.Equal(t, tc.catchAll, again.CatchAll, string(written))
		assert.Equal(t, tc.measured, again.CatchAllMeasured, string(written))
	}
}

func TestWrongTypedSMTPFieldsDoNotFailTheDecode(t *testing.T) {
	var result VerificationResult
	require.NoError(t, json.Unmarshal([]byte(`{"email":"a@example.com","status":"valid","verification":{"smtp_code":"250","smtp_message":250}}`), &result))
	require.NotNil(t, result.Verification)
	assert.Nil(t, result.Verification.SMTPCode)
	assert.Empty(t, result.Verification.SMTPResponse)
}
