package kawaa

// email_unicode reaches the caller.
//
// The API checks an address with an internationalized domain in its ASCII
// form, and every job result row and download row says so in email
// ("info@xn--mller-kva.de"). Since November 17, 2026 each row also carries
// email_unicode, the same address written back in Unicode ("info@müller.de"),
// which is what a caller matches a row to its own list by. Up to v0.3.2 the
// client dropped it.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const idnJobID = "2e31e0ec-c747-4aec-9b37-1a24c184ee7b"

// A GET /v1/jobs/{id}?include_results=true body in the API's shape.
const idnJobWithResults = `{"success": true, "data": {
	"job_id": "2e31e0ec-c747-4aec-9b37-1a24c184ee7b",
	"status": "completed",
	"total_emails": 2,
	"processed_emails": 2,
	"progress_percent": 100,
	"summary": {"valid": 0, "invalid": 2, "risky": 0, "unknown": 0},
	"results": [
		{"job_id": "2e31e0ec-c747-4aec-9b37-1a24c184ee7b", "email": "info@xn--mller-kva.de", "email_unicode": "info@müller.de",
		 "status": "invalid", "sub_status": "no_mx", "quality_score": 10,
		 "flags": {"disposable": false, "role_account": true, "free_provider": false},
		 "verification": {"syntax_valid": true, "domain_exists": true, "mx_found": false},
		 "verified_at": "2026-11-18T02:56:58.165Z", "from_cache": false},
		{"job_id": "2e31e0ec-c747-4aec-9b37-1a24c184ee7b", "email": "a@example.com", "email_unicode": "a@example.com",
		 "status": "invalid", "sub_status": "no_mx", "quality_score": 10,
		 "verified_at": "2026-11-18T02:56:58.165Z", "from_cache": false}
	],
	"next_key": null,
	"has_more": false
}}`

// A GET /v1/jobs/{id}/download?format=json body in the API's shape.
const idnDownload = `{
	"job_id": "2e31e0ec-c747-4aec-9b37-1a24c184ee7b",
	"status": "completed",
	"result_count": 1,
	"complete": true,
	"expected_rows": 1,
	"rows_missing": 0,
	"results": [
		{"email": "info@xn--mller-kva.de", "status": "invalid", "score": 10, "disposable": false, "role": true,
		 "free_provider": false, "suggestion": null, "mx_records": [], "smtp_response": null,
		 "verified_at": "2026-11-18T02:56:58.165Z", "sub_status": "no_mx", "email_unicode": "info@müller.de"}
	]
}`

func serveJSON(t *testing.T, routes map[string]string) *Client {
	t.Helper()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(api.Close)
	return NewClient("test-api-key", WithBaseURL(api.URL))
}

func TestJobResultRowsCarryEmailUnicode(t *testing.T) {
	client := serveJSON(t, map[string]string{"/v1/jobs/" + idnJobID: idnJobWithResults})

	job, err := client.GetJobStatus(context.Background(), idnJobID, true)

	require.NoError(t, err)
	require.Len(t, job.Results, 2)
	assert.Equal(t, "info@xn--mller-kva.de", job.Results[0].Email)
	assert.Equal(t, "info@müller.de", job.Results[0].EmailUnicode)
	assert.Equal(t, "a@example.com", job.Results[1].EmailUnicode)
}

func TestDownloadRowsCarryEmailUnicode(t *testing.T) {
	client := serveJSON(t, map[string]string{"/v1/jobs/" + idnJobID + "/download": idnDownload})

	download, err := client.DownloadResults(context.Background(), idnJobID)

	require.NoError(t, err)
	require.Len(t, download.Results, 1)
	assert.Equal(t, "info@xn--mller-kva.de", download.Results[0].Email)
	assert.Equal(t, "info@müller.de", download.Results[0].EmailUnicode)
	assert.Equal(t, "no_mx", download.Results[0].SubStatus)
}

func TestEmailUnicodeThatIsMissingOrNotAStringIsEmpty(t *testing.T) {
	for _, value := range []string{``, `, "email_unicode": null`, `, "email_unicode": 7`, `, "email_unicode": ["x"]`} {
		var row VerificationResult
		require.NoError(t, json.Unmarshal([]byte(`{"email": "info@xn--mller-kva.de", "status": "invalid"`+value+`}`), &row), value)
		assert.Equal(t, "", row.EmailUnicode, value)

		var flat DownloadRow
		require.NoError(t, json.Unmarshal([]byte(`{"email": "info@xn--mller-kva.de", "status": "invalid", "score": 10`+value+`}`), &flat), value)
		assert.Equal(t, "", flat.EmailUnicode, value)
	}
}

func TestDownloadRowRoundTripKeepsEmailUnicode(t *testing.T) {
	var row DownloadRow
	require.NoError(t, json.Unmarshal([]byte(`{"email": "info@xn--mller-kva.de", "status": "invalid", "score": 10, "email_unicode": "info@müller.de"}`), &row))

	encoded, err := json.Marshal(row)
	require.NoError(t, err)
	var again DownloadRow
	require.NoError(t, json.Unmarshal(encoded, &again))

	assert.Equal(t, "info@müller.de", again.EmailUnicode)
}
