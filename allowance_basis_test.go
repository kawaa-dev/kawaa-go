package kawaa

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GET /v1/account calls the allowance monthly_allowance and the spend
// used_this_month on every plan, and says in credits.allowance_basis whether
// either renews. On Free it is a one-time grant that nothing resets. The
// client dropped the field, so a Free account read as "66 of 100 used this
// month" with a refill to come. These are the shapes production returned on
// 2026-10-01.

func TestGetAccountReportsAOneTimeGrant(t *testing.T) {
	client := envelopeServer(t, `{
		"account": {"user_id": "usr_free", "email": "free@example.com", "plan": "free", "status": "active", "created_at": "2026-09-01T00:00:00.000Z"},
		"credits": {"balance": 34, "used_this_month": 66, "monthly_allowance": 100, "allowance_basis": "one_time_grant"}
	}`)

	account, err := client.GetAccount(context.Background())
	require.NoError(t, err)
	assert.Equal(t, AllowanceOneTimeGrant, account.AllowanceBasis)
	assert.Equal(t, 100.0, account.MonthlyAllowance)
	assert.Equal(t, "", account.NextReset)
}

func TestAllowanceBasisCases(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    AllowanceBasis
	}{
		{
			name:    "a renewing allowance",
			payload: `{"account": {"plan": "starter"}, "credits": {"balance": 4000, "used_this_month": 1000, "monthly_allowance": 5000, "next_reset": "2026-10-15T00:00:00.000Z", "allowance_basis": "billing_period"}}`,
			want:    AllowanceBillingPeriod,
		},
		{
			name:    "a paid plan with no billing period on file",
			payload: `{"account": {"plan": "enterprise"}, "credits": {"balance": 122.75, "used_this_month": 876.75, "monthly_allowance": 500000, "allowance_basis": "no_billing_period"}}`,
			want:    AllowanceNoBillingPeriod,
		},
		{
			// No allowance_basis and no monthly_allowance on a sub-account:
			// its plan says what the allowance is.
			name:    "a sub-account",
			payload: `{"account": {"plan": "sub_account"}, "credits": {"balance": 18.5, "credits_used": 31.5, "allocated": 50}}`,
			want:    AllowanceProviderAllocation,
		},
		{
			name:    "no basis reported is unknown, not renewing",
			payload: `{"account": {"plan": "starter"}, "credits": {"balance": 10, "used_this_month": 0, "monthly_allowance": 5000}}`,
			want:    "",
		},
		{
			name:    "a basis this release does not name is passed through",
			payload: `{"account": {"plan": "starter"}, "credits": {"balance": 10, "monthly_allowance": 5000, "allowance_basis": "seasonal"}}`,
			want:    AllowanceBasis("seasonal"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var account AccountInfo
			require.NoError(t, json.Unmarshal([]byte(tc.payload), &account))
			assert.Equal(t, tc.want, account.AllowanceBasis)
		})
	}
}
