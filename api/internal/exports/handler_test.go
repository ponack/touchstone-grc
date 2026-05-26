package exports

import "testing"

func TestParseDetails(t *testing.T) {
	cases := []struct {
		name          string
		raw           string
		wantMessage   string
		wantFailCount int
	}{
		{
			name:          "empty",
			raw:           "",
			wantMessage:   "",
			wantFailCount: 0,
		},
		{
			name:          "happy path with failures",
			raw:           `{"status":"fail","message":"two violations","failures":[{"resource_id":"a"},{"resource_id":"b"}]}`,
			wantMessage:   "two violations",
			wantFailCount: 2,
		},
		{
			name:          "pass with no failures",
			raw:           `{"status":"pass","message":"all good","failures":[]}`,
			wantMessage:   "all good",
			wantFailCount: 0,
		},
		{
			name:          "malformed json tolerated",
			raw:           `{not valid`,
			wantMessage:   "",
			wantFailCount: 0,
		},
		{
			name:          "missing fields",
			raw:           `{"status":"not_applicable"}`,
			wantMessage:   "",
			wantFailCount: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, n := parseDetails([]byte(tc.raw))
			if msg != tc.wantMessage {
				t.Errorf("message = %q, want %q", msg, tc.wantMessage)
			}
			if n != tc.wantFailCount {
				t.Errorf("failuresCount = %d, want %d", n, tc.wantFailCount)
			}
		})
	}
}
