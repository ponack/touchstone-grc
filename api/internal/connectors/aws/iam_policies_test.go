package aws

import "testing"

// Mostly-exhaustive matrix over Action / Resource shapes. CIS 1.16
// admin = Effect Allow AND Action contains "*" AND Resource contains
// "*" — anything narrower passes.
func TestDocumentAllowsAdmin(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want bool
	}{
		{
			name: "single statement object full admin",
			doc:  `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`,
			want: true,
		},
		{
			name: "statement array full admin",
			doc:  `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
			want: true,
		},
		{
			name: "array Action and Resource each containing *",
			doc:  `{"Statement":[{"Effect":"Allow","Action":["s3:Get*","*"],"Resource":["arn:aws:s3:::x","*"]}]}`,
			want: true,
		},
		{
			name: "Action is * but Resource is bucket-specific",
			doc:  `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::important-bucket/*"}]}`,
			want: false,
		},
		{
			name: "Action is s3:* but Resource is *",
			doc:  `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`,
			want: false,
		},
		{
			name: "Effect Deny does not count even with *:*",
			doc:  `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`,
			want: false,
		},
		{
			name: "mixed statements — one admin one not",
			doc:  `{"Statement":[{"Effect":"Allow","Action":"s3:Get*","Resource":"*"},{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := documentAllowsAdmin([]byte(tc.doc))
			if err != nil {
				t.Fatalf("documentAllowsAdmin: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
