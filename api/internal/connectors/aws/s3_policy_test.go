package aws

import "testing"

// CIS 2.1.2 requires a Deny statement on aws:SecureTransport=false.
// The parser must catch all three valid Condition shapes IAM accepts.
func TestBucketPolicyEnforcesHTTPSOnly(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want bool
	}{
		{
			name: "single-statement object with string false",
			doc:  `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}}`,
			want: true,
		},
		{
			name: "statement array with bool false",
			doc:  `{"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":false}}}]}`,
			want: true,
		},
		{
			name: "statement array with array false value",
			doc:  `{"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":["false"]}}}]}`,
			want: true,
		},
		{
			name: "Effect Allow does not satisfy CIS",
			doc:  `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`,
			want: false,
		},
		{
			name: "Condition references different key",
			doc:  `{"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"StringEquals":{"aws:Username":"alice"}}}]}`,
			want: false,
		},
		{
			name: "SecureTransport true (the wrong polarity)",
			doc:  `{"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`,
			want: false,
		},
		{
			name: "mixed statements — one matching among allows",
			doc:  `{"Statement":[{"Effect":"Allow","Action":"s3:Get*","Resource":"*"},{"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`,
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := bucketPolicyEnforcesHTTPSOnly([]byte(tc.doc))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
