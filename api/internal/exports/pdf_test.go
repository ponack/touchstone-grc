package exports

import (
	"bytes"
	"testing"
	"time"
)

// TestRenderPDF_Smoke exercises the renderer against a representative
// report: one framework with a passing control, a failing control with
// inline failures, and a not_applicable control. The aim is to catch
// layout-code regressions cheaply (panic on bad coordinates, fpdf
// error states, etc). It does not validate visual fidelity — that's
// what humans on review do.
func TestRenderPDF_Smoke(t *testing.T) {
	started := time.Date(2026, 5, 25, 18, 30, 0, 0, time.UTC)
	finished := started.Add(3 * time.Second)

	r := pdfReport{
		OrgName:        "Acme",
		ConnectorName:  "Prod AWS",
		ScanID:         "00000000-0000-0000-0000-000000000001",
		ScanCreated:    started,
		ScanStarted:    &started,
		ScanFinished:   &finished,
		ResourcesCount: 12,
		GeneratedAt:    finished,
		Counts: map[string]int{
			"pass":           1,
			"fail":           1,
			"not_applicable": 1,
		},
		Frameworks: []pdfFramework{
			{
				Code: "soc2_2017", Name: "SOC 2 (2017)", Version: "2017",
				Controls: []pdfControl{
					{Code: "CC6.1", Title: "Logical access", Severity: "high", Status: "pass", Message: "All console users have MFA."},
					{Code: "CC6.3", Title: "Access revocation", Severity: "high", Status: "fail", Message: "1 stale active access key.",
						Failures: []pdfFailure{
							{ResourceType: "aws.iam.user", ResourceID: "arn:aws:iam::1:user/legacy", Reason: "key older than 365 days"},
						}},
					{Code: "CC6.6", Title: "Network access", Severity: "critical", Status: "not_applicable", Message: ""},
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := renderPDF(&buf, r); err != nil {
		t.Fatalf("renderPDF: %v", err)
	}
	if buf.Len() < 1000 {
		t.Fatalf("PDF unexpectedly small: %d bytes", buf.Len())
	}
	// Sanity: PDFs start with %PDF-.
	if !bytes.HasPrefix(buf.Bytes(), []byte("%PDF-")) {
		t.Fatalf("output is not a PDF: starts with %q", buf.Bytes()[:8])
	}
}

func TestParseDetailsFull(t *testing.T) {
	raw := `{
		"status":"fail",
		"message":"two violations",
		"failures":[
			{"resource_type":"aws.iam.user","resource_id":"arn1","reason":"no mfa"},
			{"resource_type":"aws.iam.user","resource_id":"arn2","reason":"no mfa"}
		]
	}`
	msg, failures := parseDetailsFull([]byte(raw))
	if msg != "two violations" {
		t.Fatalf("message: got %q", msg)
	}
	if len(failures) != 2 {
		t.Fatalf("failures: got %d", len(failures))
	}
	if failures[0].ResourceID != "arn1" || failures[1].ResourceID != "arn2" {
		t.Fatalf("failures content drift: %+v", failures)
	}
}

func TestParseDetailsFull_Malformed(t *testing.T) {
	msg, failures := parseDetailsFull([]byte("{not json"))
	if msg != "" || failures != nil {
		t.Fatalf("expected empty results on malformed json")
	}
}
