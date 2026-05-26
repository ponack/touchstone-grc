package exports

import (
	"fmt"
	"io"
	"time"

	"github.com/go-pdf/fpdf"
)

// PDF layout constants.
const (
	pageMarginMM = 20.0
	contentWidth = 210.0 - 2*pageMarginMM // A4 portrait
)

// pdfReport is the input bundle the PDF renderer consumes. Caller
// fills these in from the database; the renderer is a pure function
// over this struct so it stays trivially testable.
type pdfReport struct {
	OrgName        string
	ConnectorName  string
	ScanID         string
	ScanCreated    time.Time
	ScanStarted    *time.Time
	ScanFinished   *time.Time
	ResourcesCount int
	GeneratedAt    time.Time
	Counts         map[string]int // pass/fail/partial/not_applicable/error
	Frameworks     []pdfFramework
}

type pdfFramework struct {
	Code     string
	Name     string
	Version  string
	Controls []pdfControl
}

type pdfControl struct {
	Code     string
	Title    string
	Severity string
	Status   string
	Message  string
	Failures []pdfFailure
}

type pdfFailure struct {
	ResourceType string
	ResourceID   string
	Reason       string
}

// renderPDF writes a compliance evidence report to w.
func renderPDF(w io.Writer, r pdfReport) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(pageMarginMM, pageMarginMM, pageMarginMM)
	pdf.SetAutoPageBreak(true, pageMarginMM)
	pdf.AliasNbPages("")
	pdf.SetFooterFunc(func() { drawFooter(pdf, r.GeneratedAt) })

	drawCover(pdf, r)
	for _, fw := range r.Frameworks {
		drawFrameworkSection(pdf, fw)
	}
	if hasFailures(r.Frameworks) {
		drawFailuresSection(pdf, r.Frameworks)
	}

	return pdf.Output(w)
}

func drawCover(pdf *fpdf.Fpdf, r pdfReport) {
	pdf.AddPage()

	// Brand bar across the top.
	pdf.SetFillColor(196, 144, 32) // brand gold
	pdf.Rect(0, 0, 210, 6, "F")

	pdf.Ln(20)
	setTextDark(pdf)
	pdf.SetFont("Helvetica", "B", 28)
	pdf.Cell(contentWidth, 12, "Touchstone GRC")

	pdf.Ln(14)
	pdf.SetFont("Helvetica", "", 16)
	pdf.SetTextColor(120, 120, 120)
	pdf.Cell(contentWidth, 10, "Compliance Evidence Report")

	pdf.Ln(20)
	setTextDark(pdf)
	pdf.SetFont("Helvetica", "B", 11)

	rows := [][2]string{
		{"Organization", emptyDash(r.OrgName)},
		{"Connector", emptyDash(r.ConnectorName)},
		{"Scan ID", r.ScanID},
		{"Scan started", fmtTime(r.ScanStarted)},
		{"Scan finished", fmtTime(r.ScanFinished)},
		{"Resources scanned", fmt.Sprintf("%d", r.ResourcesCount)},
		{"Report generated", r.GeneratedAt.UTC().Format("2006-01-02 15:04:05 UTC")},
	}
	for _, row := range rows {
		pdf.SetFont("Helvetica", "B", 10)
		pdf.SetTextColor(110, 110, 110)
		pdf.CellFormat(45, 7, row[0], "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 10)
		setTextDark(pdf)
		pdf.CellFormat(contentWidth-45, 7, row[1], "", 0, "L", false, 0, "")
		pdf.Ln(7)
	}

	// Summary card.
	pdf.Ln(8)
	pdf.SetFont("Helvetica", "B", 12)
	setTextDark(pdf)
	pdf.Cell(contentWidth, 8, "Summary")
	pdf.Ln(10)

	statuses := []struct {
		key, label string
		r, g, b    int
	}{
		{"pass", "Pass", 34, 197, 94},
		{"fail", "Fail", 239, 68, 68},
		{"partial", "Partial", 245, 158, 11},
		{"not_applicable", "N/A", 120, 120, 120},
		{"error", "Error", 220, 38, 38},
	}
	colWidth := contentWidth / float64(len(statuses))
	for _, s := range statuses {
		pdf.SetFillColor(s.r, s.g, s.b)
		pdf.SetTextColor(255, 255, 255)
		pdf.SetFont("Helvetica", "B", 16)
		pdf.CellFormat(colWidth, 10, fmt.Sprintf("%d", r.Counts[s.key]), "", 0, "C", true, 0, "")
	}
	pdf.Ln(10)
	for _, s := range statuses {
		pdf.SetFillColor(240, 240, 240)
		pdf.SetTextColor(60, 60, 60)
		pdf.SetFont("Helvetica", "", 9)
		pdf.CellFormat(colWidth, 7, s.label, "", 0, "C", true, 0, "")
	}
	pdf.Ln(7)
}

func drawFrameworkSection(pdf *fpdf.Fpdf, fw pdfFramework) {
	pdf.AddPage()
	setTextDark(pdf)
	pdf.SetFont("Helvetica", "B", 18)
	title := fw.Name
	if title == "" {
		title = fw.Code
	}
	pdf.Cell(contentWidth, 10, title)
	pdf.Ln(8)
	if fw.Version != "" {
		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(120, 120, 120)
		pdf.Cell(contentWidth, 5, "version "+fw.Version)
		pdf.Ln(8)
	}

	// Table header.
	pdf.SetFillColor(245, 245, 245)
	pdf.SetTextColor(60, 60, 60)
	pdf.SetFont("Helvetica", "B", 9)
	pdf.CellFormat(22, 7, "Code", "", 0, "L", true, 0, "")
	pdf.CellFormat(80, 7, "Title", "", 0, "L", true, 0, "")
	pdf.CellFormat(22, 7, "Severity", "", 0, "L", true, 0, "")
	pdf.CellFormat(25, 7, "Status", "", 0, "L", true, 0, "")
	pdf.CellFormat(contentWidth-22-80-22-25, 7, "Message", "", 0, "L", true, 0, "")
	pdf.Ln(7)

	// Rows.
	pdf.SetFont("Helvetica", "", 9)
	for _, c := range fw.Controls {
		setTextDark(pdf)
		pdf.SetFont("Helvetica", "B", 9)
		pdf.CellFormat(22, 6, c.Code, "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 9)
		pdf.CellFormat(80, 6, truncate(c.Title, 55), "", 0, "L", false, 0, "")
		pdf.SetTextColor(110, 110, 110)
		pdf.CellFormat(22, 6, c.Severity, "", 0, "L", false, 0, "")
		drawStatusCell(pdf, c.Status, 25)
		pdf.SetTextColor(60, 60, 60)
		pdf.MultiCell(contentWidth-22-80-22-25, 5, c.Message, "", "L", false)
		// Row separator.
		pdf.SetDrawColor(230, 230, 230)
		pdf.Line(pageMarginMM, pdf.GetY()+1, pageMarginMM+contentWidth, pdf.GetY()+1)
		pdf.Ln(2)
	}
}

func drawFailuresSection(pdf *fpdf.Fpdf, frameworks []pdfFramework) {
	pdf.AddPage()
	setTextDark(pdf)
	pdf.SetFont("Helvetica", "B", 18)
	pdf.Cell(contentWidth, 10, "Failures")
	pdf.Ln(12)

	for _, fw := range frameworks {
		for _, c := range fw.Controls {
			if c.Status != "fail" && c.Status != "error" {
				continue
			}
			if len(c.Failures) == 0 && c.Message == "" {
				continue
			}

			setTextDark(pdf)
			pdf.SetFont("Helvetica", "B", 11)
			pdf.Cell(contentWidth, 7, fmt.Sprintf("%s / %s — %s", fw.Code, c.Code, c.Title))
			pdf.Ln(6)

			if c.Message != "" {
				pdf.SetTextColor(110, 110, 110)
				pdf.SetFont("Helvetica", "", 9)
				pdf.MultiCell(contentWidth, 5, c.Message, "", "L", false)
			}

			for _, f := range c.Failures {
				pdf.SetTextColor(239, 68, 68)
				pdf.SetFont("Helvetica", "B", 9)
				pdf.MultiCell(contentWidth, 5, "• "+f.Reason, "", "L", false)
				if f.ResourceID != "" {
					pdf.SetTextColor(140, 140, 140)
					pdf.SetFont("Helvetica", "", 8)
					rt := f.ResourceType
					if rt == "" {
						rt = "resource"
					}
					pdf.MultiCell(contentWidth, 4.5, "  "+rt+": "+f.ResourceID, "", "L", false)
				}
			}

			pdf.Ln(4)
		}
	}
}

func drawFooter(pdf *fpdf.Fpdf, generated time.Time) {
	pdf.SetY(-14)
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetTextColor(150, 150, 150)
	pdf.CellFormat(
		contentWidth, 5,
		fmt.Sprintf("Touchstone GRC · Page %d / {nb} · Generated %s",
			pdf.PageNo(), generated.UTC().Format("2006-01-02")),
		"", 0, "C", false, 0, "",
	)
}

func drawStatusCell(pdf *fpdf.Fpdf, status string, w float64) {
	r, g, b := 120, 120, 120
	switch status {
	case "pass":
		r, g, b = 34, 197, 94
	case "fail", "error":
		r, g, b = 239, 68, 68
	case "partial":
		r, g, b = 245, 158, 11
	}
	pdf.SetFillColor(r, g, b)
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 8)
	pdf.CellFormat(w-4, 4.5, status, "", 0, "C", true, 0, "")
	pdf.SetX(pageMarginMM + 22 + 80 + 22 + 25)
}

func setTextDark(pdf *fpdf.Fpdf) { pdf.SetTextColor(35, 35, 35) }

func fmtTime(t *time.Time) string {
	if t == nil {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

func emptyDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func hasFailures(frameworks []pdfFramework) bool {
	for _, fw := range frameworks {
		for _, c := range fw.Controls {
			if c.Status == "fail" || c.Status == "error" {
				return true
			}
		}
	}
	return false
}
