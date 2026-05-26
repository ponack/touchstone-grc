// Package exports renders evidence in auditor-friendly formats.
//
// Endpoints:
//
//	GET /api/v1/scans/:id/export.csv  — point-in-time CSV for one scan
//	GET /api/v1/scans/:id/export.pdf  — auditor-grade PDF for one scan
//	GET /api/v1/exports/latest.csv    — most recent evidence per control
//	                                    across enabled frameworks for the org
package exports

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"

	"github.com/ponack/touchstone/internal/auth"
)

type Handler struct {
	pool *pgxpool.Pool
}

func NewHandler(pool *pgxpool.Pool) *Handler {
	return &Handler{pool: pool}
}

// Register wires the export routes under the existing protected v1
// group so auth + org-scoping apply.
func (h *Handler) Register(g *echo.Group) {
	g.GET("/scans/:id/export.csv", h.ScanCSV)
	g.GET("/scans/:id/export.pdf", h.ScanPDF)
	g.GET("/exports/latest.csv", h.LatestCSV)
}

// ── Single-scan CSV ──────────────────────────────────────────────────────────

type evidenceRow struct {
	framework     string
	controlCode   string
	controlTitle  string
	severity      string
	status        string
	message       string
	failuresCount int
	collectedAt   time.Time
	scanID        string // populated only for latest CSV
}

func (h *Handler) ScanCSV(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	scanID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}

	if err := h.requireScanInOrg(c.Request().Context(), orgID, scanID); err != nil {
		return err
	}

	rows, err := h.loadScanRows(c.Request().Context(), orgID, scanID)
	if err != nil {
		return err
	}

	res := c.Response()
	res.Header().Set("Content-Type", "text/csv; charset=utf-8")
	res.Header().Set(
		"Content-Disposition",
		fmt.Sprintf(`attachment; filename="touchstone-scan-%s.csv"`, scanID.String()),
	)
	res.WriteHeader(http.StatusOK)

	return writeCSV(res.Writer, rows, false)
}

// ── Single-scan PDF ──────────────────────────────────────────────────────────

func (h *Handler) ScanPDF(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)
	scanID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}

	if err := h.requireScanInOrg(c.Request().Context(), orgID, scanID); err != nil {
		return err
	}

	report, err := h.buildPDFReport(c.Request().Context(), orgID, scanID)
	if err != nil {
		return err
	}

	res := c.Response()
	res.Header().Set("Content-Type", "application/pdf")
	res.Header().Set(
		"Content-Disposition",
		fmt.Sprintf(`attachment; filename="touchstone-scan-%s.pdf"`, scanID.String()),
	)
	res.WriteHeader(http.StatusOK)
	return renderPDF(res.Writer, report)
}

// ── Latest-per-control CSV across enabled frameworks ─────────────────────────

func (h *Handler) LatestCSV(c echo.Context) error {
	orgID := c.Get(auth.ContextOrgID).(uuid.UUID)

	rows, err := h.loadLatestRows(c.Request().Context(), orgID)
	if err != nil {
		return err
	}

	res := c.Response()
	res.Header().Set("Content-Type", "text/csv; charset=utf-8")
	res.Header().Set(
		"Content-Disposition",
		fmt.Sprintf(`attachment; filename="touchstone-latest-%s.csv"`, time.Now().UTC().Format("2006-01-02")),
	)
	res.WriteHeader(http.StatusOK)
	return writeCSV(res.Writer, rows, true)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func (h *Handler) requireScanInOrg(ctx context.Context, orgID, scanID uuid.UUID) error {
	var exists bool
	if err := h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM scans WHERE id = $1 AND org_id = $2)`,
		scanID, orgID,
	).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return echo.NewHTTPError(http.StatusNotFound, "scan not found")
	}
	return nil
}

func (h *Handler) loadScanRows(ctx context.Context, orgID, scanID uuid.UUID) ([]evidenceRow, error) {
	q, err := h.pool.Query(ctx, `
		SELECT f.code, c.code, c.title, c.severity, e.status, e.details, e.collected_at
		FROM evidence_items e
		JOIN controls c   ON c.id = e.control_id
		JOIN frameworks f ON f.id = c.framework_id
		WHERE e.org_id = $1 AND e.scan_id = $2
		ORDER BY f.code, c.code
	`, orgID, scanID)
	if err != nil {
		return nil, err
	}
	defer q.Close()

	out := []evidenceRow{}
	for q.Next() {
		var r evidenceRow
		var details []byte
		if err := q.Scan(&r.framework, &r.controlCode, &r.controlTitle, &r.severity, &r.status, &details, &r.collectedAt); err != nil {
			return nil, err
		}
		r.message, _ = parseDetails(details)
		_, n := parseDetails(details)
		r.failuresCount = n
		out = append(out, r)
	}
	return out, q.Err()
}

// loadLatestRows returns the most recent evidence row per control, scoped
// to frameworks the org has enabled. DISTINCT ON (control_id) keeps the
// query a single sequential pass.
func (h *Handler) loadLatestRows(ctx context.Context, orgID uuid.UUID) ([]evidenceRow, error) {
	q, err := h.pool.Query(ctx, `
		SELECT DISTINCT ON (e.control_id)
		       f.code, c.code, c.title, c.severity, e.status, e.details, e.collected_at, e.scan_id
		FROM evidence_items e
		JOIN controls c        ON c.id = e.control_id
		JOIN frameworks f      ON f.id = c.framework_id
		JOIN org_frameworks of ON of.framework_id = f.id AND of.org_id = e.org_id
		WHERE e.org_id = $1
		ORDER BY e.control_id, e.collected_at DESC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer q.Close()

	out := []evidenceRow{}
	for q.Next() {
		var r evidenceRow
		var details []byte
		var scanID uuid.UUID
		if err := q.Scan(&r.framework, &r.controlCode, &r.controlTitle, &r.severity, &r.status, &details, &r.collectedAt, &scanID); err != nil {
			return nil, err
		}
		r.message, r.failuresCount = parseDetails(details)
		r.scanID = scanID.String()
		out = append(out, r)
	}
	return out, q.Err()
}

func writeCSV(w interface{ Write(p []byte) (int, error) }, rows []evidenceRow, includeScanID bool) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	header := []string{
		"framework_code",
		"control_code",
		"control_title",
		"severity",
		"status",
		"message",
		"failures_count",
		"collected_at",
	}
	if includeScanID {
		header = append(header, "scan_id")
	}
	if err := cw.Write(header); err != nil {
		return err
	}

	for _, r := range rows {
		row := []string{
			r.framework,
			r.controlCode,
			r.controlTitle,
			r.severity,
			r.status,
			r.message,
			fmt.Sprintf("%d", r.failuresCount),
			r.collectedAt.UTC().Format(time.RFC3339),
		}
		if includeScanID {
			row = append(row, r.scanID)
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	return nil
}

// buildPDFReport assembles the input bundle the PDF renderer wants:
// org name, connector name, scan timing, summary counts, evidence
// grouped by framework with parsed OPA decision details.
func (h *Handler) buildPDFReport(ctx context.Context, orgID, scanID uuid.UUID) (pdfReport, error) {
	r := pdfReport{
		ScanID:      scanID.String(),
		GeneratedAt: time.Now(),
		Counts:      map[string]int{},
	}

	// Org + connector + scan metadata in one round-trip.
	err := h.pool.QueryRow(ctx, `
		SELECT o.name, conn.name, s.created_at, s.started_at, s.finished_at, s.resources_count
		FROM scans s
		JOIN organizations o   ON o.id = s.org_id
		JOIN connectors    conn ON conn.id = s.connector_id
		WHERE s.id = $1 AND s.org_id = $2
	`, scanID, orgID).Scan(
		&r.OrgName, &r.ConnectorName,
		&r.ScanCreated, &r.ScanStarted, &r.ScanFinished, &r.ResourcesCount,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, echo.NewHTTPError(http.StatusNotFound, "scan not found")
	}
	if err != nil {
		return r, err
	}

	// Evidence with framework + control, ordered to be naturally groupable.
	rows, err := h.pool.Query(ctx, `
		SELECT f.code, f.name, f.version,
		       c.code, c.title, c.severity,
		       e.status, e.details
		FROM evidence_items e
		JOIN controls c   ON c.id = e.control_id
		JOIN frameworks f ON f.id = c.framework_id
		WHERE e.org_id = $1 AND e.scan_id = $2
		ORDER BY f.code, c.code
	`, orgID, scanID)
	if err != nil {
		return r, err
	}
	defer rows.Close()

	byFramework := map[string]*pdfFramework{}
	var order []string
	for rows.Next() {
		var fwCode, fwName string
		var fwVersion *string
		var ctlCode, ctlTitle, severity, status string
		var details []byte
		if err := rows.Scan(&fwCode, &fwName, &fwVersion, &ctlCode, &ctlTitle, &severity, &status, &details); err != nil {
			return r, err
		}
		fw, ok := byFramework[fwCode]
		if !ok {
			fw = &pdfFramework{Code: fwCode, Name: fwName}
			if fwVersion != nil {
				fw.Version = *fwVersion
			}
			byFramework[fwCode] = fw
			order = append(order, fwCode)
		}
		message, failures := parseDetailsFull(details)
		fw.Controls = append(fw.Controls, pdfControl{
			Code:     ctlCode,
			Title:    ctlTitle,
			Severity: severity,
			Status:   status,
			Message:  message,
			Failures: failures,
		})
		r.Counts[status]++
	}
	if err := rows.Err(); err != nil {
		return r, err
	}
	for _, code := range order {
		r.Frameworks = append(r.Frameworks, *byFramework[code])
	}
	return r, nil
}

// parseDetails extracts the human-readable message and the failures
// count from a stored OPA decision. Tolerates any shape — a malformed
// details JSON does not break export.
func parseDetails(raw []byte) (string, int) {
	if len(raw) == 0 {
		return "", 0
	}
	var d struct {
		Message  string           `json:"message"`
		Failures []map[string]any `json:"failures"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return "", 0
	}
	return d.Message, len(d.Failures)
}

// parseDetailsFull is the PDF variant — it preserves each failure's
// resource_type / resource_id / reason so the report can render them.
func parseDetailsFull(raw []byte) (string, []pdfFailure) {
	if len(raw) == 0 {
		return "", nil
	}
	var d struct {
		Message  string `json:"message"`
		Failures []struct {
			ResourceType string `json:"resource_type"`
			ResourceID   string `json:"resource_id"`
			Reason       string `json:"reason"`
		} `json:"failures"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return "", nil
	}
	out := make([]pdfFailure, 0, len(d.Failures))
	for _, f := range d.Failures {
		out = append(out, pdfFailure{
			ResourceType: f.ResourceType,
			ResourceID:   f.ResourceID,
			Reason:       f.Reason,
		})
	}
	return d.Message, out
}
