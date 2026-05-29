package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2/google"

	"github.com/ponack/touchstone/internal/connectors"
)

const (
	loggingHost      = "https://logging.googleapis.com"
	loggingReadScope = "https://www.googleapis.com/auth/logging.read"
	sinksPath        = "/v2/projects/%s/sinks"
	sinksPageSize    = 200
)

// scanLogging enumerates Cloud Logging sinks for the project and
// emits one gcp.logging.sink resource per non-default, enabled sink
// — the durable-export surface CC7.2 asks about. The built-in
// _Default and _Required sinks always exist and only write to the
// in-project Logging bucket, so they don't count as durable exports.
//
// Each sink resource carries two derived booleans the rego uses
// directly: captures_admin_activity (filter empty or mentions the
// cloudaudit log family) and is_durable_export (destination is
// BigQuery, GCS, or Pub/Sub).
//
// Required role: roles/logging.viewer (project-scoped).
func scanLogging(ctx context.Context, cfg PublicConfig, sec Secret) ([]connectors.Resource, error) {
	jwtCfg, err := google.JWTConfigFromJSON([]byte(sec.ServiceAccountKeyJSON), loggingReadScope)
	if err != nil {
		return nil, fmt.Errorf("gcp: parse SA key for logging client: %w", err)
	}
	client := jwtCfg.Client(ctx)
	client.Timeout = 60 * time.Second

	sinks, err := listSinks(ctx, client, cfg.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("logging sinks.list: %w", err)
	}

	out := make([]connectors.Resource, 0, len(sinks))
	for _, s := range sinks {
		if s.Disabled {
			continue
		}
		if isBuiltinSinkName(s.Name) {
			continue
		}
		out = append(out, buildSinkResource(s, cfg.ProjectID))
	}

	slog.Info("gcp logging scan complete", "exported_sinks", len(out), "project", cfg.ProjectID)
	return out, nil
}

// ── Internals ───────────────────────────────────────────────────────

type sink struct {
	Name        string `json:"name"`
	Destination string `json:"destination"`
	Filter      string `json:"filter"`
	Disabled    bool   `json:"disabled"`
}

type sinksPage struct {
	Sinks         []sink `json:"sinks"`
	NextPageToken string `json:"nextPageToken"`
}

func listSinks(ctx context.Context, client *http.Client, projectID string) ([]sink, error) {
	base := fmt.Sprintf(loggingHost+sinksPath+"?pageSize=%d", projectID, sinksPageSize)
	var out []sink
	next := ""
	for {
		url := base
		if next != "" {
			url = base + "&pageToken=" + next
		}
		body, err := gcpGET(ctx, client, url)
		if err != nil {
			return out, err
		}
		var page sinksPage
		if err := json.Unmarshal(body, &page); err != nil {
			return out, fmt.Errorf("decode sinks page: %w", err)
		}
		out = append(out, page.Sinks...)
		if page.NextPageToken == "" {
			return out, nil
		}
		next = page.NextPageToken
	}
}

// isBuiltinSinkName returns true for sinks that always exist and
// only write to the in-project _Default logging bucket — not durable
// exports.
func isBuiltinSinkName(name string) bool {
	return name == "_Default" || name == "_Required"
}

func buildSinkResource(s sink, projectID string) connectors.Resource {
	destType := destinationType(s.Destination)
	durable := destType == "bigquery" || destType == "storage" || destType == "pubsub"
	return connectors.Resource{
		Type: "gcp.logging.sink",
		ID:   "gcp-logging://" + projectID + "/sinks/" + s.Name,
		Attrs: map[string]any{
			"name":                    s.Name,
			"destination":             s.Destination,
			"destination_type":        destType,
			"filter":                  s.Filter,
			"captures_admin_activity": capturesAdminActivity(s.Filter),
			"is_durable_export":       durable,
		},
	}
}

// destinationType inspects the destination string prefix Cloud
// Logging assigns. Values: "bigquery", "storage", "pubsub",
// "logging", or "other".
func destinationType(dest string) string {
	switch {
	case strings.HasPrefix(dest, "bigquery.googleapis.com/"):
		return "bigquery"
	case strings.HasPrefix(dest, "storage.googleapis.com/"):
		return "storage"
	case strings.HasPrefix(dest, "pubsub.googleapis.com/"):
		return "pubsub"
	case strings.HasPrefix(dest, "logging.googleapis.com/"):
		return "logging"
	default:
		return "other"
	}
}

// capturesAdminActivity returns true when the sink's filter does
// not exclude admin activity audit logs. Heuristic v0:
//
//   - empty filter → catches everything → true
//   - filter mentions "cloudaudit.googleapis.com" or "activity" → true
//   - otherwise → false
//
// Real-world admin-activity filters reference
// logName="projects/X/logs/cloudaudit.googleapis.com%2Factivity"
// or use the cloudaudit log family wildcard.
func capturesAdminActivity(filter string) bool {
	if strings.TrimSpace(filter) == "" {
		return true
	}
	low := strings.ToLower(filter)
	if strings.Contains(low, "cloudaudit.googleapis.com") {
		return true
	}
	if strings.Contains(low, "activity") {
		return true
	}
	return false
}
