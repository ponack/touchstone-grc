package jira

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ponack/touchstone/internal/connectors"
)

const (
	searchPath = "/rest/api/3/search/jql"
	pageSize   = 100
	maxPages   = 10 // Hard cap: at most 1k issues per query bucket.
)

// Scan produces a single jira.site resource summarising
// security/incident ticket activity for CC7.4. Mirrors the Linear
// connector's bucket model so cc7_4.rego can apply the same rule to
// either source.
func (Connector) Scan(ctx context.Context, cfgRaw, secretRaw json.RawMessage) (*connectors.ScanResult, error) {
	var cfg PublicConfig
	if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if len(secretRaw) == 0 {
		return nil, errors.New("jira scan: missing secret")
	}
	var sec Secret
	if err := json.Unmarshal(secretRaw, &sec); err != nil {
		return nil, fmt.Errorf("decode secret: %w", err)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	now := time.Now().UTC()
	cutoff := now.Add(-time.Duration(cfg.SLAWindowDays) * 24 * time.Hour)
	cutoffDate := cutoff.Format("2006-01-02")
	authHeader := basicAuth(cfg.Email, sec.APIToken)

	closedJQL := buildJQL(cfg.IncidentLabels, cfg.ProjectKeys, "statusCategory = Done", fmt.Sprintf(`resolutiondate >= "%s"`, cutoffDate))
	staleJQL := buildJQL(cfg.IncidentLabels, cfg.ProjectKeys, "statusCategory != Done", fmt.Sprintf(`created <= "%s"`, cutoffDate))

	closed, err := searchIssues(ctx, client, cfg.SiteURL, authHeader, closedJQL)
	if err != nil {
		return nil, fmt.Errorf("jira closed search: %w", err)
	}
	stale, err := searchIssues(ctx, client, cfg.SiteURL, authHeader, staleJQL)
	if err != nil {
		return nil, fmt.Errorf("jira stale-open search: %w", err)
	}

	siteID := strings.TrimPrefix(cfg.SiteURL, "https://")
	res := &connectors.ScanResult{
		Resources: []connectors.Resource{
			{
				Type: "jira.site",
				ID:   "jira://sites/" + siteID,
				Attrs: map[string]any{
					"site_url":                         cfg.SiteURL,
					"project_keys":                     cfg.ProjectKeys,
					"incident_labels":                  cfg.IncidentLabels,
					"sla_window_days":                  cfg.SLAWindowDays,
					"attest_no_incidents":              cfg.AttestNoIncidents,
					"security_issues_closed":           summarise(closed),
					"security_issues_closed_count":     len(closed),
					"security_issues_open_stale":       summarise(stale),
					"security_issues_open_stale_count": len(stale),
				},
			},
		},
	}
	slog.Info("jira scan complete",
		"site", siteID,
		"closed_in_window", len(closed),
		"stale_open", len(stale),
		"sla_days", cfg.SLAWindowDays,
	)
	return res, nil
}

// ── Internals ───────────────────────────────────────────────────────

type issue struct {
	ID     string `json:"id"`
	Key    string `json:"key"`
	Fields struct {
		Summary        string   `json:"summary"`
		Labels         []string `json:"labels"`
		Created        string   `json:"created,omitempty"`
		ResolutionDate string   `json:"resolutiondate,omitempty"`
	} `json:"fields"`
}

type searchResponse struct {
	Issues        []issue `json:"issues"`
	NextPageToken string  `json:"nextPageToken,omitempty"`
	IsLast        bool    `json:"isLast,omitempty"`
}

func buildJQL(labels, projectKeys []string, clauses ...string) string {
	parts := []string{
		fmt.Sprintf("labels in (%s)", quoteAndJoin(labels)),
	}
	parts = append(parts, clauses...)
	if len(projectKeys) > 0 {
		parts = append(parts, fmt.Sprintf("project in (%s)", strings.Join(projectKeys, ", ")))
	}
	return strings.Join(parts, " AND ")
}

func quoteAndJoin(in []string) string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		// JQL escapes inside double-quoted strings: backslash and
		// double quote. Labels don't contain those in any realistic
		// setup, but guard anyway.
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `"`, `\"`)
		out = append(out, `"`+s+`"`)
	}
	return strings.Join(out, ", ")
}

func basicAuth(email, token string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(email+":"+token))
}

func searchIssues(ctx context.Context, client *http.Client, siteURL, authHeader, jql string) ([]issue, error) {
	out := []issue{}
	token := ""
	for page := 0; page < maxPages; page++ {
		body := map[string]any{
			"jql":        jql,
			"fields":     []string{"summary", "labels", "created", "resolutiondate"},
			"maxResults": pageSize,
		}
		if token != "" {
			body["nextPageToken"] = token
		}
		reqBody, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, siteURL+searchPath, bytes.NewReader(reqBody))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", authHeader)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
		}
		var sr searchResponse
		if err := json.Unmarshal(respBody, &sr); err != nil {
			return nil, fmt.Errorf("decode response: %w", err)
		}
		out = append(out, sr.Issues...)
		if sr.IsLast || sr.NextPageToken == "" {
			return out, nil
		}
		token = sr.NextPageToken
	}
	slog.Warn("jira pagination capped", "max_pages", maxPages, "collected", len(out))
	return out, nil
}

func summarise(in []issue) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, i := range in {
		entry := map[string]any{
			"id":      i.ID,
			"key":     i.Key,
			"summary": i.Fields.Summary,
			"labels":  i.Fields.Labels,
		}
		if i.Fields.Created != "" {
			entry["created"] = i.Fields.Created
		}
		if i.Fields.ResolutionDate != "" {
			entry["resolved_at"] = i.Fields.ResolutionDate
		}
		out = append(out, entry)
	}
	return out
}
