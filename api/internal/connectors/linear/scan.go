package linear

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/ponack/touchstone/internal/connectors"
)

const (
	apiEndpoint = "https://api.linear.app/graphql"
	pageSize    = 100
	maxPages    = 10 // Hard cap: at most 1k issues per query bucket.
)

// Scan produces a single linear.workspace resource summarising
// security/incident ticket activity for CC7.4. The bucket model:
//
//   - security_issues_closed: tickets matching the configured incident
//     labels that closed inside the SLA window. Proves the workflow
//     is actually used.
//   - security_issues_open_stale: tickets matching those labels that
//     are still open and were created longer than the SLA window ago.
//     Counts as a CC7.4 violation — incident response did not close
//     the loop on time.
func (Connector) Scan(ctx context.Context, cfgRaw, secretRaw json.RawMessage) (*connectors.ScanResult, error) {
	var cfg PublicConfig
	if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if len(secretRaw) == 0 {
		return nil, errors.New("linear scan: missing secret")
	}
	var sec Secret
	if err := json.Unmarshal(secretRaw, &sec); err != nil {
		return nil, fmt.Errorf("decode secret: %w", err)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	now := time.Now().UTC()
	cutoff := now.Add(-time.Duration(cfg.SLAWindowDays) * 24 * time.Hour)
	cutoffISO := cutoff.Format(time.RFC3339)

	closed, err := queryIssues(ctx, client, sec.APIKey, closedQuery(cfg.IncidentLabels, cutoffISO))
	if err != nil {
		return nil, fmt.Errorf("linear closed issues: %w", err)
	}

	stale, err := queryIssues(ctx, client, sec.APIKey, staleOpenQuery(cfg.IncidentLabels, cutoffISO))
	if err != nil {
		return nil, fmt.Errorf("linear stale-open issues: %w", err)
	}

	res := &connectors.ScanResult{
		Resources: []connectors.Resource{
			{
				Type: "linear.workspace",
				ID:   "linear://workspaces/" + cfg.WorkspaceName,
				Attrs: map[string]any{
					"workspace_name":                   cfg.WorkspaceName,
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
	slog.Info("linear scan complete",
		"workspace", cfg.WorkspaceName,
		"closed_in_window", len(closed),
		"stale_open", len(stale),
		"sla_days", cfg.SLAWindowDays,
	)
	return res, nil
}

// ── Internals ───────────────────────────────────────────────────────

type issue struct {
	ID          string `json:"id"`
	Identifier  string `json:"identifier"`
	Title       string `json:"title"`
	CompletedAt string `json:"completedAt,omitempty"`
	CreatedAt   string `json:"createdAt,omitempty"`
	Labels      struct {
		Nodes []struct {
			Name string `json:"name"`
		} `json:"nodes"`
	} `json:"labels"`
}

type issuesPage struct {
	Nodes    []issue `json:"nodes"`
	PageInfo struct {
		HasNextPage bool   `json:"hasNextPage"`
		EndCursor   string `json:"endCursor"`
	} `json:"pageInfo"`
}

type graphQLResponse struct {
	Data struct {
		Issues issuesPage `json:"issues"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func closedQuery(labels []string, cutoffISO string) string {
	return fmt.Sprintf(`query($after: String) {
  issues(
    first: %d
    after: $after
    filter: {
      labels: { name: { in: %s } }
      completedAt: { gte: "%s" }
    }
  ) {
    nodes { id identifier title completedAt labels { nodes { name } } }
    pageInfo { hasNextPage endCursor }
  }
}`, pageSize, jsonStringArray(labels), cutoffISO)
}

func staleOpenQuery(labels []string, cutoffISO string) string {
	return fmt.Sprintf(`query($after: String) {
  issues(
    first: %d
    after: $after
    filter: {
      labels: { name: { in: %s } }
      completedAt: { null: true }
      cancelledAt: { null: true }
      createdAt: { lt: "%s" }
    }
  ) {
    nodes { id identifier title createdAt labels { nodes { name } } }
    pageInfo { hasNextPage endCursor }
  }
}`, pageSize, jsonStringArray(labels), cutoffISO)
}

func jsonStringArray(in []string) string {
	b, _ := json.Marshal(in)
	return string(b)
}

func queryIssues(ctx context.Context, client *http.Client, apiKey, query string) ([]issue, error) {
	out := []issue{}
	cursor := ""
	for page := 0; page < maxPages; page++ {
		vars := map[string]any{}
		if cursor != "" {
			vars["after"] = cursor
		}
		body, err := json.Marshal(map[string]any{
			"query":     query,
			"variables": vars,
		})
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiEndpoint, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", apiKey)
		req.Header.Set("Content-Type", "application/json")

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
		var gql graphQLResponse
		if err := json.Unmarshal(respBody, &gql); err != nil {
			return nil, fmt.Errorf("decode response: %w", err)
		}
		if len(gql.Errors) > 0 {
			return nil, fmt.Errorf("graphql error: %s", gql.Errors[0].Message)
		}

		out = append(out, gql.Data.Issues.Nodes...)
		if !gql.Data.Issues.PageInfo.HasNextPage {
			return out, nil
		}
		cursor = gql.Data.Issues.PageInfo.EndCursor
	}
	slog.Warn("linear pagination capped", "max_pages", maxPages, "collected", len(out))
	return out, nil
}

func summarise(in []issue) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, i := range in {
		labels := make([]string, 0, len(i.Labels.Nodes))
		for _, l := range i.Labels.Nodes {
			labels = append(labels, l.Name)
		}
		entry := map[string]any{
			"id":         i.ID,
			"identifier": i.Identifier,
			"title":      i.Title,
			"labels":     labels,
		}
		if i.CompletedAt != "" {
			entry["completed_at"] = i.CompletedAt
		}
		if i.CreatedAt != "" {
			entry["created_at"] = i.CreatedAt
		}
		out = append(out, entry)
	}
	return out
}
