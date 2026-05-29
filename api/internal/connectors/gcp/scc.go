package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/oauth2/google"

	"github.com/ponack/touchstone/internal/connectors"
)

const (
	sccHost        = "https://securitycenter.googleapis.com"
	sccScope       = "https://www.googleapis.com/auth/cloud-platform"
	sccSourcesPath = "/v1/projects/%s/sources?pageSize=50"
)

// scanSCC probes the Security Command Center API for the project
// and emits exactly one gcp.scc.subscription resource summarising
// whether SCC is active and which detection sources are visible.
//
// SCC's project-scoped API only succeeds when SCC is enabled at the
// organization level AND the SA holds roles/securitycenter.findingsViewer
// (or broader) on the project. A 403 here means SCC isn't reading
// this project — that's the exact signal CC6.8 / CC7.1 / CC7.3 want.
//
// Required role: roles/securitycenter.findingsViewer (project-scoped).
func scanSCC(ctx context.Context, cfg PublicConfig, sec Secret) ([]connectors.Resource, error) {
	jwtCfg, err := google.JWTConfigFromJSON([]byte(sec.ServiceAccountKeyJSON), sccScope)
	if err != nil {
		return nil, fmt.Errorf("gcp: parse SA key for SCC client: %w", err)
	}
	client := jwtCfg.Client(ctx)
	client.Timeout = 60 * time.Second

	active, sources, err := probeSCC(ctx, client, cfg.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("scc probe: %w", err)
	}

	res := connectors.Resource{
		Type: "gcp.scc.subscription",
		ID:   "gcp-scc://" + cfg.ProjectID + "/subscription",
		Attrs: map[string]any{
			"project":      cfg.ProjectID,
			"is_active":    active,
			"source_count": len(sources),
			"sources":      sources,
		},
	}
	slog.Info("gcp scc scan complete", "project", cfg.ProjectID, "active", active, "sources", len(sources))
	return []connectors.Resource{res}, nil
}

// ── Internals ───────────────────────────────────────────────────────

type sccSource struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type sccSourcesResponse struct {
	Sources []sccSource `json:"sources"`
}

// probeSCC returns (active, sourceDisplayNames, err). active=false
// is reported on 403/404 without erroring — that's the policy signal
// the rego needs. Network failures + other status codes bubble up.
func probeSCC(ctx context.Context, client *http.Client, projectID string) (bool, []string, error) {
	url := sccHost + fmt.Sprintf(sccSourcesPath, projectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, nil, err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var page sccSourcesResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return false, nil, fmt.Errorf("decode SCC sources: %w", err)
		}
		out := make([]string, 0, len(page.Sources))
		for _, s := range page.Sources {
			name := s.DisplayName
			if name == "" {
				name = s.Name
			}
			out = append(out, name)
		}
		return true, out, nil
	case http.StatusForbidden, http.StatusNotFound:
		// SCC not enabled for this project, or SA lacks findingsViewer.
		// Either way, the rego signal is the same: not active.
		slog.Warn("gcp scc not active or permission denied", "project", projectID, "status", resp.StatusCode)
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
}
