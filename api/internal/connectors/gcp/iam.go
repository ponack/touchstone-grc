package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2/google"

	"github.com/ponack/touchstone/internal/connectors"
)

const (
	directoryHost  = "https://admin.googleapis.com"
	directoryScope = "https://www.googleapis.com/auth/admin.directory.user.readonly"
	directoryPath  = "/admin/directory/v1/users"
	pageSize       = 500
)

// scanWorkspaceUsers hits the Admin SDK Directory users.list endpoint
// and surfaces every user with its 2-Step Verification state — the
// signal CC6.1 needs.
//
// Requires the service account to have domain-wide delegation
// enabled in the Workspace admin console, with the scope
// `admin.directory.user.readonly` granted to the SA's client ID.
// The SA then impersonates the configured admin email when calling
// the Directory API.
//
// When the operator hasn't configured the Workspace fields, this
// scanner returns no resources — CC6.1 GCP source stays quiet and
// the connector still produces project-scoped evidence in later
// scanners.
func scanWorkspaceUsers(ctx context.Context, cfg PublicConfig, sec Secret) ([]connectors.Resource, error) {
	if cfg.WorkspaceCustomerID == "" || cfg.WorkspaceAdminEmail == "" {
		slog.Info("gcp workspace scan skipped — no Workspace customer configured")
		return nil, nil
	}

	jwtCfg, err := google.JWTConfigFromJSON([]byte(sec.ServiceAccountKeyJSON), directoryScope)
	if err != nil {
		return nil, fmt.Errorf("gcp: parse SA key for JWT config: %w", err)
	}
	// Domain-wide delegation — impersonate the configured Workspace
	// admin when calling the Directory API.
	jwtCfg.Subject = cfg.WorkspaceAdminEmail
	client := jwtCfg.Client(ctx)
	client.Timeout = 60 * time.Second

	q := url.Values{}
	q.Set("customer", cfg.WorkspaceCustomerID)
	q.Set("maxResults", fmt.Sprintf("%d", pageSize))
	q.Set("projection", "basic")
	q.Set("fields", "users(id,primaryEmail,isEnrolledIn2Sv,isEnforcedIn2Sv,suspended,isAdmin),nextPageToken")

	next := ""
	var out []connectors.Resource
	for {
		if next != "" {
			q.Set("pageToken", next)
		}
		page, err := fetchDirectoryPage(ctx, client, directoryHost+directoryPath+"?"+q.Encode())
		if err != nil {
			return out, fmt.Errorf("directory users.list: %w", err)
		}
		for _, u := range page.Users {
			out = append(out, buildUserResource(u, cfg.WorkspaceCustomerID))
		}
		if page.NextPageToken == "" {
			break
		}
		next = page.NextPageToken
	}

	slog.Info("gcp workspace scan complete", "users", len(out), "customer", cfg.WorkspaceCustomerID)
	return out, nil
}

// ── Internals ───────────────────────────────────────────────────────

type directoryUser struct {
	ID              string `json:"id"`
	PrimaryEmail    string `json:"primaryEmail"`
	IsEnrolledIn2Sv bool   `json:"isEnrolledIn2Sv"`
	IsEnforcedIn2Sv bool   `json:"isEnforcedIn2Sv"`
	Suspended       bool   `json:"suspended"`
	IsAdmin         bool   `json:"isAdmin"`
}

type directoryPage struct {
	Users         []directoryUser `json:"users"`
	NextPageToken string          `json:"nextPageToken"`
}

func fetchDirectoryPage(ctx context.Context, client *http.Client, url string) (directoryPage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return directoryPage{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return directoryPage{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return directoryPage{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return directoryPage{}, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	var page directoryPage
	if err := json.Unmarshal(body, &page); err != nil {
		return directoryPage{}, fmt.Errorf("decode: %w", err)
	}
	return page, nil
}

func buildUserResource(u directoryUser, customerID string) connectors.Resource {
	return connectors.Resource{
		Type: "gcp.iam.user",
		ID:   "gcp-workspace://" + customerID + "/users/" + u.ID,
		Attrs: map[string]any{
			"primary_email":   u.PrimaryEmail,
			"is_enrolled_2sv": u.IsEnrolledIn2Sv,
			"is_enforced_2sv": u.IsEnforcedIn2Sv,
			"suspended":       u.Suspended,
			"is_admin":        u.IsAdmin,
		},
	}
}
