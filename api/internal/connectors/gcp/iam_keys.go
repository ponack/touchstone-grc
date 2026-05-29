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
	iamHost          = "https://iam.googleapis.com"
	iamScope         = "https://www.googleapis.com/auth/cloud-platform"
	iamSAPath        = "/v1/projects/%s/serviceAccounts?pageSize=100"
	iamSAKeysPathFmt = "/v1/projects/%s/serviceAccounts/%s/keys?keyTypes=USER_MANAGED"
)

// scanServiceAccounts enumerates project service accounts and their
// user-managed keys. Each SA becomes a gcp.iam.service_account
// resource with a keys array. System-managed keys (Google-rotated
// automatically) are filtered at the API level via keyTypes=USER_MANAGED
// — only credentials the operator controls show up.
//
// Required role: roles/iam.serviceAccountViewer + roles/iam.serviceAccountKeyAdmin
// (the latter is needed to list keys; viewer alone is insufficient
// on the keys subresource). Both project-scoped.
func scanServiceAccounts(ctx context.Context, cfg PublicConfig, sec Secret) ([]connectors.Resource, error) {
	jwtCfg, err := google.JWTConfigFromJSON([]byte(sec.ServiceAccountKeyJSON), iamScope)
	if err != nil {
		return nil, fmt.Errorf("gcp: parse SA key for IAM client: %w", err)
	}
	client := jwtCfg.Client(ctx)
	client.Timeout = 60 * time.Second

	sas, err := listServiceAccounts(ctx, client, cfg.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("iam serviceAccounts.list: %w", err)
	}

	out := make([]connectors.Resource, 0, len(sas))
	for _, sa := range sas {
		keys, err := listUserManagedKeys(ctx, client, cfg.ProjectID, sa.Email)
		if err != nil {
			slog.Warn("gcp iam keys fetch failed", "service_account", sa.Email, "err", err)
			keys = nil
		}
		out = append(out, buildServiceAccountResource(sa, cfg.ProjectID, keys))
	}

	slog.Info("gcp iam service-account scan complete", "service_accounts", len(out), "project", cfg.ProjectID)
	return out, nil
}

// ── Internals ───────────────────────────────────────────────────────

type serviceAccount struct {
	Email       string `json:"email"`
	UniqueID    string `json:"uniqueId"`
	DisplayName string `json:"displayName"`
	Disabled    bool   `json:"disabled"`
}

type serviceAccountsPage struct {
	Accounts      []serviceAccount `json:"accounts"`
	NextPageToken string           `json:"nextPageToken"`
}

type serviceAccountKey struct {
	Name           string `json:"name"`
	KeyType        string `json:"keyType"`
	ValidAfterTime string `json:"validAfterTime"`
}

type serviceAccountKeysResponse struct {
	Keys []serviceAccountKey `json:"keys"`
}

func listServiceAccounts(ctx context.Context, client *http.Client, projectID string) ([]serviceAccount, error) {
	base := iamHost + fmt.Sprintf(iamSAPath, projectID)
	var out []serviceAccount
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
		var page serviceAccountsPage
		if err := json.Unmarshal(body, &page); err != nil {
			return out, fmt.Errorf("decode service accounts page: %w", err)
		}
		out = append(out, page.Accounts...)
		if page.NextPageToken == "" {
			return out, nil
		}
		next = page.NextPageToken
	}
}

func listUserManagedKeys(ctx context.Context, client *http.Client, projectID, email string) ([]serviceAccountKey, error) {
	url := iamHost + fmt.Sprintf(iamSAKeysPathFmt, projectID, email)
	body, err := gcpGET(ctx, client, url)
	if err != nil {
		return nil, err
	}
	var resp serviceAccountKeysResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode keys: %w", err)
	}
	out := make([]serviceAccountKey, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		// Defensive filter — keyTypes=USER_MANAGED in the query string
		// should already exclude system-managed keys, but mirror at
		// the response layer.
		if k.KeyType != "USER_MANAGED" {
			continue
		}
		out = append(out, k)
	}
	return out, nil
}

func buildServiceAccountResource(sa serviceAccount, projectID string, keys []serviceAccountKey) connectors.Resource {
	keyList := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		keyList = append(keyList, map[string]any{
			"id":               shortKeyID(k.Name),
			"key_type":         k.KeyType,
			"valid_after_time": k.ValidAfterTime,
		})
	}
	return connectors.Resource{
		Type: "gcp.iam.service_account",
		ID:   "gcp-iam://" + projectID + "/serviceAccounts/" + sa.Email,
		Attrs: map[string]any{
			"email":        sa.Email,
			"unique_id":    sa.UniqueID,
			"display_name": sa.DisplayName,
			"disabled":     sa.Disabled,
			"keys":         keyList,
		},
	}
}

// shortKeyID strips the projects/.../serviceAccounts/.../keys/ prefix
// and returns just the key identifier — the value an operator sees
// in the console and can match to gcloud output.
func shortKeyID(name string) string {
	i := strings.LastIndex(name, "/keys/")
	if i < 0 {
		return name
	}
	return name[i+len("/keys/"):]
}
