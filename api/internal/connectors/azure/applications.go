package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/ponack/touchstone/internal/connectors"
)

const applicationsURL = graphHost + "/v1.0/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials"

// scanApplications enumerates every Azure AD application registration
// in the tenant and surfaces its password credentials (client
// secrets) and key credentials (certs). CC6.3 evaluates whether any
// active credential is older than the rotation threshold.
//
// Required Graph permission (admin-consented application): Application.Read.All
func scanApplications(ctx context.Context, cfg PublicConfig, sec Secret) ([]connectors.Resource, error) {
	cred, err := azidentity.NewClientSecretCredential(cfg.TenantID, sec.ClientID, sec.ClientSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: build credential: %w", err)
	}
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{graphScope}})
	if err != nil {
		return nil, fmt.Errorf("azure: acquire Graph token: %w", err)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	url := applicationsURL
	var out []connectors.Resource

	for url != "" {
		page, err := fetchApplicationsPage(ctx, client, url, token.Token)
		if err != nil {
			return out, fmt.Errorf("graph applications: %w", err)
		}
		for _, app := range page.Value {
			out = append(out, buildApplicationResource(app, cfg.TenantID))
		}
		url = page.NextLink
	}

	slog.Info("azure applications scan complete", "applications", len(out), "tenant", cfg.TenantID)
	return out, nil
}

type graphCredential struct {
	KeyID         string `json:"keyId"`
	DisplayName   string `json:"displayName"`
	StartDateTime string `json:"startDateTime"`
	EndDateTime   string `json:"endDateTime"`
	Type          string `json:"type,omitempty"` // certificates only
	Usage         string `json:"usage,omitempty"`
}

type graphApplication struct {
	ID                  string            `json:"id"`
	AppID               string            `json:"appId"`
	DisplayName         string            `json:"displayName"`
	PasswordCredentials []graphCredential `json:"passwordCredentials"`
	KeyCredentials      []graphCredential `json:"keyCredentials"`
}

type applicationsPage struct {
	Value    []graphApplication `json:"value"`
	NextLink string             `json:"@odata.nextLink"`
}

func fetchApplicationsPage(ctx context.Context, client *http.Client, url, token string) (applicationsPage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return applicationsPage{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return applicationsPage{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return applicationsPage{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return applicationsPage{}, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	var page applicationsPage
	if err := json.Unmarshal(body, &page); err != nil {
		return applicationsPage{}, fmt.Errorf("decode: %w", err)
	}
	return page, nil
}

func buildApplicationResource(app graphApplication, tenantID string) connectors.Resource {
	return connectors.Resource{
		Type: "azure.ad.application",
		ID:   "azure-ad://" + tenantID + "/applications/" + app.AppID,
		Attrs: map[string]any{
			"app_id":               app.AppID,
			"object_id":            app.ID,
			"display_name":         app.DisplayName,
			"password_credentials": normalizeCreds(app.PasswordCredentials),
			"key_credentials":      normalizeCreds(app.KeyCredentials),
		},
	}
}

func normalizeCreds(creds []graphCredential) []map[string]any {
	out := make([]map[string]any, 0, len(creds))
	for _, c := range creds {
		out = append(out, map[string]any{
			"key_id":       c.KeyID,
			"display_name": c.DisplayName,
			"start_date":   c.StartDateTime,
			"end_date":     c.EndDateTime,
			"type":         c.Type,
			"usage":        c.Usage,
		})
	}
	return out
}
