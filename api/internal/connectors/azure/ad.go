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

const (
	graphHost              = "https://graph.microsoft.com"
	graphScope             = "https://graph.microsoft.com/.default"
	mfaRegistrationDetails = graphHost + "/v1.0/reports/authenticationMethods/userRegistrationDetails"
)

// scanAD pulls the Microsoft Graph
// reports/authenticationMethods/userRegistrationDetails endpoint
// (one paginated call covers the whole tenant) and surfaces every
// user with its MFA registration state — the signal CC6.1 needs.
//
// Requires the Service Principal to have Graph application
// permission "AuditLog.Read.All" + "UserAuthenticationMethod.Read.All"
// granted with admin consent. Operator docs note this separately.
func scanAD(ctx context.Context, cfg PublicConfig, sec Secret) ([]connectors.Resource, error) {
	cred, err := azidentity.NewClientSecretCredential(cfg.TenantID, sec.ClientID, sec.ClientSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: build client secret credential: %w", err)
	}

	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{graphScope}})
	if err != nil {
		return nil, fmt.Errorf("azure: acquire Graph token: %w", err)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	url := mfaRegistrationDetails
	var out []connectors.Resource

	for url != "" {
		page, err := fetchGraphPage(ctx, client, url, token.Token)
		if err != nil {
			return out, fmt.Errorf("graph: %w", err)
		}
		for _, u := range page.Value {
			out = append(out, buildUserResource(u, cfg.TenantID))
		}
		url = page.NextLink
	}

	slog.Info("azure ad scan complete", "users", len(out), "tenant", cfg.TenantID)
	return out, nil
}

type graphUserRegistration struct {
	ID                string `json:"id"`
	UserPrincipalName string `json:"userPrincipalName"`
	UserDisplayName   string `json:"userDisplayName"`
	IsAdmin           bool   `json:"isAdmin"`
	IsMfaRegistered   bool   `json:"isMfaRegistered"`
	IsMfaCapable      bool   `json:"isMfaCapable"`
	IsSsprRegistered  bool   `json:"isSsprRegistered"`
	UserType          string `json:"userType"`
}

type graphPage struct {
	Value    []graphUserRegistration `json:"value"`
	NextLink string                  `json:"@odata.nextLink"`
}

func fetchGraphPage(ctx context.Context, client *http.Client, url, token string) (graphPage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return graphPage{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return graphPage{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return graphPage{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return graphPage{}, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	var page graphPage
	if err := json.Unmarshal(body, &page); err != nil {
		return graphPage{}, fmt.Errorf("decode: %w", err)
	}
	return page, nil
}

func buildUserResource(u graphUserRegistration, tenantID string) connectors.Resource {
	return connectors.Resource{
		Type: "azure.ad.user",
		ID:   "azure-ad://" + tenantID + "/users/" + u.ID,
		Attrs: map[string]any{
			"user_principal_name": u.UserPrincipalName,
			"display_name":        u.UserDisplayName,
			"user_type":           u.UserType,
			"is_admin":            u.IsAdmin,
			"is_mfa_registered":   u.IsMfaRegistered,
			"is_mfa_capable":      u.IsMfaCapable,
			"is_sspr_registered":  u.IsSsprRegistered,
		},
	}
}
