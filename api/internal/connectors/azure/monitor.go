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
	monitorAPIVersion      = "2021-05-01-preview"
	subDiagSettingsPathFmt = "/subscriptions/%s/providers/microsoft.insights/diagnosticSettings?api-version=" + monitorAPIVersion
)

// scanActivityLogSettings enumerates the subscription-level diagnostic
// settings that route the Azure Activity Log to long-term sinks
// (Log Analytics workspace, Storage Account, Event Hub).
//
// The Activity Log itself is always on for every subscription, but
// retention is 90 days unless one of these settings forwards it.
// CC7.2 wants the long-term forwarding to exist.
//
// Skipped when subscription_id is empty.
//
// Required Azure RBAC role: Reader (built-in) — diagnosticSettings
// reads are covered by it.
func scanActivityLogSettings(ctx context.Context, cfg PublicConfig, sec Secret) ([]connectors.Resource, error) {
	if cfg.SubscriptionID == "" {
		slog.Info("azure monitor scan skipped — no subscription_id on connector", "tenant", cfg.TenantID)
		return nil, nil
	}

	cred, err := azidentity.NewClientSecretCredential(cfg.TenantID, sec.ClientID, sec.ClientSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: build credential: %w", err)
	}
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{armScope}})
	if err != nil {
		return nil, fmt.Errorf("azure: acquire ARM token: %w", err)
	}

	url := armHost + fmt.Sprintf(subDiagSettingsPathFmt, cfg.SubscriptionID)
	client := &http.Client{Timeout: 60 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("arm activity-log diagnostics: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("arm activity-log diagnostics HTTP %d: %s", resp.StatusCode, string(body))
	}

	var page diagSettingsList
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("decode diagnostic settings: %w", err)
	}

	out := make([]connectors.Resource, 0, len(page.Value))
	for _, s := range page.Value {
		out = append(out, buildActivityLogResource(s, cfg.SubscriptionID))
	}
	slog.Info("azure monitor scan complete", "diagnostic_settings", len(out), "subscription", cfg.SubscriptionID)
	return out, nil
}

type diagSettingsList struct {
	Value []diagSetting `json:"value"`
}

type diagSetting struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Properties diagSettingProps `json:"properties"`
}

type diagSettingProps struct {
	StorageAccountID            string         `json:"storageAccountId"`
	WorkspaceID                 string         `json:"workspaceId"`
	EventHubAuthorizationRuleID string         `json:"eventHubAuthorizationRuleId"`
	Logs                        []diagLogEntry `json:"logs"`
}

type diagLogEntry struct {
	Category string `json:"category"`
	Enabled  bool   `json:"enabled"`
}

func buildActivityLogResource(s diagSetting, subscriptionID string) connectors.Resource {
	categories := map[string]bool{}
	for _, l := range s.Properties.Logs {
		categories[l.Category] = l.Enabled
	}
	return connectors.Resource{
		Type: "azure.monitor.activity_log_setting",
		ID:   s.ID,
		Attrs: map[string]any{
			"name":               s.Name,
			"subscription_id":    subscriptionID,
			"has_workspace_sink": s.Properties.WorkspaceID != "",
			"has_storage_sink":   s.Properties.StorageAccountID != "",
			"has_eventhub_sink":  s.Properties.EventHubAuthorizationRuleID != "",
			"categories":         categories,
		},
	}
}
