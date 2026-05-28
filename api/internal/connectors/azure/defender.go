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
	defenderAPIVersion      = "2024-01-01"
	defenderPricingsPathFmt = "/subscriptions/%s/providers/Microsoft.Security/pricings?api-version=" + defenderAPIVersion
)

// scanDefender enumerates Microsoft Defender for Cloud pricing plans
// at the subscription. Each plan (VirtualMachines, StorageAccounts,
// KeyVaults, …) can be Free (off) or Standard (on). CC6.8 / CC7.1 /
// CC7.3 read these as the AWS-GuardDuty + AWS-Security-Hub equivalents.
//
// Skipped when subscription_id is empty.
//
// Required Azure RBAC role: Security Reader (built-in, least-privilege)
// or Reader.
func scanDefender(ctx context.Context, cfg PublicConfig, sec Secret) ([]connectors.Resource, error) {
	if cfg.SubscriptionID == "" {
		slog.Info("azure defender scan skipped — no subscription_id on connector", "tenant", cfg.TenantID)
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

	url := armHost + fmt.Sprintf(defenderPricingsPathFmt, cfg.SubscriptionID)
	client := &http.Client{Timeout: 60 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("arm defender pricings: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("arm defender pricings HTTP %d: %s", resp.StatusCode, string(body))
	}

	var list defenderPricingList
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("decode defender pricings: %w", err)
	}

	out := make([]connectors.Resource, 0, len(list.Value))
	for _, p := range list.Value {
		out = append(out, buildDefenderResource(p, cfg.SubscriptionID))
	}
	slog.Info("azure defender scan complete", "plans", len(out), "subscription", cfg.SubscriptionID)
	return out, nil
}

type defenderPricingList struct {
	Value []defenderPricing `json:"value"`
}

type defenderPricing struct {
	ID         string                    `json:"id"`
	Name       string                    `json:"name"`
	Properties defenderPricingProperties `json:"properties"`
}

type defenderPricingProperties struct {
	PricingTier string `json:"pricingTier"`
	SubPlan     string `json:"subPlan"`
}

func buildDefenderResource(p defenderPricing, subscriptionID string) connectors.Resource {
	enabled := p.Properties.PricingTier == "Standard"
	return connectors.Resource{
		Type: "azure.defender.pricing",
		ID:   p.ID,
		Attrs: map[string]any{
			"plan_name":       p.Name,
			"subscription_id": subscriptionID,
			"pricing_tier":    p.Properties.PricingTier,
			"sub_plan":        p.Properties.SubPlan,
			"enabled":         enabled,
		},
	}
}
