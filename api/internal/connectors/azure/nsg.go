package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/ponack/touchstone/internal/connectors"
)

const (
	networkAPIVersion = "2023-11-01"
	nsgListPathFmt    = "/subscriptions/%s/providers/Microsoft.Network/networkSecurityGroups?api-version=" + networkAPIVersion
)

// scanNSG enumerates every Network Security Group in the configured
// subscription. CC6.6 evaluates inbound rules that allow world-open
// access to sensitive admin/database ports.
//
// Returns an empty slice (no error) when subscription_id is empty —
// NSGs are subscription-scoped and out-of-scope for AD-only connectors.
//
// Required Azure RBAC role: Reader on the target subscription.
func scanNSG(ctx context.Context, cfg PublicConfig, sec Secret) ([]connectors.Resource, error) {
	if cfg.SubscriptionID == "" {
		slog.Info("azure nsg scan skipped — no subscription_id on connector", "tenant", cfg.TenantID)
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

	client := &http.Client{Timeout: 60 * time.Second}
	url := armHost + fmt.Sprintf(nsgListPathFmt, cfg.SubscriptionID)

	var out []connectors.Resource
	for url != "" {
		page, err := fetchNSGPage(ctx, client, url, token.Token)
		if err != nil {
			return out, fmt.Errorf("arm nsg: %w", err)
		}
		for _, nsg := range page.Value {
			out = append(out, buildNSGResource(nsg, cfg.SubscriptionID))
		}
		url = page.NextLink
	}

	slog.Info("azure nsg scan complete", "nsgs", len(out), "subscription", cfg.SubscriptionID)
	return out, nil
}

type nsgListPage struct {
	Value    []networkSecurityGroup `json:"value"`
	NextLink string                 `json:"nextLink"`
}

type networkSecurityGroup struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Location   string `json:"location"`
	Properties struct {
		SecurityRules []securityRule `json:"securityRules"`
	} `json:"properties"`
}

type securityRule struct {
	Name       string `json:"name"`
	Properties struct {
		Priority              int      `json:"priority"`
		Direction             string   `json:"direction"`
		Access                string   `json:"access"`
		Protocol              string   `json:"protocol"`
		SourceAddressPrefix   string   `json:"sourceAddressPrefix"`
		SourceAddressPrefixes []string `json:"sourceAddressPrefixes"`
		DestinationPortRange  string   `json:"destinationPortRange"`
		DestinationPortRanges []string `json:"destinationPortRanges"`
	} `json:"properties"`
}

func fetchNSGPage(ctx context.Context, client *http.Client, url, token string) (nsgListPage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nsgListPage{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nsgListPage{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nsgListPage{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return nsgListPage{}, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	var page nsgListPage
	if err := json.Unmarshal(body, &page); err != nil {
		return nsgListPage{}, fmt.Errorf("decode: %w", err)
	}
	return page, nil
}

func buildNSGResource(nsg networkSecurityGroup, subscriptionID string) connectors.Resource {
	inbound := []map[string]any{}
	for _, r := range nsg.Properties.SecurityRules {
		if r.Properties.Direction != "Inbound" {
			continue
		}
		if r.Properties.Access != "Allow" {
			continue
		}
		inbound = append(inbound, expandRule(r)...)
	}

	return connectors.Resource{
		Type: "azure.network.nsg",
		ID:   nsg.ID,
		Attrs: map[string]any{
			"name":            nsg.Name,
			"subscription_id": subscriptionID,
			"location":        nsg.Location,
			"inbound_rules":   inbound,
		},
	}
}

// expandRule flattens a single Azure security rule into one or more
// rego-friendly normalized rules. Azure allows either a single port
// range OR a list of port ranges per rule; same for source prefixes.
// We emit one row per (port-range × source-prefix) so the OPA query
// stays a flat scan.
func expandRule(r securityRule) []map[string]any {
	sources := r.Properties.SourceAddressPrefixes
	if len(sources) == 0 && r.Properties.SourceAddressPrefix != "" {
		sources = []string{r.Properties.SourceAddressPrefix}
	}
	if len(sources) == 0 {
		sources = []string{"*"}
	}

	rawPorts := r.Properties.DestinationPortRanges
	if len(rawPorts) == 0 && r.Properties.DestinationPortRange != "" {
		rawPorts = []string{r.Properties.DestinationPortRange}
	}
	if len(rawPorts) == 0 {
		rawPorts = []string{"*"}
	}

	out := make([]map[string]any, 0, len(rawPorts))
	for _, portSpec := range rawPorts {
		from, to := parsePortRange(portSpec)
		out = append(out, map[string]any{
			"name":            r.Name,
			"priority":        r.Properties.Priority,
			"protocol":        r.Properties.Protocol,
			"from_port":       from,
			"to_port":         to,
			"source_prefixes": sources,
		})
	}
	return out
}

// parsePortRange handles "*" / "22" / "22-100".
func parsePortRange(s string) (int, int) {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" {
		return 0, 65535
	}
	if !strings.Contains(s, "-") {
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, 65535
		}
		return n, n
	}
	parts := strings.SplitN(s, "-", 2)
	from, err1 := strconv.Atoi(parts[0])
	to, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return 0, 65535
	}
	return from, to
}
