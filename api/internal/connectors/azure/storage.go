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
	armHost            = "https://management.azure.com"
	armScope           = "https://management.azure.com/.default"
	storageAPIVersion  = "2023-05-01"
	storageListPathFmt = "/subscriptions/%s/providers/Microsoft.Storage/storageAccounts?api-version=" + storageAPIVersion
)

// scanStorage enumerates every Azure Storage Account in the configured
// subscription via the Azure Resource Manager API and surfaces the
// attributes CC6.6 (public access) and CC6.7 (TLS / encryption) need:
//   - allow_blob_public_access      blob-level public allow-list
//   - public_network_access         account-level network firewall mode
//   - enable_https_traffic_only     HTTP refused at the wire
//   - minimum_tls_version           TLS 1.2+ floor
//   - encryption.key_source         CMK vs Microsoft-managed
//
// Returns an empty slice with no error when subscription_id is empty
// — Azure tenants can be valid without a default subscription in the
// connector config; storage is just out-of-scope for that connector.
func scanStorage(ctx context.Context, cfg PublicConfig, sec Secret) ([]connectors.Resource, error) {
	if cfg.SubscriptionID == "" {
		slog.Info("azure storage scan skipped — no subscription_id on connector", "tenant", cfg.TenantID)
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
	url := armHost + fmt.Sprintf(storageListPathFmt, cfg.SubscriptionID)

	var out []connectors.Resource
	for url != "" {
		page, err := fetchStoragePage(ctx, client, url, token.Token)
		if err != nil {
			return out, fmt.Errorf("arm storage: %w", err)
		}
		for _, a := range page.Value {
			out = append(out, buildStorageAccountResource(a, cfg.SubscriptionID))
		}
		url = page.NextLink
	}

	slog.Info("azure storage scan complete", "accounts", len(out), "subscription", cfg.SubscriptionID)
	return out, nil
}

type storageListPage struct {
	Value    []storageAccount `json:"value"`
	NextLink string           `json:"nextLink"`
}

type storageAccount struct {
	ID         string                   `json:"id"`
	Name       string                   `json:"name"`
	Location   string                   `json:"location"`
	Kind       string                   `json:"kind"`
	SKU        struct{ Name string }    `json:"sku"`
	Properties storageAccountProperties `json:"properties"`
}

type storageAccountProperties struct {
	AllowBlobPublicAccess    *bool  `json:"allowBlobPublicAccess"`
	SupportsHTTPSTrafficOnly *bool  `json:"supportsHttpsTrafficOnly"`
	MinimumTLSVersion        string `json:"minimumTlsVersion"`
	PublicNetworkAccess      string `json:"publicNetworkAccess"`
	Encryption               struct {
		KeySource string `json:"keySource"`
	} `json:"encryption"`
}

func fetchStoragePage(ctx context.Context, client *http.Client, url, token string) (storageListPage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return storageListPage{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return storageListPage{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return storageListPage{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return storageListPage{}, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	var page storageListPage
	if err := json.Unmarshal(body, &page); err != nil {
		return storageListPage{}, fmt.Errorf("decode: %w", err)
	}
	return page, nil
}

func buildStorageAccountResource(a storageAccount, subscriptionID string) connectors.Resource {
	// ARM ID is already the canonical identifier; keep it verbatim.
	allowBlobPublic := false
	if a.Properties.AllowBlobPublicAccess != nil {
		allowBlobPublic = *a.Properties.AllowBlobPublicAccess
	}
	httpsOnly := false
	if a.Properties.SupportsHTTPSTrafficOnly != nil {
		httpsOnly = *a.Properties.SupportsHTTPSTrafficOnly
	}

	return connectors.Resource{
		Type: "azure.storage.account",
		ID:   a.ID,
		Attrs: map[string]any{
			"name":                      a.Name,
			"subscription_id":           subscriptionID,
			"location":                  a.Location,
			"kind":                      a.Kind,
			"sku":                       a.SKU.Name,
			"allow_blob_public_access":  allowBlobPublic,
			"enable_https_traffic_only": httpsOnly,
			"minimum_tls_version":       a.Properties.MinimumTLSVersion,
			"public_network_access":     a.Properties.PublicNetworkAccess,
			"encryption_key_source":     a.Properties.Encryption.KeySource,
		},
	}
}
