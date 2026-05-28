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
	sqlAPIVersion       = "2023-08-01-preview"
	sqlServersPathFmt   = "/subscriptions/%s/providers/Microsoft.Sql/servers?api-version=" + sqlAPIVersion
	sqlServerDBsPathFmt = "%s/databases?api-version=" + sqlAPIVersion
	sqlBackupPolicyPath = "%s/backupShortTermRetentionPolicies/default?api-version=" + sqlAPIVersion
)

// scanSQL enumerates Azure SQL databases across every SQL server in
// the configured subscription and pairs each with its short-term
// backup retention policy. CC7.5 evaluates the retention day count
// the same way it does for AWS RDS.
//
// Skipped when subscription_id is empty.
//
// The master database on each server is auto-managed by Azure and
// is skipped (no operator-controlled retention).
//
// Required Azure RBAC role: Reader on the subscription.
func scanSQL(ctx context.Context, cfg PublicConfig, sec Secret) ([]connectors.Resource, error) {
	if cfg.SubscriptionID == "" {
		slog.Info("azure sql scan skipped — no subscription_id on connector", "tenant", cfg.TenantID)
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

	servers, err := listSQLServers(ctx, client, token.Token, cfg.SubscriptionID)
	if err != nil {
		return nil, err
	}

	var out []connectors.Resource
	for _, srv := range servers {
		dbs, err := listSQLDatabases(ctx, client, token.Token, srv.ID)
		if err != nil {
			slog.Warn("azure sql databases list failed", "server", srv.ID, "err", err)
			continue
		}
		for _, db := range dbs {
			if db.Name == "master" {
				continue
			}
			retention := readBackupRetention(ctx, client, token.Token, db.ID)
			out = append(out, buildSQLDatabaseResource(srv, db, retention, cfg.SubscriptionID))
		}
	}

	slog.Info("azure sql scan complete", "databases", len(out), "subscription", cfg.SubscriptionID)
	return out, nil
}

// ── ARM helpers ────────────────────────────────────────────────────

type sqlServerList struct {
	Value []sqlServer `json:"value"`
}

type sqlServer struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Location   string `json:"location"`
	Properties struct {
		Version string `json:"version"`
	} `json:"properties"`
}

type sqlDatabaseList struct {
	Value []sqlDatabase `json:"value"`
}

type sqlDatabase struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Location string `json:"location"`
	SKU      struct {
		Name string `json:"name"`
		Tier string `json:"tier"`
	} `json:"sku"`
	Properties struct {
		Status string `json:"status"`
	} `json:"properties"`
}

type backupShortTermRetentionPolicy struct {
	Properties struct {
		RetentionDays int `json:"retentionDays"`
	} `json:"properties"`
}

func listSQLServers(ctx context.Context, client *http.Client, token, subscriptionID string) ([]sqlServer, error) {
	url := armHost + fmt.Sprintf(sqlServersPathFmt, subscriptionID)
	body, err := armGET(ctx, client, url, token)
	if err != nil {
		return nil, fmt.Errorf("sql servers list: %w", err)
	}
	var list sqlServerList
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("decode sql servers: %w", err)
	}
	return list.Value, nil
}

func listSQLDatabases(ctx context.Context, client *http.Client, token, serverID string) ([]sqlDatabase, error) {
	url := armHost + fmt.Sprintf(sqlServerDBsPathFmt, serverID)
	body, err := armGET(ctx, client, url, token)
	if err != nil {
		return nil, fmt.Errorf("sql databases list: %w", err)
	}
	var list sqlDatabaseList
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("decode sql databases: %w", err)
	}
	return list.Value, nil
}

// readBackupRetention returns the configured short-term retention in
// days for db, or 0 when the policy can't be read. Treating an
// unreadable policy as zero days makes the CC7.5 rego fail loud
// rather than silently mark the DB as compliant.
func readBackupRetention(ctx context.Context, client *http.Client, token, dbID string) int {
	url := armHost + fmt.Sprintf(sqlBackupPolicyPath, dbID)
	body, err := armGET(ctx, client, url, token)
	if err != nil {
		slog.Warn("azure sql backup retention read failed", "db", dbID, "err", err)
		return 0
	}
	var pol backupShortTermRetentionPolicy
	if err := json.Unmarshal(body, &pol); err != nil {
		slog.Warn("azure sql backup retention decode failed", "db", dbID, "err", err)
		return 0
	}
	return pol.Properties.RetentionDays
}

func armGET(ctx context.Context, client *http.Client, url, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

func buildSQLDatabaseResource(srv sqlServer, db sqlDatabase, retentionDays int, subscriptionID string) connectors.Resource {
	return connectors.Resource{
		Type: "azure.sql.database",
		ID:   db.ID,
		Attrs: map[string]any{
			"database_name":           db.Name,
			"server_name":             srv.Name,
			"server_id":               srv.ID,
			"subscription_id":         subscriptionID,
			"location":                db.Location,
			"sku_name":                db.SKU.Name,
			"sku_tier":                db.SKU.Tier,
			"status":                  db.Properties.Status,
			"backup_retention_period": retentionDays,
		},
	}
}
