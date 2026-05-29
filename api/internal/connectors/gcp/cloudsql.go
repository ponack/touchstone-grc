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
	sqlAdminHost   = "https://sqladmin.googleapis.com"
	sqlAdminScope  = "https://www.googleapis.com/auth/sqlservice.admin"
	sqlInstPath    = "/sql/v1beta4/projects/%s/instances?maxResults=100"
	primaryInstTyp = "CLOUD_SQL_INSTANCE"
)

// scanCloudSQL enumerates primary Cloud SQL instances in the project
// and surfaces the signals CC7.5 needs: automated backup enablement,
// retention window, point-in-time recovery, and deletion protection.
// Read replicas are filtered out — their backup posture is inherited
// from the primary.
//
// Required role: roles/cloudsql.viewer (project-scoped).
func scanCloudSQL(ctx context.Context, cfg PublicConfig, sec Secret) ([]connectors.Resource, error) {
	jwtCfg, err := google.JWTConfigFromJSON([]byte(sec.ServiceAccountKeyJSON), sqlAdminScope)
	if err != nil {
		return nil, fmt.Errorf("gcp: parse SA key for Cloud SQL client: %w", err)
	}
	client := jwtCfg.Client(ctx)
	client.Timeout = 60 * time.Second

	instances, err := listSQLInstances(ctx, client, cfg.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("cloudsql instances.list: %w", err)
	}

	out := make([]connectors.Resource, 0, len(instances))
	for _, inst := range instances {
		if inst.InstanceType != "" && inst.InstanceType != primaryInstTyp {
			continue
		}
		out = append(out, buildSQLInstanceResource(inst, cfg.ProjectID))
	}

	slog.Info("gcp cloudsql scan complete", "primary_instances", len(out), "project", cfg.ProjectID)
	return out, nil
}

// ── Internals ───────────────────────────────────────────────────────

type sqlInstance struct {
	Name            string `json:"name"`
	DatabaseVersion string `json:"databaseVersion"`
	State           string `json:"state"`
	InstanceType    string `json:"instanceType"`
	Settings        struct {
		DeletionProtectionEnabled bool `json:"deletionProtectionEnabled"`
		BackupConfiguration       struct {
			Enabled                    bool `json:"enabled"`
			PointInTimeRecoveryEnabled bool `json:"pointInTimeRecoveryEnabled"`
			BinaryLogEnabled           bool `json:"binaryLogEnabled"`
			BackupRetentionSettings    struct {
				RetainedBackups int    `json:"retainedBackups"`
				RetentionUnit   string `json:"retentionUnit"`
			} `json:"backupRetentionSettings"`
		} `json:"backupConfiguration"`
	} `json:"settings"`
}

type sqlInstancesPage struct {
	Items         []sqlInstance `json:"items"`
	NextPageToken string        `json:"nextPageToken"`
}

func listSQLInstances(ctx context.Context, client *http.Client, projectID string) ([]sqlInstance, error) {
	base := sqlAdminHost + fmt.Sprintf(sqlInstPath, projectID)
	var out []sqlInstance
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
		var page sqlInstancesPage
		if err := json.Unmarshal(body, &page); err != nil {
			return out, fmt.Errorf("decode instances page: %w", err)
		}
		out = append(out, page.Items...)
		if page.NextPageToken == "" {
			return out, nil
		}
		next = page.NextPageToken
	}
}

// buildSQLInstanceResource flattens the GCP API into a CC7.5-shaped
// attribute bag. retainedBackups is interpreted as days: automated
// backups in Cloud SQL run daily, so the count of retained backups
// equals the rolling-window day count.
func buildSQLInstanceResource(inst sqlInstance, projectID string) connectors.Resource {
	bc := inst.Settings.BackupConfiguration
	pitr := bc.PointInTimeRecoveryEnabled || bc.BinaryLogEnabled
	return connectors.Resource{
		Type: "gcp.sql.instance",
		ID:   "gcp-sql://" + projectID + "/instances/" + inst.Name,
		Attrs: map[string]any{
			"name":                           inst.Name,
			"project":                        projectID,
			"database_version":               strings.ToUpper(inst.DatabaseVersion),
			"state":                          inst.State,
			"backup_enabled":                 bc.Enabled,
			"backup_retention_days":          bc.BackupRetentionSettings.RetainedBackups,
			"point_in_time_recovery_enabled": pitr,
			"deletion_protection":            inst.Settings.DeletionProtectionEnabled,
		},
	}
}
