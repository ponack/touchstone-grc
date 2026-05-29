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
	storageHost      = "https://storage.googleapis.com"
	storageReadScope = "https://www.googleapis.com/auth/devstorage.read_only"
	storagePath      = "/storage/v1/b"
	bucketsPageSize  = 200

	// IAM members that mean "the public internet".
	memberAllUsers              = "allUsers"
	memberAllAuthenticatedUsers = "allAuthenticatedUsers"
)

// scanStorage enumerates Cloud Storage buckets in the configured
// project and surfaces, per bucket, the signals CC6.6 + CC6.7 care
// about: the public-access-prevention gate, uniform bucket-level
// access, any IAM bindings to allUsers / allAuthenticatedUsers, and
// the presence of a CMEK default encryption key.
//
// Required role: roles/storage.legacyBucketReader (project-scoped)
// — grants buckets.list, buckets.get, and buckets.getIamPolicy.
func scanStorage(ctx context.Context, cfg PublicConfig, sec Secret) ([]connectors.Resource, error) {
	jwtCfg, err := google.JWTConfigFromJSON([]byte(sec.ServiceAccountKeyJSON), storageReadScope)
	if err != nil {
		return nil, fmt.Errorf("gcp: parse SA key for storage client: %w", err)
	}
	client := jwtCfg.Client(ctx)
	client.Timeout = 60 * time.Second

	buckets, err := listBuckets(ctx, client, cfg.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("storage buckets.list: %w", err)
	}

	out := make([]connectors.Resource, 0, len(buckets))
	for _, b := range buckets {
		publicMembers, err := bucketPublicIAMMembers(ctx, client, b.Name)
		if err != nil {
			slog.Warn("gcp storage iam policy fetch failed", "bucket", b.Name, "err", err)
			// Keep going with empty bindings — the
			// publicAccessPrevention signal alone is still useful.
			publicMembers = nil
		}
		out = append(out, buildBucketResource(b, cfg.ProjectID, publicMembers))
	}

	slog.Info("gcp storage scan complete", "buckets", len(out), "project", cfg.ProjectID)
	return out, nil
}

// ── Internals ───────────────────────────────────────────────────────

type bucket struct {
	Name             string `json:"name"`
	Location         string `json:"location"`
	IamConfiguration struct {
		PublicAccessPrevention   string `json:"publicAccessPrevention"`
		UniformBucketLevelAccess struct {
			Enabled bool `json:"enabled"`
		} `json:"uniformBucketLevelAccess"`
	} `json:"iamConfiguration"`
	Encryption struct {
		DefaultKmsKeyName string `json:"defaultKmsKeyName"`
	} `json:"encryption"`
}

type bucketsPage struct {
	Items         []bucket `json:"items"`
	NextPageToken string   `json:"nextPageToken"`
}

type iamPolicy struct {
	Bindings []struct {
		Role    string   `json:"role"`
		Members []string `json:"members"`
	} `json:"bindings"`
}

func listBuckets(ctx context.Context, client *http.Client, projectID string) ([]bucket, error) {
	var out []bucket
	q := url.Values{}
	q.Set("project", projectID)
	q.Set("maxResults", fmt.Sprintf("%d", bucketsPageSize))
	next := ""
	for {
		if next != "" {
			q.Set("pageToken", next)
		}
		page, err := fetchBucketsPage(ctx, client, storageHost+storagePath+"?"+q.Encode())
		if err != nil {
			return out, err
		}
		out = append(out, page.Items...)
		if page.NextPageToken == "" {
			return out, nil
		}
		next = page.NextPageToken
	}
}

func fetchBucketsPage(ctx context.Context, client *http.Client, url string) (bucketsPage, error) {
	body, err := gcpGET(ctx, client, url)
	if err != nil {
		return bucketsPage{}, err
	}
	var page bucketsPage
	if err := json.Unmarshal(body, &page); err != nil {
		return bucketsPage{}, fmt.Errorf("decode buckets page: %w", err)
	}
	return page, nil
}

func bucketPublicIAMMembers(ctx context.Context, client *http.Client, bucketName string) ([]string, error) {
	url := storageHost + storagePath + "/" + bucketName + "/iam"
	body, err := gcpGET(ctx, client, url)
	if err != nil {
		return nil, err
	}
	var pol iamPolicy
	if err := json.Unmarshal(body, &pol); err != nil {
		return nil, fmt.Errorf("decode iam policy: %w", err)
	}
	seen := map[string]struct{}{}
	out := []string{}
	for _, binding := range pol.Bindings {
		for _, m := range binding.Members {
			if m != memberAllUsers && m != memberAllAuthenticatedUsers {
				continue
			}
			key := binding.Role + "|" + m
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, binding.Role+":"+m)
		}
	}
	return out, nil
}

func gcpGET(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
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

func buildBucketResource(b bucket, projectID string, publicBindings []string) connectors.Resource {
	prevention := b.IamConfiguration.PublicAccessPrevention
	if prevention == "" {
		// API returns "" when the value has never been set; semantically
		// equivalent to "inherited" — gate left open.
		prevention = "inherited"
	}
	return connectors.Resource{
		Type: "gcp.storage.bucket",
		ID:   "gcp-storage://" + projectID + "/buckets/" + b.Name,
		Attrs: map[string]any{
			"name":                        b.Name,
			"project":                     projectID,
			"location":                    b.Location,
			"public_access_prevention":    prevention,
			"uniform_bucket_level_access": b.IamConfiguration.UniformBucketLevelAccess.Enabled,
			"default_kms_key_name":        b.Encryption.DefaultKmsKeyName,
			"iam_public_bindings":         publicBindings,
		},
	}
}
