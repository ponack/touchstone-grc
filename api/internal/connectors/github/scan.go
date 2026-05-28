package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/ponack/touchstone/internal/connectors"
)

const (
	apiHost      = "https://api.github.com"
	acceptHeader = "application/vnd.github+json"
	apiVerHeader = "2022-11-28"
)

// Scan produces a single github.org resource with the org-level 2FA
// requirement flag and the count of members with 2FA disabled.
//
// "members with 2FA disabled" only resolves when the PAT has admin
// access to the org (read:org scope plus the requesting user is an
// org admin). For PATs without that visibility, the filter
// endpoint returns 200 OK with an empty list — the org-level flag
// alone is still meaningful evidence.
func (Connector) Scan(ctx context.Context, cfgRaw, secretRaw json.RawMessage) (*connectors.ScanResult, error) {
	var cfg PublicConfig
	if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if len(secretRaw) == 0 {
		return nil, errors.New("github scan: missing secret")
	}
	var sec Secret
	if err := json.Unmarshal(secretRaw, &sec); err != nil {
		return nil, fmt.Errorf("decode secret: %w", err)
	}

	client := &http.Client{Timeout: 60 * time.Second}

	orgInfo, err := getOrg(ctx, client, cfg.Org, sec.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("github get org: %w", err)
	}

	disabled, err := listMembersWithout2FA(ctx, client, cfg.Org, sec.AccessToken)
	if err != nil {
		slog.Warn("github members 2fa filter failed", "org", cfg.Org, "err", err)
		// Continue with empty list — the org-level flag is still
		// usable evidence, and a PAT lacking org-admin scope is a
		// real-world scenario.
		disabled = nil
	}

	res := &connectors.ScanResult{
		Resources: []connectors.Resource{
			{
				Type: "github.org",
				ID:   "github://orgs/" + cfg.Org,
				Attrs: map[string]any{
					"login":                          cfg.Org,
					"two_factor_requirement_enabled": orgInfo.TwoFactorRequirementEnabled,
					"members_without_2fa":            disabled,
					"members_without_2fa_count":      len(disabled),
				},
			},
		},
	}
	slog.Info("github scan complete", "org", cfg.Org, "two_factor_required", orgInfo.TwoFactorRequirementEnabled, "members_without_2fa", len(disabled))
	return res, nil
}

// ── Internals ───────────────────────────────────────────────────────

type orgResponse struct {
	Login                       string `json:"login"`
	TwoFactorRequirementEnabled bool   `json:"two_factor_requirement_enabled"`
}

type memberResponse struct {
	Login string `json:"login"`
}

func getOrg(ctx context.Context, client *http.Client, org, token string) (orgResponse, error) {
	url := apiHost + "/orgs/" + org
	body, _, err := githubGET(ctx, client, url, token)
	if err != nil {
		return orgResponse{}, err
	}
	var o orgResponse
	if err := json.Unmarshal(body, &o); err != nil {
		return orgResponse{}, fmt.Errorf("decode org: %w", err)
	}
	return o, nil
}

func listMembersWithout2FA(ctx context.Context, client *http.Client, org, token string) ([]string, error) {
	out := []string{}
	url := apiHost + "/orgs/" + org + "/members?filter=2fa_disabled&per_page=100"
	for url != "" {
		body, link, err := githubGET(ctx, client, url, token)
		if err != nil {
			return nil, err
		}
		var page []memberResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("decode members: %w", err)
		}
		for _, m := range page {
			out = append(out, m.Login)
		}
		url = nextLink(link)
	}
	return out, nil
}

func githubGET(ctx context.Context, client *http.Client, url, token string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", acceptHeader)
	req.Header.Set("X-GitHub-Api-Version", apiVerHeader)

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, resp.Header.Get("Link"), nil
}

// nextLink parses RFC 5988 Link headers (the GitHub pagination
// idiom) and returns the URL of the rel="next" entry, or "" if
// there is none.
var nextLinkRE = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func nextLink(link string) string {
	if link == "" {
		return ""
	}
	m := nextLinkRE.FindStringSubmatch(link)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}
