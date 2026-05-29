package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2/google"

	"github.com/ponack/touchstone/internal/connectors"
)

const (
	computeHost      = "https://compute.googleapis.com"
	computeReadScope = "https://www.googleapis.com/auth/compute.readonly"
	firewallsPath    = "/compute/v1/projects/%s/global/firewalls"
	firewallsPageSz  = 200
)

// scanFirewalls enumerates the project's global VPC firewall rules
// and emits one gcp.compute.firewall resource per *ingress allow*
// rule (disabled rules and egress rules are dropped — CC6.6 only
// cares about world-reachable inbound paths).
//
// Required role: roles/compute.viewer (project-scoped).
func scanFirewalls(ctx context.Context, cfg PublicConfig, sec Secret) ([]connectors.Resource, error) {
	jwtCfg, err := google.JWTConfigFromJSON([]byte(sec.ServiceAccountKeyJSON), computeReadScope)
	if err != nil {
		return nil, fmt.Errorf("gcp: parse SA key for compute client: %w", err)
	}
	client := jwtCfg.Client(ctx)
	client.Timeout = 60 * time.Second

	rules, err := listFirewalls(ctx, client, cfg.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("compute firewalls.list: %w", err)
	}

	out := make([]connectors.Resource, 0, len(rules))
	for _, r := range rules {
		if r.Disabled {
			continue
		}
		if !strings.EqualFold(r.Direction, "INGRESS") {
			continue
		}
		if len(r.Allowed) == 0 {
			continue
		}
		out = append(out, buildFirewallResource(r, cfg.ProjectID))
	}

	slog.Info("gcp compute firewall scan complete", "ingress_allow_rules", len(out), "project", cfg.ProjectID)
	return out, nil
}

// ── Internals ───────────────────────────────────────────────────────

type firewallAllowed struct {
	IPProtocol string   `json:"IPProtocol"`
	Ports      []string `json:"ports"`
}

type firewallRule struct {
	Name         string            `json:"name"`
	Network      string            `json:"network"`
	Priority     int               `json:"priority"`
	Direction    string            `json:"direction"`
	Disabled     bool              `json:"disabled"`
	SourceRanges []string          `json:"sourceRanges"`
	Allowed      []firewallAllowed `json:"allowed"`
}

type firewallsPage struct {
	Items         []firewallRule `json:"items"`
	NextPageToken string         `json:"nextPageToken"`
}

func listFirewalls(ctx context.Context, client *http.Client, projectID string) ([]firewallRule, error) {
	base := fmt.Sprintf(computeHost+firewallsPath+"?maxResults=%d", projectID, firewallsPageSz)
	var out []firewallRule
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
		var page firewallsPage
		if err := json.Unmarshal(body, &page); err != nil {
			return out, fmt.Errorf("decode firewalls page: %w", err)
		}
		out = append(out, page.Items...)
		if page.NextPageToken == "" {
			return out, nil
		}
		next = page.NextPageToken
	}
}

// buildFirewallResource flattens a firewall rule's `allowed` slice
// into a list of (protocol, from_port, to_port) triples. Each entry
// in `allowed` may carry zero or more port specs ("22", "1024-2000");
// when ports is empty the protocol allows all ports.
func buildFirewallResource(r firewallRule, projectID string) connectors.Resource {
	ingress := make([]map[string]any, 0, len(r.Allowed))
	for _, a := range r.Allowed {
		proto := strings.ToLower(a.IPProtocol)
		if len(a.Ports) == 0 {
			ingress = append(ingress, map[string]any{
				"protocol":  proto,
				"from_port": 0,
				"to_port":   65535,
			})
			continue
		}
		for _, p := range a.Ports {
			from, to := parsePortRange(p)
			ingress = append(ingress, map[string]any{
				"protocol":  proto,
				"from_port": from,
				"to_port":   to,
			})
		}
	}
	srcs := make([]any, 0, len(r.SourceRanges))
	for _, s := range r.SourceRanges {
		srcs = append(srcs, s)
	}
	return connectors.Resource{
		Type: "gcp.compute.firewall",
		ID:   "gcp-compute://" + projectID + "/firewalls/" + r.Name,
		Attrs: map[string]any{
			"name":          r.Name,
			"network":       r.Network,
			"priority":      r.Priority,
			"direction":     "INGRESS",
			"source_ranges": srcs,
			"ingress_rules": ingress,
		},
	}
}

// parsePortRange handles GCP's port spec strings: "22" or "1024-2000".
// A blank string (the "all ports of protocol" case) is handled at the
// caller — we don't fold it in here so the caller can attach the
// 0-65535 sentinel in one place.
func parsePortRange(s string) (int, int) {
	if i := strings.IndexByte(s, '-'); i >= 0 {
		from, _ := strconv.Atoi(s[:i])
		to, _ := strconv.Atoi(s[i+1:])
		return from, to
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, 0
	}
	return n, n
}
