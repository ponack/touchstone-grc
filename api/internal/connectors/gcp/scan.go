package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ponack/touchstone/internal/connectors"
)

// Scan dispatches to each sub-scanner and aggregates resources.
// Each sub-scanner is independent — a Workspace-less setup still
// runs (returning project-scoped resources only) once those
// scanners land.
func (Connector) Scan(ctx context.Context, cfgRaw, secretRaw json.RawMessage) (*connectors.ScanResult, error) {
	var cfg PublicConfig
	if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if len(secretRaw) == 0 {
		return nil, errors.New("gcp scan: missing secret")
	}
	var sec Secret
	if err := json.Unmarshal(secretRaw, &sec); err != nil {
		return nil, fmt.Errorf("decode secret: %w", err)
	}

	res := &connectors.ScanResult{}

	users, err := scanWorkspaceUsers(ctx, cfg, sec)
	if err != nil {
		return nil, err
	}
	res.Resources = append(res.Resources, users...)

	buckets, err := scanStorage(ctx, cfg, sec)
	if err != nil {
		return nil, err
	}
	res.Resources = append(res.Resources, buckets...)

	firewalls, err := scanFirewalls(ctx, cfg, sec)
	if err != nil {
		return nil, err
	}
	res.Resources = append(res.Resources, firewalls...)

	sinks, err := scanLogging(ctx, cfg, sec)
	if err != nil {
		return nil, err
	}
	res.Resources = append(res.Resources, sinks...)

	scc, err := scanSCC(ctx, cfg, sec)
	if err != nil {
		return nil, err
	}
	res.Resources = append(res.Resources, scc...)

	sqlInstances, err := scanCloudSQL(ctx, cfg, sec)
	if err != nil {
		return nil, err
	}
	res.Resources = append(res.Resources, sqlInstances...)

	serviceAccounts, err := scanServiceAccounts(ctx, cfg, sec)
	if err != nil {
		return nil, err
	}
	res.Resources = append(res.Resources, serviceAccounts...)

	return res, nil
}
