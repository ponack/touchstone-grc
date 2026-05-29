// Package connectors defines the integration interface Touchstone uses
// to talk to external systems (AWS, GitHub, Okta, …). A connector
// owns three things: how its config is shaped + validated, how it
// enumerates resources, and (later) how it streams structured logs.
package connectors

import (
	"context"
	"encoding/json"
)

// Kind identifies a connector implementation. New kinds must be added
// here as constants so the HTTP layer can validate inbound requests
// before the database accepts them.
type Kind string

const (
	KindAWS    Kind = "aws"
	KindAzure  Kind = "azure"
	KindGitHub Kind = "github"
	KindLinear Kind = "linear"
	KindJira   Kind = "jira"
	KindGCP    Kind = "gcp"
)

// Resource is one row in the normalized output of a connector scan.
// `Type` is namespaced by kind (e.g. "aws.iam.user"). `ID` is the
// stable identifier the operator would recognise (ARN for AWS, etc).
// `Attrs` is the canonical attribute bag OPA policies query against.
type Resource struct {
	Type  string         `json:"type"`
	ID    string         `json:"id"`
	Attrs map[string]any `json:"attrs"`
}

// ScanResult is what a connector hands back to the worker after a
// scan. The worker stores this verbatim as the MinIO artifact and
// passes Resources to OPA for evaluation.
type ScanResult struct {
	Resources []Resource `json:"resources"`
}

// Connector is the surface every implementation must provide.
type Connector interface {
	Kind() Kind

	// Validate parses raw inbound config from the API, sanity-checks
	// it, and splits the result into:
	//   - cfg: the non-sensitive subset persisted in connectors.config.
	//   - secret: the sensitive subset (credentials) the caller
	//             encrypts and stores in connectors.secrets_ref.
	// secret may be nil when the kind has no credentials.
	Validate(raw json.RawMessage) (cfg, secret json.RawMessage, err error)

	// Scan enumerates the configured target's resources and returns
	// the normalized result. secret may be nil when the connector
	// uses an authentication method that doesn't carry a stored
	// secret (e.g. AWS role assumption from the worker's ambient
	// IAM identity).
	Scan(ctx context.Context, cfg, secret json.RawMessage) (*ScanResult, error)
}

// Registry maps a Kind to its Connector implementation.
type Registry struct {
	byKind map[Kind]Connector
}

func NewRegistry() *Registry {
	return &Registry{byKind: map[Kind]Connector{}}
}

func (r *Registry) Register(c Connector) {
	r.byKind[c.Kind()] = c
}

func (r *Registry) Get(kind Kind) (Connector, bool) {
	c, ok := r.byKind[kind]
	return c, ok
}

// Kinds returns the registered kinds in no particular order.
func (r *Registry) Kinds() []Kind {
	out := make([]Kind, 0, len(r.byKind))
	for k := range r.byKind {
		out = append(out, k)
	}
	return out
}
