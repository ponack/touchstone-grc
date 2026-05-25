// Package connectors defines the integration interface Touchstone uses
// to talk to external systems (AWS, GitHub, Okta, …). A connector is
// pure config + a small surface for shaping that config; the actual
// resource-scanning logic is added by individual connector
// implementations in subpackages and wired into the registry at
// startup.
package connectors

import "encoding/json"

// Kind identifies a connector implementation. New kinds must be added
// here as constants so the HTTP layer can validate inbound requests
// before the database accepts them.
type Kind string

const (
	KindAWS Kind = "aws"
)

// Connector is the surface every implementation must provide. Scan,
// drift-detection, and resource enumeration land here in follow-up PRs.
type Connector interface {
	Kind() Kind

	// Validate parses raw inbound config from the API, sanity-checks
	// it, and splits the result into:
	//   - cfg: the non-sensitive subset that is safe to persist in the
	//          connectors.config column and to return on GET.
	//   - secret: the sensitive subset (credentials, tokens) that the
	//          caller will encrypt and store in connectors.secrets_ref.
	// secret may be nil when the kind has no credentials (e.g. an
	// anonymous public-endpoint connector).
	Validate(raw json.RawMessage) (cfg, secret json.RawMessage, err error)
}

// Registry maps a Kind to its Connector implementation. The server
// builds one Registry at boot and passes it into the HTTP handler so
// adding a new connector kind is a one-line change at startup.
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
