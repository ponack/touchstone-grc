// Package audit writes append-only events to the partitioned audit_events
// table. The DB-level rules (ON UPDATE / ON DELETE DO INSTEAD NOTHING) make
// the log tamper-resistant; this package is the single application-side
// write path so all events route through one schema.
package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Event struct {
	ActorID      *uuid.UUID
	ActorType    string // user | system | scanner | api_token
	Action       string // e.g. auth.login.success, evidence.collected
	ResourceID   string
	ResourceType string
	OrgID        *uuid.UUID
	IPAddress    string
	Context      json.RawMessage
}

// Record persists an audit event. Errors are logged but never returned —
// audit failures must not break the action being audited. Callers should
// still pass a reasonable context so cancellation works.
func Record(ctx context.Context, pool *pgxpool.Pool, e Event) {
	if e.ActorType == "" {
		e.ActorType = "user"
	}
	if len(e.Context) == 0 {
		e.Context = json.RawMessage("{}")
	}

	var ip *netip.Addr
	if e.IPAddress != "" {
		if addr, err := netip.ParseAddr(e.IPAddress); err == nil {
			ip = &addr
		}
	}

	_, err := pool.Exec(ctx, `
		INSERT INTO audit_events
			(actor_id, actor_type, action, resource_id, resource_type, org_id, ip_address, context)
		VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''), $6, $7, $8)
	`, e.ActorID, e.ActorType, e.Action, e.ResourceID, e.ResourceType, e.OrgID, ip, e.Context)
	if err != nil {
		slog.Error("audit.Record failed", "action", e.Action, "err", err)
	}
}
