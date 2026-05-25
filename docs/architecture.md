# Touchstone — Architecture (v0)

## Boundaries

Touchstone is fully **standalone**. It runs on a host that has never heard of Crucible IAP. Any future Crucible integration goes through Touchstone's public HTTP API + webhooks — never shared deploy units, never shared databases, never shared Go modules in the same binary.

## Process model

| Process | Binary command | Responsibility |
|---------|----------------|----------------|
| `touchstone-api` | `touchstone serve` | HTTP API, OIDC handler, OPA evaluator, audit log writer |
| `touchstone-worker` | `touchstone worker` | River job runner: scheduled scans, evidence collection, report generation |
| `touchstone-ui` | SvelteKit SSR (separate image) | Web UI |

The API and worker share the same binary and codebase; the command selects which subsystem boots.

## Storage

- **Postgres** — primary store: orgs, users, API tokens, audit log (partitioned), River queue, future tables for connectors / frameworks / controls / scans / evidence / exceptions / personnel / assets / vendors / risks.
- **MinIO** — `touchstone-evidence` bucket (raw evidence artifacts, content-addressed) + `touchstone-artifacts` bucket (auditor exports, generated reports).

## Network model

| Network | Members | Purpose |
|---------|---------|---------|
| `frontend` | caddy, api, ui, grafana | Externally reachable surface |
| `backend` (internal) | api, worker, postgres, minio, prometheus, grafana | DB + object storage traffic |
| `scanner` (external) | api, worker, ephemeral scan containers | Connector scan containers reach back to the API + MinIO without traversing the public proxy |

`scanner` is declared external in `docker-compose.yml` so it can be created once via `docker network create touchstone-scanner` and survives compose project recreation.

## Connector model (Phase 1+)

Each connector implements:

```go
type Connector interface {
    Kind() string                                       // "aws", "github", "okta", ...
    Scan(ctx context.Context, cfg json.RawMessage) (ResourceStream, error)
}
```

Scans run in **ephemeral Docker containers** (`--read-only`, `--no-new-privileges`, `--cap-drop ALL`, `tmpfs` workspace, per-job scoped JWT) reachable on the `scanner` network. They stream normalized resources back to the worker, which writes:

1. Raw artifacts → MinIO (content-addressed key)
2. Normalized resources → Postgres (for OPA queries)
3. One `evidence_items` row per control × resource hit

## Control evaluation

Controls are OPA policies bundled per framework (SOC 2, CIS, HIPAA, PCI-DSS, ISO 27001). The worker queries the bundle with the normalized resource set; each result becomes an evidence item with `status ∈ {pass, fail, partial, na}`. Exceptions (acknowledged gaps with expiry + audit chain) suppress a fail without losing it.

## Audit trail

`audit_events` is partitioned monthly, append-only at the DB level (`ON UPDATE / ON DELETE DO INSTEAD NOTHING`). Application-layer `StartPartitionMaintainer` creates current + 2 months ahead. Critical so the audit log itself can be **evidence for auditor controls** (CC4.1, CC7.2, etc.).

## Future Crucible integration (Phase 6)

A `crucible` connector type queries the Crucible IAP public API for stacks, runs, policies, drift, approvals, and audit events. Maps to controls like:

- *"All IaC changes require human approval"* — Crucible runs with `approved_by IS NOT NULL`
- *"Infrastructure changes are logged"* — Crucible audit event coverage
- *"Policy gates are enforced on production stacks"* — Crucible stack_policies attached

No shared deployment, no shared DB. Just a connector configured with a Crucible API token.
