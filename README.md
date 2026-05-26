<!-- markdownlint-disable MD033 -->
# Touchstone GRC

<p align="center">
  <img src="assets/logo-primary-dark-512.png" alt="Touchstone GRC" width="200" />
</p>

<p align="center">
  Self-hosted compliance evidence collector. Vanta / Drata / Secureframe alternative.
  <br />
  By <a href="https://www.forgedinfeatherstechnology.com">Forged in Feathers Technology</a>.
</p>

---

Sibling project to [Crucible IAP](https://github.com/ponack/crucible-iap). Standalone — runs without Crucible. Optional integration via public API in a later phase.

> **Status:** Pre-alpha. Phase 0 (foundation) is complete; Phase 1 (AWS + SOC 2) is in progress.

## What it does

- Connects (read-only) to your cloud + SaaS estate: AWS, GCP, Azure, GitHub, Okta, Google Workspace, M365, …
- Runs scheduled scans, collects evidence artifacts, evaluates them against control packs
- Ships control packs for SOC 2, CIS, HIPAA, PCI-DSS, ISO 27001
- Append-only evidence trail, auditor read-only role, auditor-export reports
- Optional integrations: SIEM streaming, BYOK (AWS KMS / Vault Transit / Azure KV)

## Stack

- Backend: Go + Echo, embedded OPA
- Frontend: SvelteKit 5 + Tailwind v4
- DB: PostgreSQL + River job queue
- Object storage: MinIO (S3-compatible)
- Auth: OIDC PKCE (Authentik bundled, or any generic OIDC IdP)
- Reverse proxy: Caddy (bundled, optional)
- Scan isolation: ephemeral Docker containers (read-only, no-new-privileges, cap-drop ALL)

## Quickstart (once implemented)

```bash
cp .env.example .env
# fill in TOUCHSTONE_BASE_URL, TOUCHSTONE_SECRET_KEY, POSTGRES_PASSWORD, MINIO_SECRET_KEY
docker network create touchstone-scanner
docker compose up -d
```

## Roadmap

- **Phase 0** — Foundation: auth, RBAC (admin/member/auditor), audit log, OPA, multi-org. *(complete)*
- **Phase 1** — MVP: AWS connector + SOC 2 control pack subset. *(in progress)*
- **Phase 2** — Connector breadth: GitHub, Google Workspace, Okta, M365.
- **Phase 3** — Framework breadth: CIS AWS, HIPAA, PCI-DSS, ISO 27001.
- **Phase 4** — GRC surface: personnel, asset inventory, vendor register, risk register.
- **Phase 5** — Trust Center: public compliance page + questionnaire automation.
- **Phase 6** — Optional Crucible IAP connector (scans Crucible stacks/runs/policies as evidence).

## License

AGPL-3.0. Same as Crucible IAP.
