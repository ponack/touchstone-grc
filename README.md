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

<p align="center">
  <a href="https://github.com/ponack/touchstone-grc/releases/tag/v0.2.0"><img src="https://img.shields.io/badge/release-v0.2.0-C49020?style=flat-square" alt="v0.2.0" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square" alt="AGPL-3.0" /></a>
</p>

---

Sibling project to [Crucible IAP](https://github.com/ponack/crucible-iap). Standalone — runs without Crucible. Optional integration via public API in a later phase.

> **Status:** v0.2.0 shipped 2026-05-27 — Phase 2 complete. AWS connector covers IAM, S3, EC2 security groups, CloudTrail, GuardDuty, Security Hub, RDS. **9 of 11 SOC 2 2017 controls** in the shipped pack now have real AWS-backed evaluations. The two remaining (CC6.2 user-access provisioning, CC7.4 incident response) need procedural evidence and ship with the Phase 3 GitHub/Jira connector.

## What it does

- Connects (read-only) to your cloud + SaaS estate. **AWS** is fully wired today; Azure, GCP, GitHub, Okta, Google Workspace, M365 on the roadmap.
- Runs scans, collects evidence artifacts, evaluates them against control packs via embedded OPA.
- Ships the **SOC 2 2017** control pack today; CIS AWS / HIPAA / PCI-DSS / ISO 27001 on the roadmap.
- Append-only evidence trail, auditor read-only role, auditor-grade CSV + PDF exports.
- Exception workflow for acknowledged gaps without erasing the audit trail.

## SOC 2 coverage today

| Control | Status | AWS source |
|---------|--------|------------|
| CC6.1 — Logical access controls | ✅ real | IAM users / MFA / console access |
| CC6.2 — New user access provisioning | ⏸ procedural — Phase 3 | (needs GitHub/Jira) |
| CC6.3 — User access revocation | ✅ real | IAM access key rotation |
| CC6.6 — Network access controls | ✅ real | S3 public access + EC2 SG ingress |
| CC6.7 — Restricted data transmission | ✅ real | S3 default encryption |
| CC6.8 — Malicious software prevention | ✅ real | GuardDuty detector status |
| CC7.1 — Vulnerability detection | ✅ real | Security Hub + subscribed standards |
| CC7.2 — System monitoring | ✅ real | CloudTrail multi-region + log validation |
| CC7.3 — Security event analysis | ✅ real | GuardDuty detector status |
| CC7.4 — Incident response | ⏸ procedural — Phase 3 | (needs GitHub/Jira) |
| CC7.5 — Recovery procedures | ✅ real | RDS backups + deletion protection |

## Stack

- Backend: Go + Echo, embedded OPA
- Frontend: SvelteKit 5 + Tailwind v4
- DB: PostgreSQL + River job queue
- Object storage: MinIO (S3-compatible)
- Auth: OIDC PKCE (Authentik bundled, or any generic OIDC IdP) + local-auth bootstrap admin
- Reverse proxy: Caddy (bundled, optional)
- Scan isolation: ephemeral Docker containers (read-only, no-new-privileges, cap-drop ALL)

## Quickstart

```bash
git clone https://github.com/ponack/touchstone-grc
cd touchstone-grc
cp .env.example .env
# fill in TOUCHSTONE_BASE_URL, TOUCHSTONE_SECRET_KEY, POSTGRES_PASSWORD, MINIO_SECRET_KEY
docker network create touchstone-scanner
docker compose up -d
```

Or pull pre-built images directly:

```text
ghcr.io/ponack/touchstone-api:0.2.0
ghcr.io/ponack/touchstone-ui:0.2.0
```

Running behind an external reverse proxy (OPNsense, Traefik, nginx, separate Caddy)?
See [docs/reverse-proxy.md](docs/reverse-proxy.md) for the routing rules + a working
Caddy / nginx snippet.

## Roadmap

- **Phase 0** — Foundation: auth, RBAC (admin/member/auditor), audit log, OPA, multi-org. *(complete)*
- **Phase 1** — MVP: AWS connector + SOC 2 control pack subset + auditor export. *(complete — v0.1.0)*
- **Phase 2** — AWS depth: each new service lights up another SOC 2 control. S3, EC2 SGs, CloudTrail, GuardDuty, Security Hub, RDS. *(complete — v0.2.0)*
- **Phase 3** — Cloud breadth + procedural connectors: Azure, GCP, GitHub, Jira/Linear, Okta, Google Workspace.
- **Phase 4** — Framework breadth: CIS AWS, HIPAA, PCI-DSS, ISO 27001 — same AWS evidence, new control mappings.
- **Phase 5** — GRC surface: personnel, asset inventory, vendor register, risk register.
- **Phase 6** — Trust Center: public compliance page + questionnaire automation.
- **Phase 7** — Optional Crucible IAP connector (scans Crucible stacks / runs / policies as evidence).

## License

AGPL-3.0. Same as Crucible IAP.
