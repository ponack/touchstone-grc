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
  <a href="https://github.com/ponack/touchstone-grc/releases/tag/v0.4.0"><img src="https://img.shields.io/badge/release-v0.4.0-C49020?style=flat-square" alt="v0.4.0" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square" alt="AGPL-3.0" /></a>
</p>

---

Sibling project to [Crucible IAP](https://github.com/ponack/crucible-iap). Standalone — runs without Crucible. Optional integration via public API in a later phase.

> **Status:** v0.4.0 shipped 2026-05-28 — Phase 4 complete. **All 11 of 11 SOC 2 2017 controls in the shipped pack now run real evaluations**, combining AWS + Azure cloud depth with procedural evidence from GitHub (MFA enforcement for CC6.2) and Linear / Jira (incident response ticket workflow for CC7.4). GCP support mirrors the cloud-depth shape in a follow-up phase.

## What it does

- Connects (read-only) to your cloud + SaaS estate. **AWS** and **Azure** are fully wired today; GCP, GitHub, Jira/Linear, Okta, Google Workspace, M365 on the roadmap.
- Runs scans, collects evidence artifacts, evaluates them against control packs via embedded OPA.
- Ships the **SOC 2 2017** control pack today; CIS AWS / HIPAA / PCI-DSS / ISO 27001 on the roadmap.
- Append-only evidence trail, auditor read-only role, auditor-grade CSV + PDF exports.
- Exception workflow for acknowledged gaps without erasing the audit trail.

## SOC 2 coverage today

| Control | Status | AWS source | Azure source |
| ------- | ------ | ---------- | ------------ |
| CC6.1 — Logical access controls | ✅ real | IAM users / MFA | AD users / MFA registration |
| CC6.2 — New user access provisioning | ✅ real | GitHub org 2FA requirement + members-without-2FA | GitHub org 2FA requirement + members-without-2FA |
| CC6.3 — User access revocation | ✅ real | IAM access key rotation | App registration secrets/certs |
| CC6.6 — Network access controls | ✅ real | S3 public access + EC2 SG ingress | Storage public access + NSG ingress |
| CC6.7 — Restricted data transmission | ✅ real | S3 default encryption | Storage HTTPS-only + TLS 1.2+ |
| CC6.8 — Malicious software prevention | ✅ real | GuardDuty | Defender for Cloud |
| CC7.1 — Vulnerability detection | ✅ real | Security Hub + standards | Defender for Cloud |
| CC7.2 — System monitoring | ✅ real | CloudTrail multi-region + log validation | Activity Log diagnostic settings |
| CC7.3 — Security event analysis | ✅ real | GuardDuty | Defender for Cloud |
| CC7.4 — Incident response | ✅ real | Linear / Jira incident ticket workflow (SLA window) | Linear / Jira incident ticket workflow (SLA window) |
| CC7.5 — Recovery procedures | ✅ real | RDS backups + deletion protection | Azure SQL short-term retention |

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
ghcr.io/ponack/touchstone-api:0.4.0
ghcr.io/ponack/touchstone-ui:0.4.0
```

Running behind an external reverse proxy (OPNsense, Traefik, nginx, separate Caddy)?
See [docs/reverse-proxy.md](docs/reverse-proxy.md) for the routing rules + a working
Caddy / nginx snippet.

## Roadmap

- **Phase 0** — Foundation: auth, RBAC (admin/member/auditor), audit log, OPA, multi-org. *(complete)*
- **Phase 1** — MVP: AWS connector + SOC 2 control pack subset + auditor export. *(complete — v0.1.0)*
- **Phase 2** — AWS depth: S3, EC2 SGs, CloudTrail, GuardDuty, Security Hub, RDS. *(complete — v0.2.0)*
- **Phase 3** — Azure parity: AD, Storage, App Registrations, NSGs, Activity Log, Defender for Cloud, Azure SQL. *(complete — v0.3.0)*
- **Phase 4** — Procedural connectors: GitHub (CC6.2 MFA enforcement) + Linear + Jira (CC7.4 incident response). *(complete — v0.4.0)*
- **Phase 5** — GCP series: mirrors Azure cadence (IAM, Cloud Storage, VPC firewall, Cloud Audit Logs, Security Command Center, Cloud SQL).
- **Phase 6** — Framework breadth: CIS AWS, HIPAA, PCI-DSS, ISO 27001 — same evidence, new control mappings.
- **Phase 7** — GRC surface: personnel, asset inventory, vendor register, risk register.
- **Phase 8** — Trust Center: public compliance page + questionnaire automation.
- **Phase 9** — Optional Crucible IAP connector (scans Crucible stacks / runs / policies as evidence).

## License

AGPL-3.0. Same as Crucible IAP.
