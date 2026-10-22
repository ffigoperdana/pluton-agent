# Coding instructions

- Work on a feature branch; do not publish, tag, deploy or access real Agents
  without explicit authorization. Use only isolated synthetic installations.
- Preserve Apache-2.0 attribution and independently developed public-source code.
  Never use proprietary Pluton editions or commit credentials, real infrastructure,
  identity/config/policy state, generated artifacts or private evidence.
- Agent runtime authority is this repository after the separately reviewed cutover.
  Keep source contract/provenance changes explicit and versioned. Do not replace
  SHA-256, TLS, host approval, capability, lease, ownership, permission, cancellation,
  exclusion, rollback or durability checks with permissive fallbacks.
- Use Node 22.23.4 (22.18.0 only for isolated prior-runtime upgrade fixtures),
  pinned pnpm 10.20.0 and the frozen minimal lockfile. Do not add
  server/frontend dependencies or global installation steps.
- Read README and docs/EXTRACTION_AUDIT.md before modifying installers. Installation
  is fresh-only; upgrades require protected standalone provenance and clean source.
  Existing monorepo Agents require a separately approved migration.
- Run relevant unit/contracts, installer safety and Ubuntu checks. Report mock
  systemd/server boundaries and skips accurately; CI is validation, not deployment.
