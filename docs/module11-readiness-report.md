# Module 11 operational readiness report

Assessment date: 2026-10-27. **Status: implementation and synthetic recovery checks complete; live trial is not authorized by this report.** The repository has no observed Workspace administrator grant, enrolled real mailbox, DNS/TLS deployment, or live Gmail result in this environment. Start with `GMAIL_RESPONSE_ENABLED=0`.

## Verified locally

| Check | Result |
| --- | --- |
| Full PostgreSQL-backed `core` suite | 121 tests passed, including five focused operational tests. The test runner applied the complete migration chain to an empty PostgreSQL test database. |
| Migration consistency | `makemigrations --check --dry-run`: no changes detected. `migrate --check` passed on a restored disposable database. |
| Database recovery drill | PostgreSQL 17 local disposable source was migrated through `core.0013` and populated with synthetic development fixtures, dumped with `pg_dump -Fc`, restored to a separate empty database with `pg_restore --exit-on-error`; restored counts were 1 organization, 2 mailboxes, 2 cases, 2 artifacts, 0 scheduler heartbeats. No real mail or credentials were used. |
| Private-file recovery drill | A synthetic private-file tar archive was extracted to a separate directory; source/restored SHA-256 values matched. The live Compose backup script and off-host encrypted storage were not exercised. |
| Deployment configuration | `docker compose -f compose.yaml -f compose.trial.yaml config --quiet` passed with a synthetic domain. `collectstatic --noinput --clear` succeeded after removing a missing Bootstrap source-map reference. |
| Django deployment check | `manage.py check --deploy` exited successfully with two intentional warnings: HSTS subdomains and preload are disabled because the trial does not control every subdomain or preload commitment. TLS termination itself was not exercised. |

## Controls delivered

The trial overlay uses Caddy HTTPS, Gunicorn, WhiteNoise, HTTPS-aware Django proxy settings, secure cookies, HSTS, private artifact storage, and a response-disabled example configuration. `trial_readiness` checks offline security settings, key isolation, database connectivity, and exact enrolled mailbox scope. A worker-executed scheduler heartbeat is reported by `gmail_health`. Daily artifact retention is disabled by default outside the trial example and can be previewed; it writes an audit event and resumes interrupted file deletion. `scripts/trial_backup.ps1` refuses to run while web/worker/beat writers are active and creates a database dump, private artifact archive, and hashes. The operations guide includes DWD/OAuth setup, allowlist limitation, incident runbooks, monitoring, and start/suspend/stop commands.

## Unverified or blocked live gates

1. Administrator must supply an organization-owned Cloud project, enable Gmail API, configure two DWD client IDs with the exact documented scopes, protect and rotate separate keys, and approve named enrolled mailboxes. The actual enrolled scope is **none observed here**.
2. Administrator/compliance owner must determine Google's OAuth verification and restricted-data handling requirements for this particular internal trial. External public multi-organization distribution requires a separate assessment. The repository cannot claim Google approval.
3. If Google OIDC dashboard login is required, it must be implemented and tested separately. Current dashboard authentication is Django login plus organization membership and role checks.
4. Deploy the profile on a trial host, verify DNS, HTTPS certificate, proxy trust boundary, external port restrictions, backup encryption/off-host transfer, scheduled backup, restore with real trial-sized encrypted data in a separate environment, and storage/file ACLs.
5. Exercise real Gmail initial/incremental polling, DWD revocation, 429 and 404 handling, mixed-thread message-level label changes, restoration conflicts, automatic rate limits and circuit breaker, and a response suspension drill. Existing mocks and synthetic database tests cannot establish these outcomes.
6. Approve a retention policy for PostgreSQL metadata and backup sets. The implemented daily command prunes original/derived **private files** by organization retention age but retains case, evidence, feedback, and audit rows. Do not claim full data erasure.

## Decision

The code and local tests support a **controlled setup phase**. Keep automatic response off until an administrator records the above live checks, exact mailbox list, provider grant, recovery drill, and incident contacts. Use the steps in [trial operations](module11-trial-operations.md) to start observation, enable automatic response, suspend it, and stop/revoke the trial.
