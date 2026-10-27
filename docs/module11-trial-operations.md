# Module 11: limited Google Workspace trial operations

This is a **single Workspace, explicitly enrolled mailbox trial**. It uses Gmail `users.history.list` polling, stores original MIME privately, and can label individual messages and optionally remove `INBOX` after the response policy qualifies them. It is not pre-delivery protection or a secure quarantine. Start with automatic response disabled. A production operator must complete the administrator and live checks below before processing real mail.

## Scope and authorization decision

The selected Gmail mode is **two service accounts with Workspace domain-wide delegation (DWD)**, not per-user OAuth. The ingestion service account requests **only** `https://www.googleapis.com/auth/gmail.readonly`. The distinct response service account requests exactly `https://www.googleapis.com/auth/gmail.modify.restricted` for administrator-delegated `users.messages.modify`, and `https://www.googleapis.com/auth/gmail.labels` to create/read the custom label. `gmail.modify.restricted` is documented for administrator message modification; do not replace it with `gmail.modify`, `https://mail.google.com/`, or another broader scope to make a failed grant work. The API must be enabled for the Cloud project. References: [Gmail scope catalog](https://developers.google.com/workspace/gmail/api/auth/scopes), [messages.modify](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/modify), [labels.create](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.labels/create).

The dashboard currently uses Django login and organization memberships. **Google OIDC dashboard login is not implemented or configured in this repository**; it is not supplied by Gmail DWD. If the trial requires OIDC, implement and test a separate Google OIDC client with `openid email profile`, exact HTTPS redirect URI, signed ID-token validation (issuer, audience, expiry, nonce, hosted domain), explicit pre-linked users, and existing membership/role checks before enabling it. Do not treat Gmail impersonation or email address alone as dashboard authorization. See [Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect).

An application mailbox allowlist is enforced before credential impersonation and each Gmail operation, but **it does not narrow the underlying DWD grant at Google**. A holder of the delegated service-account credential may be able to impersonate other domain mailboxes within the granted scopes. Keep the Google grant, key access, host access, and enrolled list under administrator review. Use dedicated service accounts and never give the response key to the web, beat, or ingestion-only processes. Source: [Workspace DWD setup](https://developers.google.com/workspace/guides/create-credentials).

## Administrator setup

1. Create a dedicated, organization-owned Google Cloud project for this trial. Enable the **Gmail API**. Record its project ID, Workspace customer/domain, data owner, and incident contact outside this repository. Restrict project IAM; review API quotas and audit logs.
2. Create two dedicated service accounts. Enable DWD on each, record their **OAuth client IDs**, and create separate JSON keys only if this key-based deployment is used. Place ingestion JSON in `secrets/google-service-account.json` and response JSON in `response_secrets/google-response-service-account.json`; restrict host file ACLs. Do not commit keys or place them in `.env`, images, backups, or logs. The ingestion key is mounted only in web/worker for enrollment and polling; the response key is mounted only in worker.
3. A Workspace super administrator adds each **client ID**, not its email address, under Security → Access and data control → API controls → Domain-wide delegation. Grant the ingestion client exactly `https://www.googleapis.com/auth/gmail.readonly`; grant the response client exactly `https://www.googleapis.com/auth/gmail.modify.restricted,https://www.googleapis.com/auth/gmail.labels`. Review that the grant contains no extra scopes. Follow [Google's current credential and DWD instructions](https://developers.google.com/workspace/guides/create-credentials).
4. In Yphish, create a dashboard administrator (`python manage.py createsuperuser`) and use Django admin to create the organization, membership, and named mailbox rows. The `bootstrap_dev` command is synthetic-only and must not be used for real enrollment. Configure the organization ingestion/response client IDs in admin. Enroll only named trial mailboxes with the command below; it verifies the exact impersonated mailbox address and Gmail profile. Record each organization, mailbox, owner, start time, and approval in an access register. Never enroll a production-wide catch-all address. Historical synchronization must not trigger retrospective bulk response.

   ```powershell
   docker compose -f compose.yaml -f compose.trial.yaml exec web python manage.py enroll_gmail_mailbox --organization YOUR_ORG_SLUG --mailbox trial-user@your-domain.example
   docker compose -f compose.yaml -f compose.trial.yaml exec web python manage.py sync_gmail_mailbox --help
   ```
5. Run `trial_readiness --require-enrollment`, `gmail_health --json`, a synthetic mailbox test, and the live-verification checklist in `docs/module4-gmail.md` with an administrator. Keep `GMAIL_RESPONSE_ENABLED=0` until the observed labels, message-level behavior, restoration, and circuit breaker have been reviewed.

### OAuth verification and restricted data

`gmail.readonly` and `gmail.modify.restricted` expose restricted Gmail data. The **actual single-organization internal trial** can potentially qualify for Google's internal-use exception when the project is owned by that Workspace organization and its OAuth consent configuration is Internal. DWD and an internal dashboard client are separate authorization mechanisms; the administrator must confirm the project's status and Google's current policy before use. A later **external, public, multi-organization deployment** must be assessed separately for OAuth brand/scope verification, data-use disclosures, privacy policy, and the applicable third-party security assessment for restricted data stored or transmitted on servers. Do not rely on this trial's internal-use rationale for that deployment. Google's guidance distinguishes internal use, domain-wide installation, public apps, restricted-scope verification, and security assessments: [restricted-scope verification](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification), [Gmail scope classification](https://developers.google.com/workspace/gmail/api/auth/scopes). Obtain a written administrator/compliance decision for the actual deployment before enabling real mail; this repository cannot establish the Google review outcome.

## Trial host and HTTPS

Use a dedicated host with DNS `TRIAL_DOMAIN` pointing to it and inbound ports 80/443. Caddy obtains and renews TLS certificates; Django sits behind Caddy. Only trusted operators may run containers on this host/network, because Django trusts `X-Forwarded-Proto` from the proxy in this profile. Block public access to Docker, PostgreSQL, RabbitMQ, and the loopback-only Django port. Never expose `/run/secrets` or `/app/private_artifacts` through the web server. Private artifact files use 0600/0700 permissions and no public URL. Static assets are collected into a separate directory and served by WhiteNoise.

On the **dedicated trial host**, copy `.env.trial.example` to `.env`, set unique strong Django/database/RabbitMQ secrets and the real domain, then verify `.env` is excluded from Git. Keep `DJANGO_DEBUG=0`, `DJANGO_SECURE_SSL_REDIRECT=1`, `DJANGO_TRUST_PROXY_HEADERS=1`, secure cookies, and `DJANGO_HSTS_SECONDS=3600`. Increase HSTS only after TLS and hostname validation. The trial profile uses Gunicorn, Caddy, Django deployment settings, PostgreSQL, Celery worker, and Celery beat:

```powershell
docker compose -f compose.yaml -f compose.trial.yaml config --quiet
docker compose -f compose.yaml -f compose.trial.yaml up --build -d
docker compose -f compose.yaml -f compose.trial.yaml exec web python manage.py check --deploy
docker compose -f compose.yaml -f compose.trial.yaml exec worker python manage.py trial_readiness --json --require-enrollment
docker compose -f compose.yaml -f compose.trial.yaml exec worker python manage.py gmail_health --json
docker compose -f compose.yaml -f compose.trial.yaml ps
```

Check `https://<TRIAL_DOMAIN>/health/` from outside the host, certificate chain, HTTP→HTTPS redirect, HSTS, dashboard login, and that port 8000 is not remotely reachable. The initial readiness command may report `no_enrolled_mailboxes` until enrollment. `check --deploy` is a framework check; it cannot verify external TLS, DWD, backups, broker recovery, or Gmail behavior.

## Secrets, rotation, disconnection, revocation

- Store service-account JSON keys in host-protected secret files and back them up separately only under the organization's secret-management policy. No credentials/tokens/raw MIME belong in logs, Git, or support tickets. Restrict the response key to worker, and rotate one identity at a time by creating a replacement key for the same service account, updating the mounted file atomically, restarting the relevant containers, verifying a synthetic API operation, then disabling/deleting the old key in Google Cloud. Rotate database, RabbitMQ, and Django secrets through an approved maintenance window; changing `DJANGO_SECRET_KEY` invalidates existing sessions and may affect signed artifacts/approvals, so preserve the old value until implications are reviewed.
- To disconnect one mailbox, set its Yphish state to `paused` and disable response for it, then inspect outstanding actions. This stops scheduled polling but **does not revoke** DWD. To revoke provider access, remove that service-account client ID or scope from Workspace DWD and disable/delete its Cloud key. Confirm authorization failure from a safe test; update the enrollment register.
- To suspend all automatic response, set `GMAIL_RESPONSE_ENABLED=0` in `.env` and recreate web/worker/beat. Stop or drain in-flight worker tasks first. To suspend all processing, stop `beat` then `worker` and leave web/db up for review. To stop the trial, stop Caddy/web/beat/worker, preserve DB and encrypted backups, then revoke DWD and keys. Ensure no alternative process retains the credentials.

From the trial repository root, the operational sequence is:

```powershell
# Start in observation mode after the administrator setup; .env has GMAIL_RESPONSE_ENABLED=0.
docker compose -f compose.yaml -f compose.trial.yaml up --build -d
# Begin automatic response only after the live gates and organization/mailbox policy flags are approved.
# Set GMAIL_RESPONSE_ENABLED=1 in .env, then recreate the worker and beat.
docker compose -f compose.yaml -f compose.trial.yaml up -d --force-recreate worker beat
# Suspend automatic response: stop beat and worker, set GMAIL_RESPONSE_ENABLED=0,
# then recreate them for ingestion/analysis without automatic Gmail changes.
docker compose -f compose.yaml -f compose.trial.yaml stop beat worker
docker compose -f compose.yaml -f compose.trial.yaml up -d --force-recreate worker beat
# Stop the whole trial without deleting data volumes; revoke DWD and keys separately.
docker compose -f compose.yaml -f compose.trial.yaml down
```

Confirm the `.env` edit **before** each recreate. Already-running tasks may finish while stopping; inspect the action ledger and current Gmail labels before declaring response suspended. To restore after a harmful action while globally suspended, use authorized manual Gmail correction, or deliberately re-enable the application restoration path after review; the global flag also blocks automated restoration execution.

## Backups and retention

Database backups contain case metadata, evidence text, audit history, and response records. The private artifact archive contains original MIME and attachments. **Both are sensitive restricted data.** Store the pair encrypted in organization-approved off-host storage with access control, versioning, and a documented deletion date. Back up service-account keys only via the separate secret process. Preserve Caddy data if certificate continuity matters; certificates can otherwise be reissued. Back up the active classifier artifacts and indicator snapshots if required to reproduce decisions.

For a consistent pair, schedule a maintenance window; stop `beat`, `worker`, then `web` and wait for them to exit. Keep `db` running. Run `scripts/trial_backup.ps1 -WritersPaused` from the repository root. It refuses to proceed while writers run, produces a PostgreSQL custom-format dump, private artifact archive, and SHA-256 manifest in ignored `trial_backups/`. Encrypt/copy the set off host immediately; remove the unencrypted host copy under the approved process. Restart web/worker/beat after the copy. Run a **restore drill in a separate test environment**: verify manifest hashes, restore the dump with `pg_restore --exit-on-error` to an empty PostgreSQL database, extract the artifact archive into a private 0700 directory, run `manage.py migrate --check`, compare artifact counts and selected SHA-256 hashes, and run smoke tests with Gmail credentials absent and response disabled. Never restore a trial dump into production or connect a restore drill to live Gmail.

`Organization.retention_days` controls daily pruning of **private artifact files** via the resumable `core.tasks.prune_private_artifacts` beat task. `python manage.py prune_private_artifacts` previews; `--execute` requires `ARTIFACT_RETENTION_ENABLED=1`. The task first marks old artifact rows deleted and creates an audit event, then deletes their files; the next run resumes interrupted file removals. **Case, evidence, feedback, and audit metadata remain in PostgreSQL**; this is not a full personal-data erasure policy. Set and approve separate retention/deletion obligations for that metadata and backups before trial, and do not claim complete erasure from this command.

## Monitoring and automatic limits

Run `gmail_health --json` every few minutes via the organization's monitoring system. Alert on broker unavailable, zero responding workers, `scheduler_health=degraded` (the 60-second beat heartbeat has not been executed by a worker in 180 seconds), stale analysis leases, pending age above policy, sync lag above twice polling interval plus retry allowance, any `authorization_failed`/`coverage_gap`, or no successful sync. The heartbeat establishes that beat scheduled and a worker completed the heartbeat task; it does not distinguish which component failed. Watch `docker compose ps`, container restarts, database disk, backup success, TLS expiry, response circuit status in dashboard, and rate-limit counters. Do not log message content or credential-bearing exception strings. A healthy queue does not prove Gmail is authorized. The trial defaults to 60-second polling, **response disabled**, 10 actions per organization/hour, 2 per mailbox/hour, failure threshold 3, 1-hour circuit pause, and maximum case age 24 hours. Reduce enrolled mailboxes and limits before broadening the trial. The application does not currently enforce a global administrator-approved mailbox count; the operator must maintain the explicit register.

## Incident runbooks

| Signal | Immediate action | Recovery and evidence |
| --- | --- | --- |
| Expired/invalid authorization or disabled DWD | Suspend response and affected mailbox; keep unrelated mailboxes scoped. | Check Cloud key status, DWD client IDs and exact scopes, Gmail API enablement, administrator policy; reverify profile and resume only after a safe test. No automatic scope broadening. |
| Gmail outage or network disconnection | Leave durable work queued; monitor lag; suspend response if labels cannot be verified. | Check provider status and network/DNS/TLS, then resume polling; review coverage and backlog before response. |
| Quota exhaustion / 429 | Keep throttled state and provider retry delay; reduce polling/enrollment if needed. | Inspect quota in Cloud Console, wait for retry window, confirm cursor advancement only after durable processing. Do not spin immediate retries. |
| Expired history cursor / 404 | Record the coverage gap and suspend response for affected mailbox pending review. | Controlled resynchronization preserves enrollment boundary and deduplicates; document the interval that history cannot prove, compare mailbox manually, then close incident. |
| Incorrect labeling / inbox removal | Set `GMAIL_RESPONSE_ENABLED=0`, drain/stop worker; disable org/mailbox response. | Inspect action/evidence/policy version and current labels; perform an authorized manual Gmail correction, or deliberately re-enable application restoration after review. Verify unrelated labels/read state; document affected IDs without raw MIME. |
| Restoration conflict, missing message, TRASH/SPAM | Keep failed/conflict state; do not force label changes or resurrect message. | Have an authorized operator inspect current Gmail state, resolve manually if appropriate, record feedback and audit reason. |
| Circuit open or response suspension | Keep polling/analysis running if safe; automatic response stays off. | Identify failure cause, reconcile ambiguous actions, review rate and scope, reset only under administrator change control. |
| Worker/beat crash or broker failure | Keep response suspended if action state is uncertain. | Restore broker/worker, run `gmail_health`, allow pending-work reconciliation, review duplicate/ambiguous actions and lag. |

## Future Pub/Sub (not deployed)

Polling plus `users.history.list` is the deployed synchronization mechanism. A later Cloud Pub/Sub optimization would need `users.watch`, a per-mailbox watch renewal (Google requires at least every seven days and recommends daily), authenticated push delivery with signed JWT audience/identity validation, duplicate/out-of-order notification handling, and periodic history reconciliation even when push is enabled. Pub/Sub notifications are hints to fetch history, not a replacement for cursor durability. Source: [Gmail push notifications](https://developers.google.com/workspace/gmail/api/guides/push), [authenticated Pub/Sub push](https://cloud.google.com/pubsub/docs/authenticate-push-subscriptions).

## Trial gates and live verification

Before enabling automatic response, record: exact Cloud project and DWD client IDs/scopes; the Google verification/compliance determination; named enrolled mailboxes and owner approval; HTTPS and access tests; successful test restore; backup retention; successful initial and incremental Gmail sync; message-level mixed-thread labeling; duplicate notification handling; restoration under concurrent label changes; worker crash/broker outage recovery; 404 coverage-gap procedure; and a successful suspension drill. Tests in this repository are synthetic/mocked and PostgreSQL-backed; they do **not** verify a live Workspace grant, Gmail API behavior, actual delivery, quotas, certificate issuance, or provider revocation. Keep `GMAIL_RESPONSE_ENABLED=0` until the administrator signs off these live gates.
