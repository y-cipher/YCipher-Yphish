# Module 5 — background Gmail synchronization and analysis

Module 5 runs two independent Celery Beat schedules. `poll_gmail` publishes a synchronization task for each active, enrolled mailbox; `dispatch_pending_analysis` reconciles and publishes committed MIME analysis runs. RabbitMQ carries task notifications. PostgreSQL stores the cursor, cases, artifacts, analysis work, retry state, and failure status. No response action or Cloud Pub/Sub subscription is implemented.

## Start and test

Copy `.env.example` to `.env`, set distinct Django, PostgreSQL, and RabbitMQ secrets, and complete the [Google Workspace setup](gmail.md) before enrolling a real mailbox. A local Compose run uses:

```powershell
docker compose up --build -d
docker compose exec web python manage.py migrate --noinput
docker compose exec web python manage.py gmail_health
docker compose exec web python manage.py test core.test_module5 core.test_gmail --noinput
docker compose logs --tail=100 worker beat rabbitmq
```

For a host run with PostgreSQL and RabbitMQ already available, set the variables in `.env`, then run these in separate PowerShell terminals:

```powershell
.\.venv\Scripts\python.exe manage.py migrate --noinput
.\.venv\Scripts\python.exe manage.py runserver
.\.venv\Scripts\celery.exe -A config worker -l WARNING --concurrency=2
.\.venv\Scripts\celery.exe -A config beat -l WARNING
.\.venv\Scripts\python.exe manage.py gmail_health --json
```

Only one Beat instance should use a given schedule. Multiple workers are safe; the PostgreSQL advisory lock allows one synchronization per mailbox at a time. The `gmail_health` command reports broker connection, responding worker count, committed analysis states, mailbox status, last successful sync, lag in seconds, next eligible retry, and any recorded coverage gap. A connected broker alone does not mean a worker is running. Run this command from a trusted operator shell; it includes enrolled mailbox addresses but no credentials or message content.

## Configuration

| Variable | Default | Purpose |
| --- | ---: | --- |
| `GMAIL_POLL_INTERVAL_SECONDS` | `60` | Beat interval for eligible enrolled mailboxes. |
| `GMAIL_ANALYSIS_SWEEP_INTERVAL_SECONDS` | `30` | Beat interval for pending work and expired leases. |
| `GMAIL_ANALYSIS_DISPATCH_BATCH_SIZE` | `100` | Maximum analysis runs published per sweep. |
| `GMAIL_ANALYSIS_REDISPATCH_SECONDS` | `120` | Minimum time before republishing an unclaimed queued run. |
| `GMAIL_ANALYSIS_LEASE_SECONDS` | `300` | Worker lease; expired work is requeued after a crash. |
| `GMAIL_RETRY_BASE_SECONDS` | `5` | Initial Gmail retry delay; jitter is added. |
| `GMAIL_RETRY_MAX_SECONDS` | `3600` | Cap on exponential component; provider `Retry-After` may be longer. |

Intervals are read at process startup. Restart Beat after changing its intervals; restart workers after changing lease or retry values. Celery acknowledges tasks late and prefetches one task per worker slot. Database state and idempotency make redelivery safe.

## Durability and state transitions

Each Gmail message is identified by `(organization, mailbox, gmail_message_id)`; thread ID is context only. Ingestion commits a case, private original MIME artifact, ingestion evidence, and one queued `AnalysisRun` (`gmail:parse:v1`) before it returns. Baseline messages from the initial scan are historical and do not queue automatic analysis. Messages added after enrollment, including arrivals during initialization, do queue analysis. The dispatcher sends only committed queued run IDs. If RabbitMQ publish fails, the run remains queued and the next sweep retries it. A run published but never claimed is republished after the configured interval. A worker claims it with a database lock and fenced lease, parses the private MIME, writes parser evidence, and marks the run/case successful atomically. Duplicate deliveries cannot create another run or parser evidence. An expired lease is requeued; late workers cannot finalize work after their lease token is replaced.

Parser failure makes the run and case `failed`. A temporarily unavailable private artifact retries up to five claims and then fails. Analysis does not classify the message or create response actions. Operators can inspect safe error codes and counts in admin; message bytes, token material, and provider response bodies are not logged.

Mailbox synchronization uses a per-mailbox PostgreSQL advisory lock. History pages are processed in order; all case, label, deletion, artifact, and analysis-run records are committed before the completed string cursor advances. If a page fails or a worker dies, the old cursor is replayed and duplicate message IDs resolve to the existing case. Label events fetch `format=minimal` for an existing case and update label IDs; repeated events and Yphish's eventual own label changes create no new analysis. Deletion events set a tombstone timestamp on an existing case and do not create a case without MIME. A message disappearing before retrieval is audited and marked deleted if previously known.

`gmail_last_synced_at` is the last **successful** sync; `gmail_last_attempt_at` records attempts. `gmail_next_sync_at` gates retries. Network failures set `disconnected`; 401, non-quota 403, and invalid delegated authorization set `authorization_failed`; 429 and Gmail rate-limit reasons set `throttled`; retryable 5xx/API failures set `unavailable`. Other permanent errors set `error`. Retriable failures use truncated exponential delay with jitter and honor a longer provider `Retry-After` value. `authorization_failed` is excluded from polling until an administrator corrects authorization and reruns `enroll_gmail_mailbox`; re-verification preserves the enrollment boundary and completed cursor. A coverage gap remains recorded separately even if a later transient failure changes the current status.

Expired Gmail history cursors (HTTP 404) retain the enrollment boundary, record `coverage_gap`, capture a new anchor, scan current messages, replay changes arriving during the scan, and advance only after committed work. Messages present only in the inaccessible interval cannot be recovered; inspect the gap before relying on complete coverage.

Google recommends [exponential backoff for Gmail API errors](https://developers.google.com/workspace/gmail/api/guides/handle-errors) and documents [history event types](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.history/list) and [expired history cursor recovery](https://developers.google.com/workspace/gmail/api/guides/sync). Cloud Pub/Sub may later reduce notification latency, but periodic history reconciliation remains necessary to recover missed notifications and cursor gaps.

## Verification boundary

The PostgreSQL-backed tests use synthetic MIME and mocked Gmail/AMQP calls. They cover duplicate and overlapping synchronization, history pagination/interruption, durable cursor behavior, broker publish failure, worker lease recovery, quota and authorization states, expired history cursors, deletions, and repeated label events. They do **not** verify live Google Workspace delegation, real Gmail quota headers, or a running RabbitMQ worker. For live verification, enroll a dedicated Workspace mailbox and follow the [Gmail checklist](gmail.md), then inspect `gmail_health` while sending, labeling, and deleting synthetic test messages.
