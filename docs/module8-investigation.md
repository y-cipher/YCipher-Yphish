# Module 8 — bounded adaptive investigation

After a successful nonhistorical Gmail MIME analysis, Yphish commits one `InvestigationRun` for that case. The Celery sweep dispatches queued runs through RabbitMQ; a worker claims each run with a lease and records each selected tool call as an `InvestigationStep` and `Evidence.Source.TOOL`. Broker failures leave queued work for the next sweep, and expired leases are reconciled. The run records its rounds, calls, summary, and stopping reason. The workflow is read-only and never changes the message verdict or creates an action.

The default `ExplicitPolicy` chooses from a typed catalogue: exact matches in locally cached, timestamped indicators; an optional bounded DNS A-record query; approved earlier sender counts from the same mailbox; and optional earlier conversation MIME from the same enrolled mailbox and Gmail thread. The DNS lookup disables search suffixes, uses a per-tool lifetime, returns at most eight addresses, and never fetches a URL or connects to an answer. It is disabled by default. The sender and conversation tools are separately disabled by default for each mailbox; an owner or admin can enable them in Django admin after approval. There is no arbitrary mailbox search, shell command, URL fetch, attachment execution, Gmail modification, or response credential in the catalogue.

The case, mailbox, analysis run, and organization must match. PostgreSQL also rejects mismatched investigation relationships. A dashboard caller must be authenticated and have an active owner, admin, or analyst membership in the active organization; `authorized_case` checks this separately from Gmail enrollment. The internal Celery worker accepts only a persisted investigation run and rechecks enrollment and tenant scope before each tool. An unapproved mailbox, cross-mailbox case, or changed enrollment stops the run.

`Selector` is the narrow integration point for a future approved LLM adapter. It receives `SelectionView`: validated tool candidates, previous tool statuses and limited factual summaries, and remaining budgets. It receives no MIME text, service-account object, token, Gmail client, or response method. Any returned tool and typed arguments must equal a candidate derived from the current case and its rule evidence. Invalid selections are recorded as rejected and stop before tool execution. For an external LLM, keep its process and credentials separate and send only this serialized view; prompts and message text are untrusted data. The deterministic policy is the only configured selector in this module.

## Limits and interpretation

| Setting | Default | Purpose |
| --- | ---: | --- |
| `INVESTIGATION_ENABLED` | `1` | Queue investigations after new-message analysis. |
| `INVESTIGATION_MAX_ROUNDS` | `4` | Hard limit on selection rounds (maximum 10). |
| `INVESTIGATION_MAX_CALLS` | `4` | Hard limit on tool attempts (maximum 10). |
| `INVESTIGATION_TIMEOUT_SECONDS` | `20` | Overall wall-clock budget (maximum 120). |
| `INVESTIGATION_TOOL_TIMEOUT_SECONDS` | `3` | DNS lifetime and per-tool budget (maximum 10). |
| `INVESTIGATION_DNS_ENABLED` | `0` | Permit controlled DNS A-record lookups. |
| `INVESTIGATION_THREAD_MAX_MESSAGES` | `5` | Maximum earlier messages before opening MIME (maximum 20). |
| `INVESTIGATION_THREAD_MAX_BYTES` | `262144` | Maximum total original MIME bytes before opening files (maximum 5 MB). |
| `INVESTIGATION_THREAD_MAX_AGE_DAYS` | `30` | Maximum earlier conversation age (maximum 365 days). |
| `INVESTIGATION_SENDER_MAX_CASES` | `100` | Maximum earlier sender records examined (maximum 1000); a truncated count is marked as a lower bound. |
| `INVESTIGATION_SWEEP_INTERVAL_SECONDS` | `30` | Celery reconciliation interval. |

The runner checks round, call, elapsed-time, enrollment, and repeated-request state before each tool. A repeated tool+argument request stops without executing it twice. DNS has an explicit resolver lifetime; local tools have pre-execution budget checks and discard results that exceed their elapsed-time budget. Local file-system reads cannot be forcibly interrupted, so the conversation tool also enforces byte and message limits before opening any MIME. It checks access, same-mailbox/thread identity, message count, age, and total stored artifact bytes **before opening any MIME**. It returns only bounded excerpts; these are stored as untrusted tool results and are not passed to the selector. The stored MIME remains private and unchanged. A time or size limit yields an unavailable observation with a reason. Tool failures are recorded without exception text, credentials, or raw MIME in logs.

Historical sender and conversation queries use only records with a message time before the target and a Yphish creation time no later than the target decision time. Gmail `internalDate` is preferred for that time and capped by case creation time; MIME `Date` is only a fallback. Post-decision analyst feedback, dispositions, and future indicator snapshots are excluded. The local indicator tool uses only snapshots valid at the target time. Prior contact, a shared Gmail thread, DNS resolution, and an absent indicator match never establish legitimacy. Each message keeps its own verdict and evidence.

## Run and test

Set the variables above in the private `.env`; leave DNS and mailbox context disabled until approved. Apply migrations and run the worker and scheduler with the existing Compose setup:

```powershell
docker compose up --build -d
docker compose exec web python manage.py migrate --noinput
docker compose exec web python manage.py test core.test_investigation --noinput
docker compose exec web python manage.py test core --noinput
```

For host execution, use the README's `.env` export step, then `python manage.py migrate` and `python manage.py test core.test_investigation`. Inspect the read-only `InvestigationRun`, `InvestigationStep`, and tool evidence views in Django admin. Tests use synthetic cases, private local MIME artifacts, mocked DNS responses, and PostgreSQL. They do not verify a live Gmail mailbox, a real DNS resolver, or detection performance.
