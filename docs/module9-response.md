# Module 9: automatic Gmail message response

This feature labels an individual Gmail message `Yphish/Suspicious` and, when an enrolled mailbox has `gmail_response_remove_inbox` enabled, removes `INBOX` from that message. It is **not** secure quarantine, pre-delivery protection, or a guarantee that a recipient did not see the message. It never calls Gmail thread modification, SPAM, TRASH, deletion, filters, or account settings. Gmail `UNREAD` and unrelated labels are not included in the requested changes.

## Authorization and enrollment

The worker uses a **separate** response service account and key from read-only ingestion. For Workspace domain-wide delegation, Google's current [`users.messages.modify` reference](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/modify) requires `https://www.googleapis.com/auth/gmail.modify.restricted` for administrator-delegated modification. Creating and listing the custom label require `https://www.googleapis.com/auth/gmail.labels` under [`users.labels.create`](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.labels/create) and [`users.labels.list`](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.labels/list). The response identity is configured with exactly these two scopes; the application rejects incorrect scope strings and never silently substitutes `gmail.modify` or `https://mail.google.com/`. Read-only ingestion credentials supply [`users.messages.get`](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/get) to inspect and verify labels. Keep the ingestion key and response key separate.

1. In Google Cloud, create a distinct service account for response, enable Gmail API, enable domain-wide delegation, and record its OAuth client ID. In Workspace Admin Console, authorize that **response client ID** for the exact two scopes above. Follow your organization's approval and key-handling process.
2. Put the response JSON key at `response_secrets/google-response-service-account.json` for Compose. Only the worker mounts this directory at `/run/response-secrets`; the web service does not mount it. The existing read-only ingestion key remains in `secrets/google-service-account.json`. For host execution, set `GOOGLE_RESPONSE_SERVICE_ACCOUNT_FILE` to the response key's private absolute path and `GOOGLE_INGESTION_SERVICE_ACCOUNT_FILE` to the ingestion key's path.
3. In Django admin, set the organization's **response** client ID, `gmail_response_scope` to `https://www.googleapis.com/auth/gmail.modify.restricted`, `gmail_response_labels_scope` to `https://www.googleapis.com/auth/gmail.labels`, and enable `gmail_response_enabled`. The client ID must differ from ingestion's. For each intended, already enrolled and active Gmail mailbox, enable its `gmail_response_enabled`. Enable `gmail_response_remove_inbox` only if inbox removal is desired. The global `GMAIL_RESPONSE_ENABLED=0` switch pauses all execution and preparation.
4. Start/restart the worker and Beat. Beat scans every `GMAIL_RESPONSE_SWEEP_INTERVAL_SECONDS` for eligible cases, reviewed legitimate corrections, and durable pending actions. No per-message human approval is needed for qualifying operations.

An application mailbox allowlist does **not** narrow Workspace's underlying domain-wide delegation grant. Keep the grant and keys protected. Yphish checks active organization, explicit mailbox enrollment, response enablement, case/mailbox/organization identity, and the permitted operation set before impersonation and before each API operation. Django dashboard login and organization roles do not grant Gmail access.

## Versioned policy

`gmail-response-v1` acts only on a newly ingested, nonhistorical message in a ready mailbox, within `GMAIL_RESPONSE_MAX_CASE_AGE_HOURS` (default 24), with successful `rules-v1` analysis and completed `explicit-v1` investigation. It requires an **operational**, timestamp-valid exact indicator observation plus a separate visible-link mismatch or link-free payment-redirection observation from the same analysis. Synthetic indicators, Gmail placement and labels, thread membership, classifier output alone, and authentication results do not authorize response. A reviewed legitimate correction suppresses application and can initiate restoration. Older baseline and recovery-scan messages cannot trigger retrospective bulk action.

The scheduled sweep supplies automatic execution; `ActionExecution` stores the idempotency key, policy version, analysis run, evidence IDs and versions, message ID, before labels and history ID, exact label additions/removals, and which changes Yphish owns. This is committed **before** `users.messages.modify`. The worker reads the individual message state first, performs only the recorded delta, then reads it again and records verification. An ambiguous timeout enters `reconciling`: the worker reads current state before any retry, marks already-applied deltas successful, and retries only if the original history ID and tracked labels still match. A changed state fails conservatively. Expired worker leases return to reconciliation; repeated task delivery is idempotent. A Gmail 404 records a missing-message failure and case tombstone.

Gmail does not offer a compare-and-swap label modification for this flow. A user or other client can change labels between Yphish's final read and modification. Yphish detects known tracked-label conflicts before writing and verifies afterward; operators should inspect failed or ambiguous actions in admin. It does not overwrite unrelated labels or `UNREAD`.

## Label lifecycle and restoration

The worker finds or creates the exact USER label `Yphish/Suspicious`; its current Gmail label ID is stored on the mailbox and each action. A renamed/deleted old label ID is never silently reused. New cases may create/find a new canonical label. Pending actions involving a changed label fail safely.

A reviewed legitimate correction can create one idempotent restoration action per successful application. Restoration removes the **recorded label ID** only if the application added it and it is still the canonical label. It re-adds `INBOX` only if the application removed it, `INBOX` remains absent, and the message is in neither SPAM nor TRASH. Preexisting Yphish labels remain untouched. User-added labels, read state, and changed unrelated labels remain untouched. If no owned change remains, the action is skipped. Successful restoration prevents automatic reapplication of the same policy version, avoiding move/restore loops. Missing messages and SPAM/TRASH messages are never automatically resurrected.

## Rate limits, circuit breaker, and operation

`ResponseControl` stores per-organization and per-mailbox rolling one-hour reservations. Defaults are 100 organization operations/hour and 20 mailbox operations/hour. Attempts above either limit wait until the window resets. `GMAIL_RESPONSE_FAILURE_THRESHOLD` consecutive failed/uncertain operations (default 5) open both circuits for `GMAIL_RESPONSE_CIRCUIT_SECONDS` (default 1800); authorization failures open immediately. Disable the organization or mailbox response flag, or set `GMAIL_RESPONSE_ENABLED=0`, for an immediate pause. Inspect `ActionExecution`, `ResponseControl`, and append-only `AuditEvent` in admin. A broker outage leaves authorized actions in the database for Beat reconciliation after recovery. `GMAIL_RESPONSE_LEASE_SECONDS` controls crash recovery.

```powershell
docker compose up --build -d
docker compose exec web python manage.py migrate
docker compose exec web python manage.py check
docker compose exec web python manage.py test core.test_response
docker compose exec web python manage.py test core
docker compose logs -f worker beat
```

For host execution with exported `.env` values and PostgreSQL, use `python manage.py test core.test_response`. The tests use synthetic cases and mocked Gmail clients with a real PostgreSQL test database. They cover mixed legitimate/malicious messages in one thread, exact `messages.modify` arguments, restoration ownership, renamed labels, SPAM/TRASH, duplicate delivery, ambiguous timeouts, concurrent label changes, missing messages, rate limits, the circuit breaker, and scope/tenant guards. These tests do **not** verify live Gmail behavior.

## Live verification checklist

In a disposable Workspace tenant and explicitly enrolled test mailbox: verify the two separate DWD client IDs and exact scopes; send a known test message and a benign message in the same thread; confirm only the qualifying message receives `Yphish/Suspicious` and optional `INBOX` removal while `UNREAD` and other labels persist; verify the action's prestate, delta, and poststate; induce a provider timeout and confirm reconciliation; rename/delete the custom label and confirm safe failure/new-label creation; review a legitimate correction and verify only Yphish-owned changes are restored; place a test message in SPAM/TRASH and confirm no resurrection; check the rate/circuit controls. This checklist requires real Workspace access and has not been performed by the automated tests.

Periodic Gmail history polling remains necessary. Cloud Pub/Sub can later reduce notification latency but does not replace reconciliation.
