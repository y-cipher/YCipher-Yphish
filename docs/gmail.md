# Module 4 — Google Workspace Gmail ingestion

Module 4 uses Gmail polling, Django/PostgreSQL case identity, private MIME artifacts, the existing header parser and evidence service, Celery, and RabbitMQ. It performs **no mailbox response action**. The `ActionExecution` table remains for other modules, but the Module 4 worker does not create or execute Gmail actions. Django admin sign-in and organization membership are separate from Gmail authorization.

## Scopes and identities

Google's [Gmail scope reference](https://developers.google.com/workspace/gmail/api/auth/scopes) classifies `https://www.googleapis.com/auth/gmail.readonly` as a **restricted** scope. It permits the `messages.list`, `messages.get(format="raw")`, `history.list`, and `users.getProfile` calls used here. Ingestion requests only this scope. The service-account JSON is read from `GOOGLE_INGESTION_SERVICE_ACCOUNT_FILE`; no key or token is stored in PostgreSQL.

Google's [`users.messages.modify` reference](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/modify) states that administrator-delegated modification for users in an organization requires a domain-wide delegated service account impersonating users with `https://www.googleapis.com/auth/gmail.modify.restricted`. Module 4 reserves a **different** response client ID, key path, and exact scope for future response code. The credential provider rejects missing or broader/incorrect response scope configuration and never falls back to `gmail.modify` or `https://mail.google.com/`. No response API method is called in this module.

A Yphish mailbox allowlist controls which stored mailbox IDs this application will impersonate. It **does not narrow the underlying Workspace domain-wide delegation grant**. Protect the key and limit Workspace authorization to the required scope. Google documents [domain-wide delegation setup](https://developers.google.com/workspace/guides/create-credentials). Consult your Workspace administrator about organizational policy and restricted-scope verification requirements.

## Google Cloud and Workspace setup

1. Enable Gmail API in a Google Cloud project. Create a service account with Workspace domain-wide delegation. Download its JSON key into `secrets/google-service-account.json` outside Git, with restricted host file permissions. Compose mounts `secrets/` read-only and excludes it from Docker build context.
2. In Workspace Admin, add the service account's **numeric client ID** to domain-wide delegation for exactly `https://www.googleapis.com/auth/gmail.readonly`. Do not grant a broader scope for ingestion.
3. Set the usual Django/PostgreSQL/RabbitMQ values in `.env`. Compose sets `GOOGLE_INGESTION_SERVICE_ACCOUNT_FILE=/run/secrets/google-service-account.json`. For a host process, set it to the absolute JSON path. `GOOGLE_SERVICE_ACCOUNT_FILE` remains a compatibility fallback but should be replaced in new deployments.
4. Add the organization and **specific mailbox address** in Django admin using an owner/admin membership. The mailbox begins pending. Enrollment uses the stored address as the impersonation subject and verifies that `users.getProfile` reports the same address; aliases or another user's profile are rejected.
5. Run:

   ```powershell
   docker compose exec web python manage.py enroll_gmail_mailbox --organization YOUR_SLUG --mailbox security@YOUR_DOMAIN
   docker compose exec web python manage.py sync_gmail_mailbox --organization YOUR_SLUG --mailbox security@YOUR_DOMAIN
   ```

   Enrollment records a history boundary **before** initial synchronization. The sync command runs the initial scan immediately; Celery beat also dispatches eligible mailboxes every 60 seconds. Repeating enrollment preserves the boundary and completed cursor. Synthetic `example.test` fixtures cannot be enrolled.

## Synchronization behavior

Initial synchronization pages through `users.messages.list` (including Spam and Trash), fetches each message with `users.messages.get(format="raw")`, decodes Gmail's base64url MIME, and records case, artifact, and ingestion evidence. Module 5 parses new messages in a separate task and records parser evidence. Baseline messages are marked `gmail_is_historical=True`; they cannot become retrospective response candidates. The service then replays `users.history.list` from the enrollment boundary. Messages added during initialization are deduplicated by `(organization, mailbox, gmail_message_id)` and marked nonhistorical. `gmail_thread_id` is conversation context only. Label changes refresh stored label IDs. See Google's [message resource](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages) and [synchronization guide](https://developers.google.com/workspace/gmail/api/guides/sync).

The mailbox stores `gmail_enrollment_history_id`, `gmail_history_id` (the **completed** cursor), enrollment and initial completion times, sync status, and any coverage-gap details. Both history IDs remain strings; no contiguous-ID arithmetic is used. Each message and its evidence commit before the cursor advances. If a later page fails, the cursor stays put and retries deduplicate already recorded messages. A message that disappears between listing and retrieval is recorded as an audit event before the cursor can advance.

An expired history cursor produces HTTP 404 per Google's [sync guide](https://developers.google.com/workspace/gmail/api/guides/sync). Yphish records a persistent `coverage_gap` status and audit event with the old cursor, captures a fresh history anchor, scans current messages, then replays changes from that anchor. The enrollment boundary is preserved. The current mailbox can be reconciled, but messages that appeared and disappeared solely in the unavailable interval cannot be reconstructed; the gap remains visible in admin and the sync command output. No response action is triggered by either full scan or recovery.

`gmail_label_ids` and `gmail_internal_date_ms` are stored on each case. The latter preserves Google's exact string-valued epoch milliseconds; `received_at` still reflects the MIME `Date` header. Original MIME is stored only through private artifact storage and is never logged. `gmail_message_id` is the case key. Migration `0005` retains legacy rows and marks Gmail rows created before this explicit boundary model as historical with a coverage gap.

## Commands and tests

```powershell
docker compose up --build -d
docker compose exec web python manage.py check
docker compose exec web python manage.py makemigrations --check --dry-run
docker compose exec web python manage.py test core --noinput
docker compose exec web python manage.py sync_gmail_mailbox --organization YOUR_SLUG --mailbox security@YOUR_DOMAIN
```

The test suite uses PostgreSQL and mocks Gmail. It checks scope separation, enrollment enforcement, pagination, base64url decoding, initial replay, cursor durability, 404 recovery, tenant identity, and migration preservation. It does **not** prove live Workspace access.

## Live-verification checklist

Use a dedicated test Workspace mailbox and administrator-approved service-account grant:

- Confirm only `gmail.readonly` is granted to the ingestion client ID, and enrollment rejects a mismatched Gmail profile.
- Enroll one exact mailbox, then inspect its enrollment history ID and `initializing` status.
- Run the sync command; check that the baseline cases are historical, each Gmail message ID is unique per mailbox, MIME artifacts are private, and the completed cursor is populated.
- Deliver two separate messages in one thread. Poll again and confirm two cases with one shared thread ID.
- Add a label to a test message and poll; confirm stored label IDs refresh.
- Interrupt a paged sync in a test environment, retry, and confirm one case per message and no cursor advance before completion.
- In a controlled test, force an expired cursor; verify `coverage_gap`, the retained enrollment boundary, an audit event, and current-mail reconciliation.
- Confirm no Gmail label modification, move, delete, or send call appears in logs or API audit events.

Do not mark live Gmail behavior verified until these checks have actually been performed with real Workspace authorization.