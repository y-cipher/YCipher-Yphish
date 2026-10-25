# Google Workspace Gmail setup and runtime

Yphish uses Django 5.2 LTS, PostgreSQL, private artifacts, Celery, and RabbitMQ. Django admin login and membership roles are independent from Gmail access. No Microsoft dashboard SSO, Bootstrap interface, or existing Graph client was present in this checkout, so there is no login flow to convert to Google OIDC.

## Run and test

```powershell
Copy-Item .env.example .env
# Set DJANGO_SECRET_KEY, DATABASE_PASSWORD, RABBITMQ_PASSWORD in .env.
docker compose up --build -d
docker compose exec web python manage.py check
docker compose exec web python manage.py test core --noinput
Invoke-RestMethod http://localhost:8000/health/
```

The test command uses a fresh PostgreSQL test database. `docker compose down` retains the database and private artifact volumes. For host execution, install `requirements.txt`, export `.env`, run `python manage.py migrate`, then start `celery -A config worker -l WARNING`, `celery -A config beat -l WARNING`, and `python manage.py runserver` separately. The host needs Python 3.12+, PostgreSQL 16+, and RabbitMQ. The host test command is `python manage.py test core --noinput` with a PostgreSQL role that can create test databases.

## Administrator authorization

1. Create a Google Cloud service account with domain-wide delegation and enable the Gmail API. In Workspace Admin, authorize its **numeric client ID** for the `https://www.googleapis.com/auth/gmail.modify` scope. Domain-wide delegation grants impersonation capability across the Workspace domain for that scope; Yphish only polls enrolled mailboxes, but enrollment is an application restriction. Limit key access accordingly. Google documents [credentials](https://developers.google.com/workspace/guides/create-credentials) and [delegation](https://developers.google.com/workspace/cloud-search/docs/guides/delegation).
2. Put its JSON key in `secrets/google-service-account.json` for Compose. Git ignores this file; Compose mounts the directory read-only. Restrict host file permissions. For host execution, set `GOOGLE_SERVICE_ACCOUNT_FILE` to its absolute path. Never put the key, tokens, or mailbox passwords in `.env`, fixtures, the database, or Git.
3. Create an organization and pending mailbox through Django admin or a trusted management workflow. Synthetic `bootstrap_dev` addresses under `example.test` cannot be used for live enrollment.
4. Verify and enroll the real mailbox:

   ```powershell
   docker compose exec web python manage.py enroll_gmail_mailbox --organization YOUR_SLUG --mailbox security@YOUR_DOMAIN
   ```

   The command checks delegated `users.getProfile` access to that exact address, creates or finds the `Yphish/Investigate` user label, and saves the client ID, history cursor, label ID, and verification time. It stores no credential or token. By default only changes after enrollment are ingested. `--backfill` scans existing messages first and stores their original MIME privately. Repeating enrollment preserves an existing cursor.

The Celery scheduler polls every 60 seconds. It follows all `history.list` pages, fetches each added Gmail message by its immutable **message ID**, parses headers, saves MIME as a private artifact, records ingestion and parser evidence, and advances the cursor only after processing succeeds. A stale cursor triggers a full mailbox reconciliation. See Google's [message resource](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages) and [sync guide](https://developers.google.com/workspace/gmail/api/guides/sync).

Case identity is `(organization, mailbox, gmail_message_id)`. `gmail_thread_id` is conversation context. Neither thread ID, MIME digest, nor the `Message-ID` header is used for case deduplication. Migration `0004` leaves existing case IDs untouched, marks existing mailboxes `legacy`, and adds Gmail IDs/cursors/label/configuration fields. The old `provider_immutable_id` field remains for prior records and integrity guards; new Gmail rows set it equal to the Gmail message ID.

## Automated response

`gmail_response_enabled` defaults to false. After authorization, an organization owner may enable it in Django admin. For an `analyzed` Gmail case with a `malicious` verdict, the scheduler creates one idempotent `move` action and authorizes it by policy. The worker automatically adds the configured label to the individual message and removes `INBOX`. `categorize` only adds the label; `restore` removes it and adds `INBOX`. A worker reads and verifies labels around a write. An uncertain result enters `reconciling` and is checked before any further mutation. See [Gmail message modify](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/modify).

This repository captures headers and evidence but has no phishing classifier or rule engine that decides a message is malicious. It does not autonomously assign malicious verdicts. The response policy becomes effective only when a trusted analysis component or operator sets a verdict. No per-message Gmail authorization or manual approval is required after the separate administrator setup and policy opt-in.

## Configuration and security

| Variable | Meaning |
| --- | --- |
| `DJANGO_SECRET_KEY`, `DJANGO_DEBUG`, `DJANGO_ALLOWED_HOSTS`, `DJANGO_CSRF_TRUSTED_ORIGINS` | Django signing, development mode, hosts, CSRF origins. |
| `DATABASE_NAME`, `DATABASE_USER`, `DATABASE_PASSWORD`, `DATABASE_HOST`, `DATABASE_PORT` | PostgreSQL connection; Compose sets host to `db`. |
| `POSTGRES_HOST_PORT` | Host PostgreSQL port, default `5433`. |
| `RABBITMQ_PASSWORD` | Compose broker password; choose a distinct random value. |
| `CELERY_BROKER_URL` | Broker URL for host deployment; Compose supplies this to worker and beat. |
| `GOOGLE_SERVICE_ACCOUNT_FILE` | Read-only service-account file path; Compose uses `/run/secrets/google-service-account.json`. |
| `PRIVATE_ARTIFACT_ROOT` | Private storage path; Compose uses a named volume. |

The Gmail client does not log credentials, tokens, provider response bodies, or MIME. The private artifact storage uses random paths and exposes no URL. Back up both the database and artifact volume; do not serve the private directory. Compose uses Django's development server; use a production server and HTTPS for deployment. The tests mock Gmail and verify PostgreSQL behavior. Live Gmail behavior has not been verified here.
