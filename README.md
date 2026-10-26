# Yphish — Django foundation and Gmail integration

This repository contains the Django/PostgreSQL foundation, direct Google Workspace Gmail ingestion, Module 5 Celery/RabbitMQ synchronization, Module 6 deterministic detection evidence, and the Module 7 TF-IDF classifier. See [Gmail setup](docs/gmail.md), [Module 5 operations](docs/module5-operations.md), [Module 6 detection](docs/module6-detection.md), and [Module 7 classifier](docs/module7-classifier.md). Mailbox response actions are not implemented.

## Module 1: run and test

From the project root, copy `.env.example` to `.env` and replace the Django, database, and RabbitMQ example secrets before the first run:

```powershell
Copy-Item .env.example .env
# Edit .env: set DJANGO_SECRET_KEY, DATABASE_PASSWORD, and RABBITMQ_PASSWORD.
docker compose up --build -d
docker compose exec web python manage.py test core
Invoke-RestMethod http://localhost:8000/health/
```

The test command runs the database, admin, fixture, storage, Gmail, and migration tests. The health command should return `status: ok`. To stop the application while preserving its data, run `docker compose down`.

## Requirements

- Docker Desktop or Docker Engine with Compose v2, for the recommended setup.
- Alternatively, Python 3.12+ and PostgreSQL 16+ for a host setup.

The application uses Django 5.2 LTS (`>=5.2.18,<5.3`) and psycopg 3. The [Django support schedule](https://www.djangoproject.com/download/) lists extended support for the 5.2 LTS series through April 2028. Update to newer 5.2 patch releases as they become available.

## Start with Docker Compose

1. Start Docker Desktop/Engine. Copy `.env.example` to `.env` (PowerShell: `Copy-Item .env.example .env`; POSIX shell: `cp .env.example .env`).
2. Edit `.env`: set long random, different values for `DJANGO_SECRET_KEY`, `DATABASE_PASSWORD`, and `RABBITMQ_PASSWORD`. Keep `.env` private. The example is for local development (`DJANGO_DEBUG=1`).
3. Run `docker compose up --build -d`. Compose starts PostgreSQL, waits for its health check, applies Django migrations, and starts the development server.
4. Run `docker compose logs -f web` to inspect startup. Open `http://localhost:8000/health/`; a successful response is `{"status":"ok"}`.
5. Run `docker compose exec web python manage.py bootstrap_dev --with-sample-cases` to create the synthetic development organization, staff owner, and two pending `example.test` mailboxes. Running it again returns the same records. The optional sample cases contain no message body or MIME and all sample actions are skipped.
6. To sign in as the synthetic owner, run `docker compose exec web python manage.py changepassword demo_owner` and choose a local password interactively. The bootstrap command stores no password or provider credential; the owner starts with an unusable password. Open `http://localhost:8000/admin/`.

Stop the stack with `docker compose down`. The PostgreSQL and private artifact named volumes persist. `docker compose down -v` **deletes both volumes and their data**.

### Run management commands

```text
docker compose exec web python manage.py check
docker compose exec web python manage.py showmigrations core
docker compose exec web python manage.py shell
docker compose exec web python manage.py bootstrap_dev --help
```

The web container runs as an unprivileged user. Compose exposes PostgreSQL only on the local loopback interface at host port 5433 by default, so it can coexist with a local PostgreSQL server on 5432. The web container connects internally to `db:5432`. To inspect the Compose database in pgAdmin, connect to `127.0.0.1:5433` using the database credentials in `.env`; set `POSTGRES_HOST_PORT` to another free port if needed. The development web server is exposed only at port 8000 on loopback.

### Custom synthetic setup

```powershell
docker compose exec web python manage.py bootstrap_dev --slug lab --name "Lab" --owner lab_owner --mailbox alerts@example.test --mailbox finance@example.test --with-sample-cases
docker compose exec web python manage.py changepassword lab_owner
```

The command requires `DJANGO_DEBUG=1`, accepts only mailbox addresses under `example.test`, and refuses to promote an existing unrelated user. It creates a staff owner with an unusable password, an active owner membership, and pending mailbox records. The optional sample records use synthetic IDs, empty subject and sender fields, no artifact file, and a skipped action. No Gmail credential, MIME, or email body is stored.

### Admin roles

All admin users need `is_staff=True` and an active membership in an active organization. Superusers can inspect all organizations and manage global Django users and groups. Owners can view their organization and memberships, edit organization settings, and add pending mailboxes. Admin members can view organization settings and memberships and add pending mailboxes. Analysts can inspect cases, evidence, runs, actions, feedback, artifacts, and audit history. Viewers can inspect cases, mailboxes, evidence, runs, actions, and feedback; artifact and audit views are hidden from them. Owners and admins can also inspect those operational records. Global Django user and group admin views remain superuser-only even if a staff user has a separately granted auth permission. Mailbox organization, address, provider identity, and state cannot be changed through admin after creation. Operational records are read-only; the write services and database triggers remain authoritative.

## Run directly on the host

1. Create and activate a Python 3.12+ virtual environment. Install dependencies: `python -m pip install -r requirements.txt`.
2. Create a PostgreSQL 16+ database and login matching `.env` (`DATABASE_NAME`, `DATABASE_USER`, `DATABASE_PASSWORD`). For example, in a PostgreSQL administrator `psql` session, run `CREATE ROLE yphish LOGIN PASSWORD '<the-password-from-.env>';` and `CREATE DATABASE yphish OWNER yphish;`. Set `DATABASE_HOST=localhost` and `DATABASE_PORT=5432` or adjust them for your server. Use a different role/database name if you change their environment variables.
3. Export every variable in `.env` into the process environment. Django does **not** read `.env` directly. For PowerShell, one option is to set variables in the current session from the edited file:

   ```powershell
   Get-Content .env | Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]*=' } | ForEach-Object {
       $name, $value = $_ -split '=', 2
       [Environment]::SetEnvironmentVariable($name, $value, 'Process')
   }
   ```

4. Run `python manage.py migrate`, `python manage.py check`, and `python manage.py runserver` from the project root. Visit `http://localhost:8000/health/`.

For a POSIX shell, `set -a; . ./.env; set +a` exports a trusted `.env` file into the current shell. The artifact directory defaults to `<project>/private_artifacts` when `PRIVATE_ARTIFACT_ROOT` is relative to the project working directory.

## Configuration

| Variable | Purpose |
| --- | --- |
| `DJANGO_SECRET_KEY` | Required signing key. Use a random, secret value. |
| `DJANGO_DEBUG` | `1` for local development; `0` for deployment. |
| `DJANGO_ALLOWED_HOSTS` | Required comma-separated hostnames. |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | Optional comma-separated full origins. |
| `DATABASE_NAME`, `DATABASE_USER`, `DATABASE_PASSWORD` | Required PostgreSQL credentials. |
| `DATABASE_HOST`, `DATABASE_PORT` | PostgreSQL endpoint; defaults to `localhost:5432` for host use. Compose sets the host to `db`. |
| `POSTGRES_HOST_PORT` | Optional host port for the Compose database; defaults to `5433`. |
| `PRIVATE_ARTIFACT_ROOT` | Private filesystem directory. Compose mounts a named volume at `/app/private_artifacts`. |
| `RABBITMQ_PASSWORD` | Required Compose broker password, distinct from the database password. |
| `GOOGLE_INGESTION_SERVICE_ACCOUNT_FILE` | Read-only ingestion service-account JSON path for host execution; Compose mounts `secrets/google-service-account.json`. |
| `GOOGLE_RESPONSE_SERVICE_ACCOUNT_FILE` | Separate reserved response identity path; Module 4 makes no response calls. |
| `GMAIL_POLL_INTERVAL_SECONDS`, `GMAIL_ANALYSIS_SWEEP_INTERVAL_SECONDS` | Celery Beat polling and pending-analysis reconciliation intervals. |
| `GMAIL_ANALYSIS_DISPATCH_BATCH_SIZE`, `GMAIL_ANALYSIS_REDISPATCH_SECONDS`, `GMAIL_ANALYSIS_LEASE_SECONDS` | Analysis outbox dispatch and crash recovery controls. |
| `GMAIL_RETRY_BASE_SECONDS`, `GMAIL_RETRY_MAX_SECONDS` | Gmail retry backoff with jitter; provider `Retry-After` can be longer. |
| `DETECTION_INDICATOR_MODE` | `operational` by default; `synthetic` is available only in debug mode. |
| `DETECTION_AUTH_RESULTS_MODE` | `untrusted_context` or `ignore`; retrieved MIME headers are never trusted automatically. |
| `CLASSIFIER_ACTIVE_VERSION`, `CLASSIFIER_MODEL_ROOT` | Optional signed classifier version and private model artifact directory. Empty version records classifier unavailability while rules continue. |
| `CLASSIFIER_DATASET_SELECTION_FILE`, `CLASSIFIER_APPROVAL_KEY` | Explicit signed dataset selection used only by training/evaluation commands. |
| `CLASSIFIER_SIGNING_KEY`, `CLASSIFIER_ALLOW_SYNTHETIC` | Artifact verification key and debug-only permission to use synthetic models. See the Module 7 guide. |

`DJANGO_DEBUG=0` enables secure session and CSRF cookies. For a real deployment, put a production WSGI/ASGI server behind HTTPS, configure proxy and TLS settings, restrict database connectivity, and back up **both** the database and artifact store. Compose's `runserver` is for development only.

## Data model and integrity

See [the complete model and constraint reference](docs/data-model.md) for every model, named database constraint, index, relationship guard, and state.

- `Organization` owns tenant records; `Membership` links Django users to organizations with owner, admin, analyst, or viewer roles.
- `Mailbox` records an enrolled address and its enrollment state (`pending`, `active`, `paused`, `error`). No provider credentials are stored in this model.
- `EmailCase` binds a message to one mailbox and tracks processing (`queued`, `processing`, `analyzed`, `action_pending`, `completed`, `failed`) and verdict (`unknown`, `legitimate`, `suspicious`, `malicious`). Message bodies are not stored in this row.
- `Artifact` holds a private file, its SHA-256 digest, size, kind, and storage state (`pending`, `stored`, `failed`, `deleted`). `AnalysisRun` tracks attempts; `Evidence` records sourced observations and unavailable/error outcomes.
- `ActionExecution` records an intended or executed response and its idempotency key. `Feedback` records proposed corrections. `AuditEvent` records history and is append-only at the database level.

The initial migration creates PostgreSQL unique/check constraints and query indexes. The second migration adds tenant relationship triggers. The third adds idempotency keys and failure-state constraints. The fourth adds Gmail identity fields; the fifth adds enrollment boundaries, sync status, gap visibility, label IDs, and internalDate while preserving legacy rows. The sixth adds queue leases, retry timing, deletion tombstones, and explicit integration states. The seventh adds structured rule evidence fields and timestamped indicator snapshots. Mailbox addresses are case-insensitively unique per organization. Gmail message IDs are unique within each organization and mailbox.

The models establish persistence and legal states, and the service guards the failure and skipped transitions described below. Read-only Gmail polling is documented in the [Gmail guide](docs/gmail.md). Mailbox response execution is outside Module 4.

### Transactional write services

`core.services` provides `create_email_case`, `record_evidence`, and `create_action_execution`. Each returns `(record, created)`. Callers supply a persisted organization and related records; the service validates their relationships, writes the new row and its audit event in one transaction, and returns the existing row on a duplicate request. Database unique constraints settle concurrent inserts.

- Gmail case creation requires a nonblank, case-sensitive `gmail_message_id`, unique within `(organization, mailbox)`. New Gmail rows also populate the retained `provider_immutable_id` for existing integrity guards. A retry does not overwrite case metadata or state; `gmail_thread_id` is context only.
- Evidence recording requires a stable, nonblank idempotency key unique within one case. A database trigger rejects new blank keys while allowing older keyless evidence to remain. A repeat with different evidence data raises `IdempotencyConflict`. Supply the original timezone-aware `observed_at` on retries.
- Action creation requires a stable, nonblank idempotency key unique across the organization. Reusing it for another case, action, policy version, analysis run, or target raises `IdempotencyConflict`. Creation only records a `proposed` action; it does not authorize or execute it.
- `mark_action_failure` records `failed` only when a started attempt is known not to have succeeded. Use `uncertain=True` only after an action entered `running` and the external outcome is unknown; it records `reconciling`, which requires provider-state reconciliation before another attempt. `mark_action_skipped` records a proposed or authorized action that was never attempted. Failed, reconciling, and skipped rows require a nonblank `error_code`; the migration assigns `legacy_unspecified` to any older rows missing one.

The database trigger remains the final guard against cross-organization/case relationships even when callers bypass the services. The services raise `InvalidRelationship` before writing when they detect one. Gmail workers call these Python APIs; no ingestion HTTP endpoint is exposed.

## Private artifact storage

`Artifact.file` uses `PrivateArtifactStorage`, which stores files under `PRIVATE_ARTIFACT_ROOT` with random names under organization/case UUID directories. Submitted filenames never become storage paths. Created files and directories request `0600` and `0700` permissions respectively, and the storage exposes no URL. No `/media/` route exists. Never map the private directory into a web server's static files location. The database stores file paths and metadata; include the private volume in backups and retention/deletion procedures.

## Migrations and verification

Run `python manage.py makemigrations --check --dry-run` to confirm model definitions match committed migrations. Run `python manage.py check` for Django system checks and `python manage.py test core` for PostgreSQL-backed integrity tests. With Compose, use:

```powershell
docker compose exec web python manage.py makemigrations --check --dry-run
docker compose exec web python manage.py test core
```

The migrations require PostgreSQL and run automatically in the Compose setup. If changing the schema, create and review a migration, then apply it with `python manage.py migrate`. The `core` migrations are PostgreSQL-specific because tenant and audit guards use PL/pgSQL.

To verify the migration chain without touching the main development database, use a new disposable database name:

```powershell
docker compose exec -T db createdb -U yphish yphish_module1_verify
docker compose exec -T db psql -U yphish -d yphish_module1_verify -tAc "SELECT count(*) FROM pg_tables WHERE schemaname='public'"
docker compose run --rm -T -e DATABASE_NAME=yphish_module1_verify web python manage.py migrate --noinput
docker compose exec -T db dropdb -U yphish yphish_module1_verify
```

The table count must be `0` before migration. The final command removes only the disposable database you just created. The PostgreSQL test runner also applies the migration chain to a fresh test database.
