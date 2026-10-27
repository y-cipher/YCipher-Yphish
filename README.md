# 🛡️ Yphish

**Evidence-driven phishing investigation and automatic Gmail response for Google Workspace teams.**

Connect enrolled mailboxes, inspect message evidence, and apply controlled responses through an organization-scoped operator dashboard.

[Features](#features) · [Tech Stack](#tech-stack) · [Getting Started](#getting-started) · [Usage](#usage) · [Configuration](#configuration) · [Troubleshooting](#troubleshooting) · [Documentation](#documentation)

> **Try it locally first:** the dashboard and automated tests work without Google credentials. Real mailbox processing requires separate Google Workspace administrator configuration.

<a id="features"></a>

## ✨ Key Features

- **Direct Gmail integration:** incremental polling, durable history cursors, and explicit mailbox enrollment.
- **Evidence-backed analysis:** versioned rule observations, provenance, errors, and visible coverage gaps.
- **Optional machine learning:** TF-IDF and logistic regression with signed model artifacts and explicitly selected training data.
- **Bounded investigations:** controlled tools for local indicator lookups, optional DNS, and approved historical context.
- **Automatic message response:** apply `Yphish/Suspicious` and optionally remove `INBOX` when the configured policy qualifies.
- **Recoverable actions:** record exact changes and support restoration after a reviewed legitimate correction.
- **Organization-scoped access:** role-based dashboard permissions, private artifacts, and audited operator changes.
- **Developer-friendly workflow:** Docker Compose, reproducible management commands, and PostgreSQL-backed tests.

**Current scope:** investigation uses an explicit policy; an LLM selector is an extension point rather than a configured feature. Labeling and inbox removal happen after delivery and do not make a message inaccessible. Rule/model outputs are evidence; a classifier score alone does not authorize an action, and a successfully analyzed case can retain an `unknown` verdict.

<a id="tech-stack"></a>

## 🧰 Tech Stack

| Layer | Technologies |
| --- | --- |
| Language and framework | **Python 3.12**, **Django 5.2 LTS** |
| Interface | Django templates, **Bootstrap 5.3.8**, CSS, JavaScript |
| Database | **PostgreSQL 16**, psycopg 3, Django ORM and migrations |
| Background processing | **Celery**, **RabbitMQ**, Celery Beat |
| Email integration | **Gmail API**, Google Auth, Google API Python Client |
| Detection and ML | Deterministic rules, **scikit-learn**, TF-IDF, logistic regression, joblib |
| Investigation | Explicit selection policy, cached indicators, dnspython, bounded historical context |
| Packaging and serving | **Docker Compose**; Gunicorn, WhiteNoise, and Caddy in the HTTPS trial profile |
| Tests | Django test runner, PostgreSQL, synthetic fixtures, mocked external services |

Dependency ranges are defined in [requirements.txt](requirements.txt); service images and startup commands are defined in [compose.yaml](compose.yaml).

<a id="getting-started"></a>

## 🚀 Getting Started

<a id="prerequisites"></a>

### Prerequisites

For the recommended setup, install:

- Git.
- Docker Desktop on Windows/macOS, or Docker Engine with Docker Compose v2 or newer on Linux.
- A running Linux container engine. On Windows, Docker Desktop normally uses WSL 2.

Compose supplies Python, PostgreSQL, and RabbitMQ; you do not need to install them separately. The image uses Python 3.12 and Django 5.2 LTS. See [requirements.txt](requirements.txt) for dependency ranges.

Commands below use **PowerShell** and run from the repository root. Basic Docker commands also work in other shells; adapt the file-copy and environment commands for your shell.

<a id="first-time-setup"></a>

### Installation

Follow these steps in order. All commands run from the folder containing `manage.py` and `compose.yaml`.

#### 1. Open the repository

For a new checkout:

```powershell
git clone https://github.com/y-cipher/YCipher-Yphish.git Yphish
Set-Location Yphish
```

If you already have a checkout, open it instead. For example:

```powershell
Set-Location "D:\Open Source Contributions\Yphish"
```

Your working directory should contain `manage.py` and `compose.yaml`.

#### 2. Start Docker

Start Docker Desktop. On Windows, you can use:

```powershell
docker desktop start --timeout 60
```

Verify that the engine is available:

```powershell
docker version
docker compose version
```

`docker version` must show both **Client** and **Server** information. Resolve daemon or named-pipe errors before continuing; see [Troubleshooting](#troubleshooting).

#### 3. Create the environment file

Copy the example only if `.env` does not already exist:

```powershell
if (-not (Test-Path -LiteralPath ".env")) {
    Copy-Item -LiteralPath ".env.example" -Destination ".env"
}

notepad .env
```

Replace `DJANGO_SECRET_KEY`, `DATABASE_PASSWORD`, and `RABBITMQ_PASSWORD` with long, random, different values. Keep `.env` private and out of Git.

For local HTTP development, retain:

```dotenv
DJANGO_DEBUG=1
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1
DJANGO_CSRF_TRUSTED_ORIGINS=http://localhost:8000
```

If PostgreSQL was already initialized, retain its working credentials. Editing `.env` alone does not change the password stored in an existing database volume. On Linux/macOS, use your editor and equivalent file-copy command without overwriting an existing `.env`.

#### 4. Build and start

```powershell
docker compose config --quiet
docker compose up --build -d --wait --wait-timeout 180
docker compose ps
```

Compose starts five services:

| Service | Purpose |
| --- | --- |
| `db` | PostgreSQL database |
| `rabbitmq` | Background-task broker |
| `web` | Django dashboard, admin, and management commands |
| `worker` | Synchronization, analysis, investigation, and response tasks |
| `beat` | Scheduled polling and recovery tasks |

Web startup applies migrations and collects static assets before starting Django's development server. The first build also downloads images and Python dependencies.

#### 5. Check application health

```powershell
docker compose exec web python manage.py check
Invoke-RestMethod -Uri "http://localhost:8000/health/" -TimeoutSec 10
```

Django should report no system-check issues. The health endpoint should return `{"status":"ok"}`. This confirms the web application responds; it does not verify Gmail authorization or detection performance.

<a id="usage"></a>

## ▶️ Usage / Quick Start

After installation, use the local walkthrough to explore cases, then connect real mailboxes when you are ready.

### Sign in and explore sample cases

```powershell
docker compose exec web python manage.py bootstrap_dev --with-sample-cases
docker compose exec web python manage.py changepassword demo_owner
```

Enter a password when prompted. Open the [dashboard](http://localhost:8000/dashboard/) and sign in as **`demo_owner`** with that password. There is no default password.

| Page | Address |
| --- | --- |
| Dashboard | [http://localhost:8000/dashboard/](http://localhost:8000/dashboard/) |
| Django admin | [http://localhost:8000/admin/](http://localhost:8000/admin/) |
| Health | [http://localhost:8000/health/](http://localhost:8000/health/) |

Bootstrap creates organization `demo-org`, an owner membership, two pending `example.test` mailboxes, and optional synthetic cases. It is repeatable and requires `DJANGO_DEBUG=1`. Sample cases contain no email body or original MIME, and their sample actions are skipped. These mailboxes cannot connect to real Gmail.

<a id="testing"></a>

### Run the tests

Start the stack, then run:

```powershell
docker compose exec web python manage.py makemigrations --check --dry-run
docker compose exec web python manage.py test core --noinput
```

A successful suite ends with **`OK`**. `Destroying test database for alias 'default'` is normal: Django removes the temporary test database, not the main application database. The test count changes as coverage grows.

The test runner collects assets into a fresh temporary directory and uses the real strict static manifest. You do not need to run `collectstatic` manually before tests.

#### Focused tests

```powershell
# Login, dashboard, admin, and static assets.
docker compose exec web python manage.py test core.test_csrf core.test_dashboard core.test_admin core.test_staticfiles --noinput

# Gmail ingestion and background processing.
docker compose exec web python manage.py test core.test_gmail core.test_gmail_migration core.test_module5 --noinput

# Rules, classifier, and investigation.
docker compose exec web python manage.py test core.test_detection core.test_classifier core.test_investigation --noinput

# Automatic response and operational controls.
docker compose exec web python manage.py test core.test_response core.test_operations --noinput
```

Tests use PostgreSQL, synthetic messages, and mocked external services. Enrollment messages printed during tests describe fixtures, not a real Workspace connection. Passing tests does not establish live Gmail behavior or phishing accuracy.

For schema changes, create migrations with `python manage.py makemigrations core` in a configured host environment, review them, and apply them with `python manage.py migrate`. Compose applies committed migrations at startup. PostgreSQL-specific constraints and triggers mean SQLite is not a supported substitute.

<a id="everyday-development"></a>

### Everyday commands

| Task | Command |
| --- | --- |
| Start existing containers | `docker compose up -d --wait --wait-timeout 180` |
| Rebuild after source/dependency changes | `docker compose up --build -d --wait --wait-timeout 180` |
| Reload changed `.env` values | `docker compose up -d --force-recreate web worker beat` |
| Show status | `docker compose ps` |
| Follow logs | `docker compose logs -f --tail=100 web worker beat` |
| Check workers and synchronization | `docker compose exec worker python manage.py gmail_health --json` |
| Ping workers | `docker compose exec worker celery -A config inspect ping` |
| Open a Django shell | `docker compose exec web python manage.py shell` |
| Inspect migrations | `docker compose exec web python manage.py showmigrations core` |
| Stop and preserve data | `docker compose down` |

**Source is copied into the image, not mounted for automatic reload.** Rebuild after changing Python, templates, CSS, or JavaScript. Restarting alone uses the existing image. Environment changes require container recreation rather than just `docker compose restart`.

Press **Ctrl+C** to stop following logs; detached containers keep running. Running tests does not start or stop the application server.

Named volumes retain the database, private artifacts, and model artifacts across `docker compose down`. Adding `-v` deletes the project's named volumes and their data.

For pgAdmin or another host database client, connect to `127.0.0.1:5433` with the database credentials from `.env`. Change `POSTGRES_HOST_PORT` if occupied. Containers use `db:5432`; do not change their internal port to `5433`.

<a id="connect-google-workspace-gmail"></a>

### Connect a real Google Workspace mailbox

This integration requires an organization-managed **Google Workspace** domain and a Workspace administrator. Personal `@gmail.com` OAuth enrollment is not implemented. Dashboard login and Gmail authorization are separate; Google OIDC dashboard login is also not implemented.

#### 1. Configure ingestion credentials

Follow [Gmail setup](docs/gmail.md) to enable the Gmail API and service-account domain-wide delegation. Grant the ingestion identity exactly:

```text
https://www.googleapis.com/auth/gmail.readonly
```

Place its JSON key at `secrets/google-service-account.json`. Compose mounts this directory read-only into `web` and `worker`. Never commit keys or paste their contents into `.env`, source, screenshots, or logs.

The application's enrolled-mailbox checks do not narrow Google's underlying domain-wide delegation grant. Protect the delegated identity and its key accordingly.

#### 2. Create real organization records

Create a global administrator if needed:

```powershell
docker compose exec web python manage.py createsuperuser
```

In [Django admin](http://localhost:8000/admin/):

1. Create an active organization and choose its slug.
2. Link your dashboard user to it with an active owner membership.
3. Create a pending Gmail mailbox using its exact primary Workspace address.

Use real organization records, not the synthetic `example.test` mailboxes. Enrollment verifies the provider profile and records the ingestion client identity.

#### 3. Enroll and synchronize

```powershell
docker compose up -d --force-recreate web worker beat

$orgSlug = Read-Host "Organization slug created in Django admin"
$gmailMailbox = Read-Host "Exact primary Workspace mailbox address"

docker compose exec web python manage.py enroll_gmail_mailbox --organization "$orgSlug" --mailbox "$gmailMailbox"
docker compose exec web python manage.py sync_gmail_mailbox --organization "$orgSlug" --mailbox "$gmailMailbox"
docker compose exec worker python manage.py gmail_health --json
```

The first scan records historical messages as a baseline. History replay handles messages arriving during initialization. Synchronization deduplicates by organization, mailbox, and Gmail message ID; thread ID is only conversation context.

Send a harmless new message after initial synchronization and inspect **Dashboard -> Cases**. Polling defaults to 60 seconds; analysis and investigation are additional queued steps. Inspect evidence and coverage as well as processing status. An unavailable model or empty indicator cache is not proof of safety or a synchronization failure.

Expired history cursors produce a visible coverage gap and controlled recovery. See [background operations](docs/module5-operations.md) for details.

<a id="enable-automatic-response"></a>

### Enable automatic response

Read the [response guide](docs/module9-response.md) for credential setup, eligibility, reconciliation, and restoration.

1. Create a separate delegated response service account with a different client ID and key.
2. Configure the exact scopes enforced by the current code:

   ```text
   https://www.googleapis.com/auth/gmail.modify.restricted
   https://www.googleapis.com/auth/gmail.labels
   ```

3. Place its JSON key at `response_secrets/google-response-service-account.json`. Only `worker` mounts that directory.
4. Configure the response client ID and both scope fields on the organization in Django admin.
5. Enable response for the organization and each intended enrolled mailbox. Enable optional `INBOX` removal only where desired.
6. Ensure `GMAIL_RESPONSE_ENABLED=1`; recreate `web`, `worker`, and `beat` after environment changes.

The local `.env.example` enables the global switch, but an action also requires organization/mailbox enablement, valid credentials, and qualifying evidence. The HTTPS trial example starts with the global switch disabled.

The current policy requires a ready mailbox, a recent nonhistorical case, successful rule analysis, a completed investigation, an applicable operational indicator match, and an independent link-mismatch or link-free payment-redirection observation. Model scores, urgency, and synthetic indicators alone do not authorize response. Qualifying runtime actions execute automatically.

A reviewed legitimate correction can trigger restoration of Yphish-owned changes where current Gmail state permits it. Restoration preserves unrelated labels and does not resurrect messages from Spam or Trash.

#### Suspend automatic response

```powershell
docker compose stop beat worker
# Edit .env and set GMAIL_RESPONSE_ENABLED=0 before continuing.
docker compose up -d --force-recreate web worker beat
```

In-flight tasks may finish while stopping. Inspect the action ledger and Gmail state during an incident. The global switch also blocks automated restoration; use the detailed recovery instructions when a correction is needed while response is suspended.

<a id="configuration"></a>

## ⚙️ Configuration / Environment Variables

Use [.env.example](.env.example) for local development and [.env.trial.example](.env.trial.example) when following the HTTPS trial guide. Keep your actual `.env` private.

**Required credentials:** replace the example `DJANGO_SECRET_KEY`, `DATABASE_PASSWORD`, and `RABBITMQ_PASSWORD` before starting. Keep the database name/user and host settings aligned with your PostgreSQL instance.

| Variable | Purpose | Local example / action |
| --- | --- | --- |
| `DJANGO_SECRET_KEY` | Django signing and sessions | **Required:** supply a long random secret. |
| `DATABASE_PASSWORD` | PostgreSQL authentication | **Required:** supply a distinct database password. |
| `RABBITMQ_PASSWORD` | Compose broker authentication | **Required:** supply a different broker password. |
| `DATABASE_NAME` | PostgreSQL database name | `yphish` |
| `DATABASE_USER` | PostgreSQL login | `yphish` |
| `DJANGO_DEBUG` | Local development behavior | `1`; use `0` with the HTTPS deployment settings. |
| `DJANGO_ALLOWED_HOSTS` | Allowed hostnames | `localhost,127.0.0.1` |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | Trusted complete origins | `http://localhost:8000` |
| `DATABASE_HOST`, `DATABASE_PORT` | Host-run database endpoint | `localhost`, `5432`; Compose supplies host `db`. |
| `POSTGRES_HOST_PORT` | Database port exposed on your computer | `5433` by default; containers use internal port `5432`. |

Compose reads `.env`; a Django process started directly on your computer does not. A service's explicit `environment` values in `compose.yaml` override matching `.env` values inside that container. See [Optional host setup](#optional-host-setup) for loading variables into a local Python process.

<details>
<summary><strong>Additional Gmail, model, investigation, and retention settings</strong></summary>

| Setting | Purpose |
| --- | --- |
| `PRIVATE_ARTIFACT_ROOT` | Private file location; Compose uses `/app/private_artifacts` on a named volume. |
| `GOOGLE_INGESTION_SERVICE_ACCOUNT_FILE` | Host ingestion key path; Compose supplies `/run/secrets/google-service-account.json`. |
| `GOOGLE_RESPONSE_SERVICE_ACCOUNT_FILE` | Separate response key path, supplied only to the Compose worker. |
| `GMAIL_POLL_INTERVAL_SECONDS` | Polling interval; default `60`. |
| `GMAIL_ANALYSIS_*`, `GMAIL_RETRY_*` | Dispatch, leases, reconciliation, and retry settings. See [operations](docs/module5-operations.md). |
| `DETECTION_INDICATOR_MODE` | `operational` by default; synthetic mode requires debug. |
| `DETECTION_AUTH_RESULTS_MODE` | `untrusted_context` or `ignore`; retrieved headers are not automatically verified. |
| `CLASSIFIER_ACTIVE_VERSION`, `CLASSIFIER_MODEL_ROOT` | Optional signed model version and storage location. Empty version records model unavailability while rules continue. |
| `CLASSIFIER_SIGNING_KEY`, `CLASSIFIER_APPROVAL_KEY`, `CLASSIFIER_DATASET_SELECTION_FILE` | Model verification and explicitly authorized training data. See [classifier](docs/module7-classifier.md). |
| `CLASSIFIER_ALLOW_SYNTHETIC` | Debug-only synthetic artifact permission; default `0`. |
| `INVESTIGATION_*` | Tool/context permissions and investigation budgets. DNS is disabled by default. See [investigation](docs/module8-investigation.md). |
| `GMAIL_RESPONSE_*` | Global switch, dispatch, limits, circuit breaker, and eligible case age. See [response](docs/module9-response.md). |
| `ARTIFACT_RETENTION_*` | Private-file pruning; database metadata and backups need separate retention policies. |

</details>

### Indicators and model training

These paths have data prerequisites and are separate from first-time startup:

- [Detection guide](docs/module6-detection.md): snapshot format, expiry, operational/synthetic imports, and backfill.
- [Classifier guide](docs/module7-classifier.md): reviewed JSONL format, signed selection, chronological splits, training, evaluation, and activation.

An empty cache or absent model is an explicit coverage limitation. Gmail `SPAM` is not phishing ground truth. Mailbox content is not automatically selected for training.

<a id="developer-reference"></a>

## 🧭 Developer Reference

<a id="project-structure-and-data-boundaries"></a>

### Project structure and data boundaries

```text
Gmail polling -> private MIME -> rules/model evidence -> bounded investigation
                                                            |
                                               automatic response policy
                                                            |
                                           label / optional INBOX removal

Dashboard: evidence, processing, actions, corrections, and integration health
```

| Location | Responsibility |
| --- | --- |
| `config/` | Django settings, entry points, and isolated static-file test runner |
| `core/models.py`, `core/migrations/` | Records, constraints, and PostgreSQL relationship guards |
| `core/services.py` | Transactional case, evidence, and action creation |
| `core/gmail*.py` | Credentials, API clients, synchronization, and message modification |
| `core/analysis_runtime.py`, `core/detection.py`, `core/indicators.py` | MIME analysis and rule evidence |
| `core/ml_*.py` | Dataset validation, features, training, and signed model serving |
| `core/investigation.py` | Bounded investigation and tool selection |
| `core/response_policy.py`, `core/response_runtime.py` | Eligibility, actions, reconciliation, and recovery |
| `core/tasks.py` | Worker tasks and scheduled recovery |
| `core/dashboard_*.py`, `core/templates/`, `core/static/` | Operator interface |
| `core/management/commands/` | Enrollment, synchronization, training, imports, and health commands |
| `deploy/`, `compose.trial.yaml`, `scripts/` | HTTPS trial deployment and operational tools |
| `docs/` | Detailed implementation guides and runbooks |

`Organization` owns operational records. `Membership` gives a user an owner, admin, analyst, or viewer role. Dashboard access requires active membership in an active organization; Django admin additionally requires staff status. Global user administration is superuser-only. See [dashboard permissions](docs/module10-dashboard.md).

Write services validate related records and use database constraints to resolve duplicates. Evidence/actions require stable idempotency keys. An uncertain external action enters reconciliation before another attempt. Original MIME uses private storage with random paths and no public URL. Back up the database and artifact volume together. See [data model](docs/data-model.md) for the complete contracts.

<a id="optional-host-setup"></a>
<details>
<summary><strong>Advanced: run Django directly in a local Python environment</strong></summary>

Use this for Python development or Django-only debugging. Host `runserver` does not start the broker, worker, or scheduler; Compose is the complete application path.

Install Python 3.12+ and PostgreSQL 16+. Create a database and role matching `.env`; the test role also needs permission to create test databases. Then, in PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Load your trusted `.env` into this terminal. This simple loader expects unquoted `KEY=value` entries as in `.env.example`; it is not a full dotenv parser:

```powershell
Get-Content -LiteralPath ".env" |
    Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]*=' } |
    ForEach-Object {
        $settingName, $settingValue = $_ -split '=', 2
        [Environment]::SetEnvironmentVariable($settingName, $settingValue, 'Process')
    }
```

Set the database endpoint for your server: typically `localhost:5432` for native PostgreSQL, or `127.0.0.1:5433` for the running Compose database unless its host port was changed.

```powershell
python manage.py migrate
python manage.py check
python manage.py collectstatic --noinput
python manage.py runserver 127.0.0.1:8000
```

Run `python manage.py test core --noinput` in another terminal with the same environment loaded. Choose an unused web port if Compose already occupies 8000. Do not run host workers against a database whose artifact paths refer to a different filesystem layout.

</details>

<a id="troubleshooting"></a>

## 🛠️ Troubleshooting

| Symptom | What to check |
| --- | --- |
| Missing `dockerDesktopLinuxEngine` pipe or daemon connection error | Start Docker Desktop's Linux engine. `docker version` must show Server information. If Desktop crashes, inspect its diagnostics; this is an engine startup issue. |
| Startup wait times out | Inspect `docker compose ps` and `docker compose logs --tail=100 web db rabbitmq worker beat` to identify the unhealthy service. |
| Code changes do not appear | Run `docker compose up --build -d --wait --wait-timeout 180`, then refresh. Source is copied into images. |
| Missing staticfiles manifest entry | Update/rebuild the web image. Startup collects assets and tests use the isolated static runner. A host-run server needs `python manage.py collectstatic --noinput`. |
| CSRF failure with `Origin: null` | Use the current dashboard template with `same-origin` referrer policy. Rebuild and hard-refresh with Ctrl+Shift+R, then reload the form. Keep CSRF checks enabled; do not trust `null` or exempt login. |
| Other cookie/CSRF errors | Use one consistent host, reload old forms after login changes, allow cookies, and check scheme/port in trusted origins. Local HTTP uses debug mode; the HTTPS trial uses secure cookies. |
| `demo_owner` cannot sign in | Run `changepassword demo_owner`. Bootstrap supplies no default password and requires debug mode. |
| Login succeeds but no organization is available | Add an active membership linking the user to an active organization. Login alone does not establish dashboard access. |
| Database authentication fails after an `.env` edit | Existing volumes retain their database credentials. Restore matching configuration or deliberately change the database role password. Container recreation does not rotate it. |
| Web health is OK but no new cases appear | Run `docker compose exec worker python manage.py gmail_health --json`; check enrollment, broker, worker, scheduler, and sync lag. |
| Gmail authorization fails | Check API enablement, delegated numeric client IDs, exact scopes, key paths, and primary address. This implementation requires Workspace. |
| Initial messages are historical | This is expected baseline behavior. Send a new message after enrollment and allow polling/analysis to run. |
| No automatic label change | Check global/org/mailbox flags, separate response credentials, case age, completed investigation, operational indicators, and action policy reasons. Model scores and synthetic cases alone do not qualify. |
| Model or indicator cache unavailable | Configure a signed model or import a current approved snapshot. Inspect coverage; unavailable does not mean safe. |

For cursor gaps, response conflicts, suspension, and recovery procedures, use the [trial runbooks](docs/module11-trial-operations.md).

<a id="https-trial-deployment"></a>

## 🌐 HTTPS Trial Deployment

The base Compose file runs a local development server. The separate trial overlay uses Gunicorn, WhiteNoise, and Caddy for HTTPS.

Follow [trial operations](docs/module11-trial-operations.md) on a dedicated host. Configure the trial `.env`, real DNS, unique secrets, and Google identities first:

```powershell
docker compose -f compose.yaml -f compose.trial.yaml config --quiet
docker compose -f compose.yaml -f compose.trial.yaml up --build -d --wait --wait-timeout 180
docker compose -f compose.yaml -f compose.trial.yaml exec web python manage.py check --deploy
docker compose -f compose.yaml -f compose.trial.yaml exec worker python manage.py trial_readiness --json --require-enrollment
docker compose -f compose.yaml -f compose.trial.yaml exec worker python manage.py gmail_health --json
```

The trial example disables automatic response initially. Readiness can fail until enrollment and security settings are complete. Framework checks and mocked tests do not verify real Google grants, external TLS, backup recovery, or detection performance. Complete the guide's live checks before enabling mailbox changes or broadening access.

<a id="documentation"></a>

## 📚 Documentation

| Guide | Purpose |
| --- | --- |
| [Data model](docs/data-model.md) | Schemas, constraints, identity, and write-service contracts |
| [Gmail setup](docs/gmail.md) | Delegation, enrollment, and history synchronization |
| [Background operations](docs/module5-operations.md) | Dispatch, retries, leases, health, and recovery |
| [Detection](docs/module6-detection.md) | Rules, coverage, indicator snapshots, and backfill |
| [Classifier](docs/module7-classifier.md) | Authorized datasets, training, evaluation, and signed artifacts |
| [Investigation](docs/module8-investigation.md) | Tools, context, limits, and stopping behavior |
| [Response](docs/module9-response.md) | Automatic labeling, inbox removal, restoration, and limits |
| [Dashboard](docs/module10-dashboard.md) | Roles, operator workflows, settings, and feedback |
| [Trial operations](docs/module11-trial-operations.md) | HTTPS deployment, secrets, backup/restore, and incident runbooks |
| [Readiness report](docs/module11-readiness-report.md) | Recorded trial assessment and unverified external requirements |
