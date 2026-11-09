# YCipher Yphish

Yphish is a Django application for reviewing Gmail message evidence and, when an administrator has explicitly configured it, applying a limited automatic response to individual messages.

This repository is useful for local development and controlled evaluation. It is **not presented as a certified production security product**. Read the readiness notes below before connecting mailboxes or enabling automatic response.

## Readiness and transparency

| Area | Current position |
| --- | --- |
| Local application | Docker Compose runs Django, PostgreSQL, RabbitMQ, a Celery worker, and the scheduler. |
| Local examples | Synthetic cases can populate the dashboard without contacting Gmail or using real message content. |
| Automated checks | PostgreSQL-backed tests cover application behavior with synthetic data and mocked Google calls. Run the checks in this README for the current checkout. |
| Live Gmail | Requires a Google Workspace mailbox and administrator-approved domain-wide delegation. This checkout has no verified live Gmail access. |
| Personal Gmail | Personal `@gmail.com` OAuth enrollment is not implemented. If you do not have a Workspace administrator, use the local synthetic examples; this version cannot connect your personal mailbox. |
| Deployment | An HTTPS trial configuration and runbooks are included. A successful local test or Django deployment check does not verify an actual host, TLS, Google authorization, or detection quality. |
| Automatic response | The configured operation labels a qualifying message and may remove it from `INBOX`. It is not secure quarantine, deletion, or pre-delivery protection. Keep it disabled until the real authorization and recovery checks are complete. |

Yphish keeps dashboard sign-in separate from Gmail permission. An application's enrolled-mailbox allowlist is checked before Gmail access, but **does not narrow the identities that the underlying Google domain-wide delegation grant could impersonate**. Protect delegated credentials as powerful organization credentials.

No live Gmail behavior, external security assessment, OAuth verification, or phishing detection benchmark is claimed here. The [readiness report](docs/module11-readiness-report.md) and [trial operations guide](docs/module11-trial-operations.md) record checks and open requirements; review their assessment dates before relying on them.

## What Yphish does

- Polls enrolled Workspace mailboxes and keeps Gmail message IDs distinct from conversation thread IDs.
- Stores original message artifacts privately and builds structured, versioned evidence from parsed messages and Gmail metadata.
- Runs deterministic detection rules; an optional TF-IDF/logistic-regression model can be used with an explicitly authorized dataset and a compatible signed artifact.
- Runs bounded investigation steps using approved local indicators, optional DNS, and explicitly enabled historical context.
- Presents organization-scoped cases, evidence, processing health, and action history in a Django/Bootstrap dashboard.
- Can apply the configured Yphish label to a qualifying individual message and optionally remove `INBOX`. It preserves unrelated labels and records restoration history.

Gmail labels and inbox placement are contextual information, not Yphish verdicts or phishing ground truth. An unavailable model, empty indicator cache, incomplete analysis, or missing evidence is shown as a limitation; none means a message is safe.

## Technology

| Concern | Stack |
| --- | --- |
| Web application | Python 3.12, Django 5.2 LTS, Bootstrap 5 |
| Database | PostgreSQL 16, Django ORM and migrations |
| Background work | Celery, RabbitMQ, Celery Beat |
| Mail access | Gmail API, Google Auth, Google API Python Client |
| Detection | MIME parsing, deterministic rules, optional scikit-learn TF-IDF and logistic regression |
| Local environment | Docker Compose |
| HTTPS trial profile | Gunicorn, WhiteNoise, Caddy |

## Run locally

The commands below use PowerShell from the repository root. Docker Compose supplies Python, PostgreSQL, and RabbitMQ.

### Prerequisites

- Git and Docker Desktop with its Linux engine running (or Docker Engine and Docker Compose v2.20 or newer).
- On Windows, Docker Desktop with WSL 2 is the recommended setup.

Check that Docker's client and server are both available:

```powershell
docker version
docker compose version
```

### Configure and start

If you already have the repository at `D:\Open Source Contributions\Yphish`, open that directory. Otherwise clone it:

```powershell
git clone https://github.com/y-cipher/YCipher-Yphish.git Yphish
Set-Location Yphish
```

Create `.env` only if it does not already exist; keep existing working database settings intact:

```powershell
if (-not (Test-Path -LiteralPath ".env")) {
    Copy-Item -LiteralPath ".env.example" -Destination ".env"
}
notepad .env
```

For local development, set distinct values for `DJANGO_SECRET_KEY`, `DATABASE_PASSWORD`, and `RABBITMQ_PASSWORD`. Keep `.env` and Google credential files private and out of Git. The example is for local development, not for internet-facing deployment.

Start the full application:

```powershell
docker compose config --quiet
docker compose up --build -d --wait --wait-timeout 180
docker compose ps
```

Check Django and the health endpoint:

```powershell
docker compose exec web python manage.py check
Invoke-RestMethod -Uri "http://localhost:8000/health/" -TimeoutSec 10
```

Open the [Yphish dashboard](http://localhost:8000/dashboard/). The stack includes:

| Service | Purpose |
| --- | --- |
| `db` | PostgreSQL database |
| `rabbitmq` | Background-task broker |
| `web` | Django dashboard, admin, and commands |
| `worker` | Synchronization, analysis, investigation, and response tasks |
| `beat` | Scheduled polling and recovery |

The health endpoint checks that the web process responds. It does not confirm worker health, Gmail authorization, or detection performance.

### Load local dashboard examples

Create the repeatable development organization and sample cases, then set a password for the local account:

```powershell
docker compose exec web python manage.py bootstrap_dev --with-demo-emails
docker compose exec web python manage.py changepassword demo_owner
```

Sign in at [http://localhost:8000/dashboard/](http://localhost:8000/dashboard/) as `demo_owner` with the password you just chose. The examples use reserved `example.test` sender addresses and synthetic metadata. They were **not received from Gmail** and contain no real message body or original MIME. This command does not enroll or contact a mailbox. It requires `DJANGO_DEBUG=1`.

The bootstrap command is repeatable. To create the organization and mailboxes without the six example cases, run `bootstrap_dev --with-sample-cases` instead.

## Check the current checkout

Run the PostgreSQL-backed application suite inside the Compose environment:

```powershell
docker compose exec web python manage.py makemigrations --check --dry-run
docker compose exec web python manage.py test core --noinput
```

The suite should end with `OK`. Tests use synthetic data and mock calls to Google. They do not log in to a Workspace account, establish that Gmail scopes were granted, or measure real-world phishing precision and recall. SQLite is not a supported substitute for PostgreSQL because the application uses PostgreSQL-specific constraints and triggers.

For CI workflow details and local release checks, see [CI and release setup](CI_CD.md). To check background service status while running Compose:

```powershell
docker compose ps
docker compose exec worker celery -A config inspect ping
docker compose exec worker python manage.py gmail_health --json
```

## Connect Google Workspace Gmail

This path requires a Workspace domain and a Workspace administrator. It is not available for a personal Gmail account without an administrator-managed grant.

1. Follow [Gmail setup](docs/gmail.md) to create the Google Cloud project, enable Gmail API, configure a service account, and enroll a specific Workspace mailbox.
2. Grant the ingestion service account only this domain-wide delegation scope:

   ```text
   https://www.googleapis.com/auth/gmail.readonly
   ```

3. Store the service-account key outside Git at `secrets/google-service-account.json`. Do not paste credentials or tokens into `.env`, source files, screenshots, or logs.
4. Create the organization, membership, and exact primary mailbox address in Django admin. Enroll that mailbox and run the initial synchronization:

   ```powershell
   docker compose exec web python manage.py enroll_gmail_mailbox --organization YOUR_SLUG --mailbox user@your-workspace-domain
   docker compose exec web python manage.py sync_gmail_mailbox --organization YOUR_SLUG --mailbox user@your-workspace-domain
   docker compose exec worker python manage.py gmail_health --json
   ```

Initial synchronization records existing mail as a historical baseline. New messages arriving during initialization are reconciled using Gmail history. Cases are identified by organization, mailbox, and individual Gmail message ID; a Gmail thread ID only supplies conversation context. See the [Gmail guide](docs/gmail.md) for cursor recovery, access boundaries, and live checks.

### Automatic response

Response uses a separate credential identity from ingestion. It is disabled in the HTTPS trial example and requires administrator-managed scopes, organization and mailbox configuration, and qualifying evidence. Follow the [response guide](docs/module9-response.md) before enabling it. The documented operation is message-level labeling and optional `INBOX` removal; it does not prevent delivery or make the message inaccessible to the user.

Do not enable response against demo cases or assume an automated action is safe because a model scored a message highly. The configured policy and documented evidence requirements govern eligibility.

## Settings and data handling

The local environment template is [.env.example](.env.example); the HTTPS trial template is [.env.trial.example](.env.trial.example). Key settings include:

| Setting | Use |
| --- | --- |
| `DJANGO_SECRET_KEY` | Django signing and sessions |
| `DATABASE_PASSWORD` | PostgreSQL authentication |
| `RABBITMQ_PASSWORD` | RabbitMQ authentication |
| `DJANGO_DEBUG` | Local development behavior; disable for deployment |
| `DJANGO_ALLOWED_HOSTS` | Accepted hostnames |
| `GMAIL_POLL_INTERVAL_SECONDS` | Gmail polling schedule |
| `GMAIL_RESPONSE_*` | Automatic response switch, limits, and circuit breaker |
| `CLASSIFIER_*` | Optional model selection, authorization, and artifact verification |
| `PRIVATE_ARTIFACT_ROOT` | Private storage for original/derived artifacts |

Full variable descriptions and operational advice are in the [trial operations guide](docs/module11-trial-operations.md).

Yphish keeps original MIME in private artifact storage and does not write raw message content or credentials to logs. Back up the database and private artifact volume together. Mailbox data is not automatically selected for model training; Gmail `SPAM` labels are not training truth. Establish retention and backup policies before a live trial.

## Readiness before a live trial

Treat a live deployment as unready until its own operator has completed and recorded these checks:

- A Workspace administrator has approved the exact delegated identity, scopes, and specific mailbox list.
- Credential files are isolated, access-controlled, and covered by a rotation and revocation procedure.
- OAuth verification and restricted-data handling requirements have been assessed for the actual internal or external distribution model.
- HTTPS, Django deployment settings, private artifact storage, backups, retention, monitoring, and restore procedures have been verified on the chosen host.
- Live polling, cursor recovery, authorization failure, provider throttling, message-level action, restoration conflicts, response limits, and suspension have been exercised with a dedicated test mailbox.
- Automatic response remains disabled until the responsible administrator explicitly approves it after reviewing those results.

Local tests and health checks are useful evidence about code paths and service availability. They are not evidence that the checks above have passed. The [readiness report](docs/module11-readiness-report.md) lists the recorded local checks and unresolved live gates; re-run and update checks when the deployment changes.

## Everyday commands

| Task | Command |
| --- | --- |
| Start existing services | `docker compose up -d --wait --wait-timeout 180` |
| Rebuild after code or dependency changes | `docker compose up --build -d --wait --wait-timeout 180` |
| Show service status | `docker compose ps` |
| View recent logs | `docker compose logs -f --tail=100 web worker beat` |
| Check migrations | `docker compose exec web python manage.py showmigrations core` |
| Stop services and keep named-volume data | `docker compose down` |

Source files are copied into the image, not mounted for live reload. Rebuild after changing Python, templates, CSS, or JavaScript. `docker compose down` preserves named volumes; `docker compose down -v` deletes them and their data.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Docker cannot connect to `dockerDesktopLinuxEngine` | Start Docker Desktop's Linux engine and confirm `docker version` shows both Client and Server. |
| A service does not become healthy | Inspect `docker compose ps` and `docker compose logs --tail=100 web db rabbitmq worker beat`. |
| Code changes do not appear | Rebuild with `docker compose up --build -d --wait --wait-timeout 180`, then refresh the browser. |
| `demo_owner` cannot sign in | Run `docker compose exec web python manage.py changepassword demo_owner`. |
| Django says a database password is missing | Check `.env` has `DATABASE_PASSWORD`, then validate with `docker compose config --quiet`. Never post the value publicly. |
| Health works but no cases arrive | Check enrollment, worker and scheduler status with `gmail_health --json`; health alone only checks the web process. |
| Gmail authorization fails | Confirm Workspace admin approval, numeric delegated client ID, exact scope, key path, and exact primary mailbox address. |
| A model or indicator source is unavailable | Inspect case coverage and configure an approved artifact or current indicator snapshot. Unavailability does not mean the message is safe. |

For synchronization gaps, authorization recovery, incorrect labels, restoration conflicts, and response suspension, follow the [trial runbooks](docs/module11-trial-operations.md).

## HTTPS trial deployment

The base Compose file is for local development. The separate trial overlay adds Gunicorn, WhiteNoise, and Caddy HTTPS. Use it only after selecting and securing a host and reviewing the [trial operations guide](docs/module11-trial-operations.md). Its example configuration starts with automatic response disabled.

On the configured trial host, validate the composed settings and readiness:

```powershell
docker compose -f compose.yaml -f compose.trial.yaml config --quiet
docker compose -f compose.yaml -f compose.trial.yaml up --build -d --wait --wait-timeout 180
docker compose -f compose.yaml -f compose.trial.yaml exec web python manage.py check --deploy
docker compose -f compose.yaml -f compose.trial.yaml exec worker python manage.py trial_readiness --json --require-enrollment
docker compose -f compose.yaml -f compose.trial.yaml exec worker python manage.py gmail_health --json
```

These commands check configuration and application state; they do not independently verify public DNS, a real TLS handshake, Google authorization, backup recovery, or detection performance.

## Contributing

Contributions and clear issue reports are welcome. Before opening a pull request, describe the behavior changed, keep organization boundaries and data privacy intact, and run the PostgreSQL-backed checks above. For an issue, include reproducible steps and sanitized logs; **never attach real email content, access tokens, service-account keys, or production database data**.

There is currently no top-level `LICENSE` file, so the repository does not yet state terms for reuse or redistribution. Confirm licensing with the maintainers before treating it as an open-source release.

See [CI and release setup](CI_CD.md) for the current workflow and branch guidance. CI passing does not mean a change was tested against live Gmail.

## Guides

| Guide | What it covers |
| --- | --- |
| [Data model](docs/data-model.md) | Records, constraints, identity, and write-service contracts |
| [Gmail setup](docs/gmail.md) | Workspace authorization, mailbox enrollment, polling, and cursor recovery |
| [Background processing](docs/module5-operations.md) | Queues, retries, worker recovery, and health |
| [Detection and evidence](docs/module6-detection.md) | Rules, coverage, and indicator snapshots |
| [Model training](docs/module7-classifier.md) | Dataset selection, leakage controls, evaluation, and model artifacts |
| [Investigation](docs/module8-investigation.md) | Approved lookups, context, limits, and stopping behavior |
| [Automatic response](docs/module9-response.md) | Labeling, inbox removal, idempotency, and restoration |
| [Dashboard](docs/module10-dashboard.md) | Roles, case review, settings, and feedback |
| [Trial operations](docs/module11-trial-operations.md) | Deployment, secrets, backup, monitoring, and incident runbooks |
| [Readiness report](docs/module11-readiness-report.md) | Recorded checks and outstanding live requirements |
| [CI and releases](CI_CD.md) | Automated checks and release workflow |
