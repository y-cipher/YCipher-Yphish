# Yphish CI and release setup

Adapted for Yphish from the supplied YCipher CI/release guide. This repository is a Django application with PostgreSQL, Celery/RabbitMQ, Gmail services, and a Bootstrap dashboard. Website, Node, Next.js, SQLite, and Alembic instructions from the reference do not apply here.

## What is configured

`.github/workflows/ci.yml` runs on pull requests targeting `master`, `main`, or `develop`, pushes to those branches, and manual dispatch. There are no path filters. A new revision cancels the older run for that PR/ref. The final job is uniquely named **CI required**, runs even when a dependency fails, and requires every test matrix job, image check, and audit to succeed. Failed, cancelled, or skipped work cannot produce a passing final check. No automatic merge or deployment is configured.

- Python 3.12 with disposable PostgreSQL 16 and 17: migrate an empty database, check pending migrations/model drift, run Django checks, and run the complete `core` suite. The suite covers tenant boundaries, Gmail ingestion/history recovery, analysis, classifier, investigation, response/restoration, dashboard roles, and operational checks using synthetic data and mocked provider calls. It does not contact real Gmail.
- Secure Django deployment checks: all warnings fail except the two documented trial exceptions for HSTS subdomains/preload. `config.ci_deploy_settings` is only used by this check; normal production settings are unchanged.
- Build the Docker image, validate trial Compose, collect static assets as the application user, and smoke-test Gunicorn's `/health/` endpoint. This is liveness only; it does not verify a database, broker, TLS certificate, or Workspace authorization.
- Audit the resolved application requirements using `pip-audit --strict`. A vulnerability or an audit service/resolution failure blocks CI. Review the dependency and fix it; do not silently suppress the check.

Official checkout/setup actions are pinned to commit revisions, token permissions are read-only, checkout credentials are not persisted, and no repository/environment secrets are requested. Pull requests use the normal `pull_request` event and GitHub's proposed merge revision. Tests run on disposable hosted runners, not on a production database. Dependabot proposes weekly Python, Dockerfile, and Actions updates against the repository's default branch. It becomes active once its configuration is present there. Dependency ranges are currently resolved at run time; this setup does not claim identical dependency versions across different runs.

No new browser automation suite, application-wide lint baseline, deployment credentials, or hosting resources are supplied by this change. Existing dashboard tests exercise Django views/forms/permissions. Test output is in Actions job logs; database dumps, MIME, key files, and browser session traces are not uploaded.

## Activate it on GitHub

At setup time, the local checkout was `master`; local remote references included `main` and `master`, with `origin/HEAD` pointing to `main`. These are local observations, not proof of current GitHub settings. No branches have been renamed or force-pushed. Review the repository's branch history before deciding whether `main` or `master` is the release branch.

1. Review and commit the CI files on a feature branch, push it, and open a PR into the branch holding the current Yphish code (currently local `master`). For example, from this directory:

   ```powershell
   git switch -c codex/yphish-ci
   git add .github CI_CD.md config/ci_deploy_settings.py requirements-ci.txt .dockerignore README.md
   git diff --cached
   git commit -m "ci: add Yphish PostgreSQL checks and release guidance"
   git push -u origin codex/yphish-ci
   ```

2. In GitHub Settings → Actions → General, allow GitHub Actions and the official pinned actions used by this workflow. Keep the default workflow token read-only. No Gmail, Cloud, production database, or hosting secrets are needed. Review any first-time contributor workflow approval prompt.
3. Open the PR's **Checks** tab, wait for **CI required**, and inspect failed job output. A manual Actions button normally requires the workflow on the default branch; the PR trigger can validate it before that. Do not claim success until GitHub has run this revision.
4. After the check is available, protect the release/integration branches in Settings → Branches or Rulesets: require a PR, **CI required**, an up-to-date branch, resolution of review discussions, and no force pushes/deletion. Apply the rules to administrators and avoid bypasses. Require an independent reviewer when one is available. A workflow file alone does not configure branch protection.
5. Check this repository's actual visibility and GitHub plan. The reference document's private-Free limitation belongs to its original repository and must not be assumed here. GitHub documents protected branches for public Free repositories and eligible paid private repositories. If the account cannot enforce the rules, explicitly use manual review/merge discipline or change the plan; CI alone cannot prohibit a red merge. See [GitHub branch protection](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches).

For normal development, branch from the agreed integration branch and open feature PRs back to it. If adopting `develop`, create it from the reviewed release history rather than replacing either existing branch. Release with a PR from `develop` to the selected release branch; use a merge commit to preserve the ancestry of long-lived branches, and synchronize hotfixes back into `develop`. Review and merge manually only when the latest proposed merge passes CI. Do not enable a merge queue without adding and testing a `merge_group` trigger.

## Run the checks locally

Use a dedicated PostgreSQL test instance and a role allowed to create Django's temporary test database. Never point these commands at production. The settings module does not automatically load `.env` for host Python, so export the variables in PowerShell first (replace port/user/password with your disposable test instance):

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt -r requirements-ci.txt
$env:DJANGO_SECRET_KEY='synthetic-local-ci-secret-key-with-sufficient-length-123456789'
$env:DJANGO_DEBUG='1'
$env:DJANGO_ALLOWED_HOSTS='localhost,127.0.0.1,testserver'
$env:DATABASE_NAME='yphish_ci'
$env:DATABASE_USER='yphish_ci'
$env:DATABASE_PASSWORD='disposable-ci-password'
$env:DATABASE_HOST='127.0.0.1'
$env:DATABASE_PORT='5432'
python -m pip check
python manage.py migrate --noinput
python manage.py makemigrations --check --dry-run
python manage.py test core --noinput --verbosity 2
python -m pip_audit -r requirements.txt --strict
```

For secure deployment checks in that same shell:

```powershell
$env:DJANGO_SETTINGS_MODULE='config.ci_deploy_settings'
$env:DJANGO_DEBUG='0'
$env:DJANGO_ALLOWED_HOSTS='trial.example.test'
$env:DJANGO_CSRF_TRUSTED_ORIGINS='https://trial.example.test'
$env:DJANGO_SECURE_SSL_REDIRECT='1'
$env:DJANGO_TRUST_PROXY_HEADERS='1'
$env:DJANGO_HSTS_SECONDS='3600'
python manage.py check --deploy --fail-level WARNING
Remove-Item Env:DJANGO_SETTINGS_MODULE
```

With Docker Desktop's Linux engine running and the existing `.env` configured, validate/build locally using `docker compose -f compose.yaml -f compose.trial.yaml config --quiet` and `docker build -t yphish:ci .`. Do not overwrite a real `.env` with CI values. The workflow copies the example only inside a fresh disposable runner. Docker's build context excludes private artifacts, credentials, local PostgreSQL data, test output, and backup dumps.

## Deployment follows hosting selection

CI verifies code; the trial Compose profile is a deployment configuration, not an automatic deployment. Follow [Module 11 operations](docs/module11-trial-operations.md) for administrator authorization and trial setup. When a hosting target is confirmed, add separate staging and production environments, protected deployment credentials, serialized releases, an exact tested image digest/commit, staging checks, health verification, and an application rollback procedure. Test database restore separately and preserve compatible migration history. Keep Gmail test identities, databases, storage, and secrets isolated from production; never run destructive regression tests on live mailbox data.

## Local validation 

Workflow/Dependabot YAML parsed; trial Compose validation and the strict Django deployment check passed. The dependency audit found no known vulnerabilities in its resolved requirements. All 126 tests passed against a disposable local PostgreSQL 17 instance, and no model/migration drift was detected. The Docker Linux engine was unavailable locally, so PostgreSQL 16, the Docker build/smoke test, and the actual GitHub Actions run remain unverified until the workflow runs on GitHub. Repository settings, branches, and remote protections have not been changed by this setup.
