"""Offline configuration and database gate for the limited Workspace trial."""

import json
import os
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import connection

from core.models import Mailbox, Organization


def assess_trial(*, require_enrollment=False):
    failures = []
    warnings = []
    if settings.DEBUG:
        failures.append("debug_enabled")
    if not settings.SECURE_SSL_REDIRECT:
        failures.append("https_redirect_disabled")
    if settings.SECURE_PROXY_SSL_HEADER != ("HTTP_X_FORWARDED_PROTO", "https"):
        failures.append("trusted_https_proxy_not_configured")
    if settings.SECURE_HSTS_SECONDS < 3600:
        warnings.append("hsts_below_one_hour")
    if not settings.SESSION_COOKIE_SECURE or not settings.CSRF_COOKIE_SECURE:
        failures.append("secure_cookies_disabled")
    if not settings.CSRF_TRUSTED_ORIGINS or any(not x.startswith("https://") for x in settings.CSRF_TRUSTED_ORIGINS):
        failures.append("https_csrf_origin_missing")
    if not settings.ALLOWED_HOSTS or any(x in {"*", "localhost", "127.0.0.1"} for x in settings.ALLOWED_HOSTS):
        failures.append("public_allowed_hosts_invalid")
    if not settings.ARTIFACT_RETENTION_ENABLED:
        warnings.append("artifact_retention_disabled")
    private_root = Path(settings.PRIVATE_ARTIFACT_ROOT)
    static_root = Path(settings.STATIC_ROOT)
    if private_root == static_root or static_root in private_root.parents:
        failures.append("private_artifacts_under_static_root")
    ingestion = settings.GOOGLE_INGESTION_SERVICE_ACCOUNT_FILE
    if not ingestion or not Path(ingestion).is_file():
        failures.append("ingestion_key_unavailable")
    response = settings.GOOGLE_RESPONSE_SERVICE_ACCOUNT_FILE
    if settings.GMAIL_RESPONSE_ENABLED:
        if not response or not Path(response).is_file():
            failures.append("response_key_unavailable")
        elif ingestion and os.path.realpath(response) == os.path.realpath(ingestion):
            failures.append("response_identity_not_isolated")
    try:
        connection.ensure_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        enrolled = list(Mailbox.objects.filter(
            provider=Mailbox.Provider.GMAIL, state=Mailbox.State.ACTIVE,
            organization__is_active=True,
            organization__gmail_access_verified_at__isnull=False,
        ).exclude(gmail_enrollment_history_id="").values_list(
            "organization__slug", "address", "gmail_sync_status",
        ).order_by("organization__slug", "address"))
        active_organizations = Organization.objects.filter(is_active=True).count()
    except Exception:
        failures.append("database_unavailable")
        enrolled = []
        active_organizations = None
    if require_enrollment and not enrolled:
        failures.append("no_enrolled_mailboxes")
    elif not enrolled:
        warnings.append("no_enrolled_mailboxes")
    for _, _, status in enrolled:
        if status in {Mailbox.GmailSyncStatus.AUTHORIZATION_FAILED, Mailbox.GmailSyncStatus.COVERAGE_GAP}:
            warnings.append("enrolled_mailbox_requires_review")
            break
    return {
        "ready": not failures,
        "failures": sorted(set(failures)), "warnings": sorted(set(warnings)),
        "active_organizations": active_organizations,
        "enrolled_mailboxes": [
            {"organization": org, "mailbox": address, "sync_status": status}
            for org, address, status in enrolled
        ],
        "automatic_response_enabled": settings.GMAIL_RESPONSE_ENABLED,
    }


class Command(BaseCommand):
    help = "Check offline trial configuration, database, and exact enrolled scope."

    def add_arguments(self, parser):
        parser.add_argument("--json", action="store_true")
        parser.add_argument("--require-enrollment", action="store_true")

    def handle(self, *args, **options):
        report = assess_trial(require_enrollment=options["require_enrollment"])
        if options["json"]:
            self.stdout.write(json.dumps(report, sort_keys=True))
        else:
            self.stdout.write(f"Trial configuration: {'ready' if report['ready'] else 'FAILED'}")
            self.stdout.write(f"Failures: {', '.join(report['failures']) or 'none'}")
            self.stdout.write(f"Warnings: {', '.join(report['warnings']) or 'none'}")
            self.stdout.write(f"Enrolled mailboxes: {len(report['enrolled_mailboxes'])}")
            self.stdout.write(f"Automatic response: {'enabled' if report['automatic_response_enabled'] else 'suspended'}")
        if not report["ready"]:
            raise CommandError("Trial readiness checks failed")
