"""Queue rule evaluation for already-ingested Gmail cases without actions."""

from django.core.management.base import BaseCommand, CommandError

from core.analysis_runtime import ensure_rule_backfill_run
from core.models import Artifact, EmailCase, Mailbox, Organization


class Command(BaseCommand):
    help = "Queue deterministic rules for existing Gmail cases; does not publish response actions."

    def add_arguments(self, parser):
        parser.add_argument("--organization", required=True, help="Existing organization slug")
        parser.add_argument("--limit", type=int, default=100)
        parser.add_argument("--include-historical", action="store_true")

    def handle(self, *args, **options):
        if not 1 <= options["limit"] <= 10000:
            raise CommandError("--limit must be between 1 and 10000")
        try:
            organization = Organization.objects.get(slug=options["organization"], is_active=True)
        except Organization.DoesNotExist:
            raise CommandError("Active organization not found") from None
        cases = EmailCase.objects.filter(
            organization=organization, mailbox__provider=Mailbox.Provider.GMAIL,
            artifacts__kind=Artifact.Kind.ORIGINAL_MIME,
            artifacts__state=Artifact.State.STORED,
        ).exclude(gmail_message_id="").distinct().order_by("created_at")
        if not options["include_historical"]:
            cases = cases.filter(gmail_is_historical=False)
        created = 0
        for case in cases[:options["limit"]]:
            _run, added = ensure_rule_backfill_run(case)
            created += int(added)
        self.stdout.write(f"Queued {created} rule-analysis run(s); Celery reconciliation will dispatch them.")
