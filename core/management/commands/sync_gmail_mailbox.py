"""Run a single enrolled mailbox synchronization without Celery."""

from django.core.management.base import BaseCommand, CommandError

from core.gmail import GmailError
from core.gmail_runtime import sync_mailbox
from core.models import Mailbox, Organization


class Command(BaseCommand):
    help = "Run initial or incremental read-only Gmail synchronization for one enrolled mailbox."

    def add_arguments(self, parser):
        parser.add_argument("--organization", required=True)
        parser.add_argument("--mailbox", required=True)

    def handle(self, *args, **options):
        try:
            organization = Organization.objects.get(slug=options["organization"], is_active=True)
            mailbox = Mailbox.objects.get(organization=organization, address__iexact=options["mailbox"])
        except (Organization.DoesNotExist, Mailbox.DoesNotExist):
            raise CommandError("Active organization and existing mailbox are required") from None
        if not mailbox.gmail_enrollment_history_id or mailbox.state != Mailbox.State.ACTIVE:
            raise CommandError("Mailbox is not actively enrolled for Gmail")
        try:
            count = sync_mailbox(mailbox.pk)
        except GmailError as exc:
            mailbox.refresh_from_db(fields=["gmail_sync_status"])
            updates = {"last_error_code": exc.code}
            if mailbox.gmail_sync_status != Mailbox.GmailSyncStatus.COVERAGE_GAP:
                updates["gmail_sync_status"] = Mailbox.GmailSyncStatus.ERROR
            Mailbox.objects.filter(pk=mailbox.pk).update(**updates)
            raise CommandError(f"Gmail synchronization failed: {exc.code}") from None
        mailbox.refresh_from_db()
        self.stdout.write(self.style.SUCCESS(
            f"Synchronized {count} message event(s); status={mailbox.gmail_sync_status}; "
            f"completed_cursor={mailbox.gmail_history_id}."
        ))
        if mailbox.gmail_coverage_gap_detected_at:
            self.stdout.write(self.style.WARNING(
                "Coverage gap remains recorded; messages that existed only during the expired interval may be unavailable."
            ))
