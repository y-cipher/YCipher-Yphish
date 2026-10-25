"""One-time administrator enrollment, distinct from dashboard authentication."""

import json

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from core.gmail import GmailClient, GmailError
from core.gmail_runtime import ingest_message
from core.models import Mailbox, Organization


class Command(BaseCommand):
    help = "Verify Workspace delegation and enroll a Gmail mailbox without storing credentials."

    def add_arguments(self, parser):
        parser.add_argument("--organization", required=True, help="Existing organization slug")
        parser.add_argument("--mailbox", required=True, help="Existing mailbox address")
        parser.add_argument("--label", default="Yphish/Investigate", help="User label for response actions")
        parser.add_argument("--backfill", action="store_true", help="Ingest existing messages before normal history polling")

    def handle(self, *args, **options):
        if not settings.GOOGLE_SERVICE_ACCOUNT_FILE:
            raise CommandError("GOOGLE_SERVICE_ACCOUNT_FILE is not configured")
        try:
            with open(settings.GOOGLE_SERVICE_ACCOUNT_FILE, encoding="utf-8") as stream:
                client_id = str(json.load(stream)["client_id"])
        except (OSError, ValueError, KeyError, TypeError):
            raise CommandError("Service account file is unavailable or invalid") from None
        try:
            organization = Organization.objects.get(slug=options["organization"], is_active=True)
            mailbox = Mailbox.objects.get(organization=organization, address__iexact=options["mailbox"])
        except (Organization.DoesNotExist, Mailbox.DoesNotExist):
            raise CommandError("Active organization and existing mailbox are required") from None
        if organization.gmail_service_account_client_id and organization.gmail_service_account_client_id != client_id:
            raise CommandError("Service account client ID differs from this organization's authorization")
        previous_cursor = mailbox.gmail_history_id if mailbox.provider == Mailbox.Provider.GMAIL else ""
        mailbox.provider = Mailbox.Provider.GMAIL
        try:
            client = GmailClient(mailbox.address)
            profile = client.profile()
            if profile.get("emailAddress", "").casefold() != mailbox.address.casefold():
                raise CommandError("Delegated Gmail profile does not match the mailbox")
            label_id = client.ensure_label(options["label"])
            cursor = previous_cursor or client.profile()["historyId"]
            if options["backfill"]:
                for item in client.list_messages():
                    try:
                        ingest_message(mailbox, item["id"], client=client)
                    except GmailError as exc:
                        if exc.code != "gmail_http_404":
                            raise
        except GmailError as exc:
            raise CommandError(f"Gmail enrollment failed: {exc.code}") from None
        with transaction.atomic():
            organization.gmail_service_account_client_id = client_id
            organization.gmail_access_verified_at = timezone.now()
            organization.save(update_fields=["gmail_service_account_client_id", "gmail_access_verified_at", "updated_at"])
            mailbox.provider = Mailbox.Provider.GMAIL
            mailbox.state = Mailbox.State.ACTIVE
            mailbox.gmail_history_id = cursor
            mailbox.gmail_label_id = label_id
            mailbox.last_error_code = ""
            mailbox.save(update_fields=["provider", "state", "gmail_history_id", "gmail_label_id", "last_error_code", "updated_at"])
        self.stdout.write(self.style.SUCCESS("Gmail mailbox enrolled and delegated access verified."))
