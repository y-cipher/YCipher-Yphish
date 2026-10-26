"""Administrator enrollment of one persisted organizational mailbox."""

import json

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from core.gmail import GmailClient, GmailError
from core.models import Mailbox, Organization


class Command(BaseCommand):
    help = "Verify read-only Workspace delegation and enroll one existing mailbox."

    def add_arguments(self, parser):
        parser.add_argument("--organization", required=True, help="Existing organization slug")
        parser.add_argument("--mailbox", required=True, help="Existing mailbox address")

    def handle(self, *args, **options):
        path = settings.GOOGLE_INGESTION_SERVICE_ACCOUNT_FILE
        if not path:
            raise CommandError("GOOGLE_INGESTION_SERVICE_ACCOUNT_FILE is not configured")
        try:
            with open(path, encoding="utf-8") as stream:
                client_id = str(json.load(stream)["client_id"])
        except (OSError, ValueError, KeyError, TypeError):
            raise CommandError("Ingestion service-account file is unavailable or invalid") from None
        try:
            organization = Organization.objects.get(slug=options["organization"], is_active=True)
            mailbox = Mailbox.objects.get(
                organization=organization, address__iexact=options["mailbox"],
            )
        except (Organization.DoesNotExist, Mailbox.DoesNotExist):
            raise CommandError("Active organization and existing mailbox are required") from None
        if mailbox.address.casefold().endswith("@example.test"):
            raise CommandError("Synthetic development mailboxes cannot be enrolled")
        if (organization.gmail_service_account_client_id
                and organization.gmail_service_account_client_id != client_id):
            raise CommandError("Ingestion client ID differs from this organization's configuration")
        if (mailbox.gmail_enrollment_history_id and mailbox.gmail_enrolled_at
                and mailbox.state == Mailbox.State.ACTIVE):
            if mailbox.gmail_sync_status == Mailbox.GmailSyncStatus.AUTHORIZATION_FAILED:
                try:
                    GmailClient(mailbox.pk)
                except GmailError as exc:
                    raise CommandError(f"Gmail authorization recheck failed: {exc.code}") from None
                Mailbox.objects.filter(pk=mailbox.pk).update(
                    gmail_sync_status=Mailbox.GmailSyncStatus.READY if mailbox.gmail_history_id else Mailbox.GmailSyncStatus.INITIALIZING,
                    last_error_code="", gmail_next_sync_at=None, gmail_retry_count=0,
                )
                self.stdout.write("Authorization reverified; existing boundary and cursor preserved.")
                return
            self.stdout.write("Mailbox is already enrolled; its boundary and cursor were preserved.")
            return
        with transaction.atomic():
            current = Mailbox.objects.select_for_update().get(pk=mailbox.pk)
            organization.gmail_service_account_client_id = client_id
            organization.save(update_fields=["gmail_service_account_client_id", "updated_at"])
            current.provider = Mailbox.Provider.GMAIL
            current.gmail_enrolled_at = timezone.now()
            current.gmail_sync_status = Mailbox.GmailSyncStatus.ENROLLING
            current.state = Mailbox.State.PENDING
            current.last_error_code = ""
            current.save(update_fields=[
                "provider", "gmail_enrolled_at", "gmail_sync_status",
                "state", "last_error_code", "updated_at",
            ])
        try:
            client = GmailClient(mailbox.pk)
            profile = getattr(client, "verified_profile", None) or client.profile()
            if profile.get("emailAddress", "").casefold() != mailbox.address.casefold():
                raise GmailError("gmail_impersonated_mailbox_mismatch")
            boundary = profile.get("historyId")
            if not isinstance(boundary, str) or not boundary:
                raise GmailError("gmail_history_cursor_missing")
        except GmailError as exc:
            Mailbox.objects.filter(pk=mailbox.pk).update(
                gmail_sync_status=Mailbox.GmailSyncStatus.ERROR,
                state=Mailbox.State.ERROR, last_error_code=exc.code,
            )
            raise CommandError(f"Gmail enrollment failed: {exc.code}") from None
        with transaction.atomic():
            current = Mailbox.objects.select_for_update().get(pk=mailbox.pk)
            if current.gmail_sync_status != Mailbox.GmailSyncStatus.ENROLLING:
                raise CommandError("Mailbox enrollment state changed; retry enrollment")
            current.gmail_enrollment_history_id = boundary
            current.gmail_history_id = ""
            current.gmail_sync_status = Mailbox.GmailSyncStatus.INITIALIZING
            current.state = Mailbox.State.ACTIVE
            current.last_error_code = ""
            current.save(update_fields=[
                "gmail_enrollment_history_id", "gmail_history_id",
                "gmail_sync_status", "state", "last_error_code", "updated_at",
            ])
            organization.gmail_access_verified_at = timezone.now()
            organization.save(update_fields=["gmail_access_verified_at", "updated_at"])
        self.stdout.write(self.style.SUCCESS(
            "Gmail mailbox enrolled with a read-only delegated identity. Initial synchronization is pending."
        ))
