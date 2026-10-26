import base64
import json
import os
import tempfile
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import DatabaseError, transaction
from django.test import TestCase, TransactionTestCase, override_settings
from django.utils import timezone
from googleapiclient.errors import HttpError
from httplib2 import Response

from .gmail import GmailClient, GmailError, GmailHistoryExpired
from .gmail_credentials import (
    ADMIN_RESPONSE_SCOPE, INGESTION_SCOPE, LABELS_SCOPE, CredentialProviderError,
    CredentialPurpose, WorkspaceDelegatedCredentialProvider,
)
from .gmail_runtime import ingest_message, sync_mailbox
from .models import Artifact, AuditEvent, EmailCase, Evidence, Mailbox, Organization
from .services import create_email_case


RAW = b"From: sender@example.test\r\nTo: inbox@example.test\r\nSubject: Test\r\nMessage-ID: <synthetic@example.test>\r\n\r\nsynthetic body"


class FakeGmail:
    def __init__(self, *, pages=None, events=None, profile_cursor="900"):
        self.pages = pages if pages is not None else [["baseline"]]
        self.events = events if events is not None else {}
        self.profile_cursor = profile_cursor
        self.history_calls = []

    def profile(self):
        return {"emailAddress": "inbox@example.test", "historyId": self.profile_cursor}

    def list_messages(self):
        for page in self.pages:
            for message_id in page:
                yield {"id": message_id, "threadId": "shared-thread"}

    def history_messages(self, cursor):
        self.history_calls.append(cursor)
        entries = self.events.get(cursor, [])
        if entries == "expired":
            raise GmailHistoryExpired()
        for message_id, kind in entries:
            yield message_id, kind
        yield None, f"{cursor}-completed"

    def get_raw_message(self, message_id):
        return {
            "id": message_id,
            "threadId": "shared-thread",
            "labelIds": ["INBOX", "Label_42"],
            "internalDate": "1700000000123",
        }, RAW

    def get_message_metadata(self, message_id):
        return {"id": message_id, "threadId": "shared-thread", "labelIds": ["INBOX", "Label_42"]}


class Request:
    def __init__(self, result):
        self.result = result

    def execute(self, **kwargs):
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class Service:
    def __init__(self, *, message_pages=None, history_pages=None, raw=None):
        self.message_pages = message_pages or []
        self.history_pages = history_pages or []
        self.raw = raw
        self.resource = ""

    def users(self):
        return self

    def messages(self):
        self.resource = "messages"
        return self

    def history(self):
        self.resource = "history"
        return self

    def getProfile(self, **kwargs):
        return Request({"emailAddress": "inbox@example.test", "historyId": "101"})

    def list(self, **kwargs):
        pages = self.history_pages if self.resource == "history" else self.message_pages
        page = 1 if kwargs.get("pageToken") else 0
        return Request(pages[page])

    def get(self, **kwargs):
        return Request(self.raw)


class Provider:
    def __init__(self):
        self.calls = []

    def for_mailbox(self, mailbox_id, purpose):
        self.calls.append((mailbox_id, purpose))
        return object()


class GmailClientTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(
            slug="client-tests", name="Client", gmail_service_account_client_id="client-1",
            gmail_access_verified_at=timezone.now(),
        )
        self.mailbox = Mailbox.objects.create(
            organization=self.org, address="inbox@example.test",
            state=Mailbox.State.ACTIVE, gmail_enrolled_at=timezone.now(),
            gmail_enrollment_history_id="100", gmail_sync_status=Mailbox.GmailSyncStatus.READY,
        )

    def test_google_client_paginates_and_decodes_raw_base64url(self):
        payload = RAW + b"\xfb\xff"
        encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
        service = Service(
            message_pages=[
                {"messages": [{"id": "A"}], "nextPageToken": "next"},
                {"messages": [{"id": "B"}]},
            ],
            history_pages=[
                {"history": [{"messagesAdded": [{"message": {"id": "A"}}]}], "nextPageToken": "next"},
                {"history": [{"labelsAdded": [{"message": {"id": "B"}}]}], "historyId": "9001"},
            ],
            raw={"id": "A", "raw": encoded},
        )
        provider = Provider()
        client = GmailClient(self.mailbox.pk, credential_provider=provider, service=service)
        self.assertEqual([item["id"] for item in client.list_messages()], ["A", "B"])
        self.assertEqual(list(client.history_messages("100")), [
            ("A", "added"), ("B", "labels"), (None, "9001"),
        ])
        self.assertEqual(client.get_raw_message("A")[1], payload)
        self.assertEqual(provider.calls, [(self.mailbox.pk, CredentialPurpose.INGESTION)])

    def test_operation_rechecks_enrollment(self):
        client = GmailClient(self.mailbox.pk, credential_provider=Provider(), service=Service())
        Mailbox.objects.filter(pk=self.mailbox.pk).update(state=Mailbox.State.PAUSED)
        with self.assertRaises(GmailError) as caught:
            client.profile()
        self.assertEqual(caught.exception.code, "gmail_mailbox_not_enrolled")

    def test_history_404_is_explicit(self):
        error = HttpError(Response({"status": 404}), b"expired")
        service = Service(history_pages=[error])
        client = GmailClient(self.mailbox.pk, credential_provider=Provider(), service=service)
        with self.assertRaises(GmailHistoryExpired):
            list(client.history_messages("100"))

    def test_credentials_reject_unenrolled_and_invalid_response_scope(self):
        pending = Mailbox.objects.create(organization=self.org, address="other@example.test")
        with self.assertRaises(CredentialProviderError):
            WorkspaceDelegatedCredentialProvider().for_mailbox(
                pending.pk, CredentialPurpose.INGESTION,
            )
        self.org.gmail_response_scope = "https://www.googleapis.com/auth/gmail.modify"
        self.org.gmail_response_enabled = True
        self.org.gmail_response_service_account_client_id = "response-client"
        self.org.save(update_fields=["gmail_response_scope", "gmail_response_enabled", "gmail_response_service_account_client_id"])
        self.mailbox.gmail_response_enabled = True
        self.mailbox.save(update_fields=["gmail_response_enabled"])
        with self.assertRaises(CredentialProviderError) as caught:
            WorkspaceDelegatedCredentialProvider().for_mailbox(
                self.mailbox.pk, CredentialPurpose.RESPONSE,
            )
        self.assertEqual(caught.exception.code, "gmail_response_scope_invalid")

    def test_ingestion_identity_uses_only_readonly_scope_and_stored_subject(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".json", delete=False) as stream:
            json.dump({"client_id": "client-1"}, stream)
            path = stream.name
        class Credentials:
            subject = None
            def with_subject(self, subject):
                self.subject = subject
                return self
        values = []
        def from_info(info, *, scopes):
            values.append(scopes)
            return Credentials()
        try:
            with override_settings(GOOGLE_INGESTION_SERVICE_ACCOUNT_FILE=path), patch(
                "core.gmail_credentials.service_account.Credentials.from_service_account_info",
                side_effect=from_info,
            ):
                credentials = WorkspaceDelegatedCredentialProvider().for_mailbox(
                    self.mailbox.pk, CredentialPurpose.INGESTION,
                )
        finally:
            os.unlink(path)
        self.assertEqual(values, [[INGESTION_SCOPE]])
        self.assertEqual(credentials.subject, self.mailbox.address)
        self.assertNotEqual(INGESTION_SCOPE, ADMIN_RESPONSE_SCOPE)

    def test_response_identity_requires_separate_key_and_exact_scopes(self):
        self.org.gmail_response_scope = ADMIN_RESPONSE_SCOPE
        self.org.gmail_response_labels_scope = LABELS_SCOPE
        self.org.gmail_response_enabled = True
        self.org.gmail_response_service_account_client_id = "response-client"
        self.org.save(update_fields=["gmail_response_scope", "gmail_response_labels_scope", "gmail_response_enabled", "gmail_response_service_account_client_id"])
        self.mailbox.gmail_response_enabled = True
        self.mailbox.save(update_fields=["gmail_response_enabled"])
        with tempfile.TemporaryDirectory() as directory:
            ingestion_path = os.path.join(directory, "ingestion.json")
            response_path = os.path.join(directory, "response.json")
            with open(response_path, "w", encoding="utf-8") as stream:
                json.dump({"client_id": "response-client"}, stream)
            class Credentials:
                def with_subject(self, subject):
                    self.subject = subject
                    return self
            requested = []
            def from_info(info, *, scopes):
                requested.append(scopes)
                return Credentials()
            with override_settings(
                GOOGLE_INGESTION_SERVICE_ACCOUNT_FILE=ingestion_path,
                GOOGLE_RESPONSE_SERVICE_ACCOUNT_FILE=response_path,
            ), patch(
                "core.gmail_credentials.service_account.Credentials.from_service_account_info",
                side_effect=from_info,
            ):
                credentials = WorkspaceDelegatedCredentialProvider().for_mailbox(
                    self.mailbox.pk, CredentialPurpose.RESPONSE,
                )
        self.assertEqual(requested, [[ADMIN_RESPONSE_SCOPE, LABELS_SCOPE]])
        self.assertEqual(credentials.subject, self.mailbox.address)


class GmailSyncTests(TransactionTestCase):
    def setUp(self):
        self.org = Organization.objects.create(
            slug="sync-tests", name="Sync", gmail_service_account_client_id="client-1",
            gmail_access_verified_at=timezone.now(),
        )
        self.mailbox = Mailbox.objects.create(
            organization=self.org, address="inbox@example.test",
            state=Mailbox.State.ACTIVE, gmail_sync_status=Mailbox.GmailSyncStatus.INITIALIZING,
            gmail_enrolled_at=timezone.now(), gmail_enrollment_history_id="100",
        )

    def _private_storage(self, directory):
        return patch.object(Artifact._meta.get_field("file").storage, "_location", directory)

    def test_initial_scan_replays_arrivals_without_retroactive_action(self):
        fake = FakeGmail(
            pages=[["baseline"], ["arrived"]],
            events={"100": [("arrived", "added"), ("baseline", "labels")]},
        )
        with tempfile.TemporaryDirectory() as directory, self._private_storage(directory):
            self.assertEqual(sync_mailbox(self.mailbox.pk, client=fake), 4)
            self.assertEqual(sync_mailbox(self.mailbox.pk, client=fake), 0)
        self.mailbox.refresh_from_db()
        self.assertEqual(self.mailbox.gmail_enrollment_history_id, "100")
        self.assertEqual(self.mailbox.gmail_history_id, "100-completed-completed")
        self.assertEqual(self.mailbox.gmail_sync_status, Mailbox.GmailSyncStatus.READY)
        self.assertIsNotNone(self.mailbox.gmail_initial_sync_completed_at)
        self.assertTrue(EmailCase.objects.get(gmail_message_id="baseline").gmail_is_historical)
        self.assertFalse(EmailCase.objects.get(gmail_message_id="arrived").gmail_is_historical)
        self.assertEqual(EmailCase.objects.count(), 2)
        self.assertEqual(Artifact.objects.filter(state=Artifact.State.STORED).count(), 2)
        self.assertEqual(Evidence.objects.count(), 2)
        self.assertEqual(EmailCase.objects.get(gmail_message_id="arrived").gmail_label_ids, ["INBOX", "Label_42"])
        self.assertEqual(EmailCase.objects.get(gmail_message_id="arrived").gmail_internal_date_ms, "1700000000123")

    def test_failed_history_page_keeps_completed_cursor_while_work_remains_durable(self):
        class Interrupted(FakeGmail):
            def history_messages(self, cursor):
                yield "arrival", "added"
                raise GmailError("gmail_http_503", retryable=True)
        with tempfile.TemporaryDirectory() as directory, self._private_storage(directory):
            with self.assertRaises(GmailError):
                sync_mailbox(self.mailbox.pk, client=Interrupted(pages=[["baseline"]]))
            self.mailbox.refresh_from_db()
            self.assertEqual(self.mailbox.gmail_history_id, "")
            self.assertEqual(EmailCase.objects.count(), 2)
            retry = FakeGmail(pages=[["baseline"]], events={"100": [("arrival", "added")]})
            sync_mailbox(self.mailbox.pk, client=retry)
        self.assertEqual(EmailCase.objects.count(), 2)
        self.assertEqual(self.mailbox.gmail_enrollment_history_id, "100")

    def test_expired_history_resync_exposes_gap_and_preserves_boundary(self):
        self.mailbox.gmail_sync_status = Mailbox.GmailSyncStatus.READY
        self.mailbox.gmail_history_id = "700"
        self.mailbox.save(update_fields=["gmail_sync_status", "gmail_history_id"])
        fake = FakeGmail(
            pages=[["existing"], ["arrival"]],
            events={"700": "expired", "900": [("new-after-anchor", "added")]},
            profile_cursor="900",
        )
        with tempfile.TemporaryDirectory() as directory, self._private_storage(directory):
            sync_mailbox(self.mailbox.pk, client=fake)
        self.mailbox.refresh_from_db()
        self.assertEqual(self.mailbox.gmail_history_id, "900-completed")
        self.assertEqual(self.mailbox.gmail_enrollment_history_id, "100")
        self.assertEqual(self.mailbox.gmail_coverage_gap_from_history_id, "700")
        self.assertEqual(self.mailbox.gmail_sync_status, Mailbox.GmailSyncStatus.COVERAGE_GAP)
        self.assertTrue(EmailCase.objects.get(gmail_message_id="existing").gmail_is_historical)
        self.assertFalse(EmailCase.objects.get(gmail_message_id="new-after-anchor").gmail_is_historical)
        self.assertEqual(AuditEvent.objects.filter(event_type="gmail.coverage_gap").count(), 1)

    def test_case_identity_is_message_not_thread_or_content_hash(self):
        first, _ = create_email_case(
            organization=self.org, mailbox=self.mailbox, gmail_message_id="A", gmail_thread_id="same",
        )
        second, _ = create_email_case(
            organization=self.org, mailbox=self.mailbox, gmail_message_id="B", gmail_thread_id="same",
        )
        self.assertNotEqual(first.pk, second.pk)
        with self.assertRaises(DatabaseError), transaction.atomic():
            EmailCase.objects.create(
                organization=self.org, mailbox=self.mailbox, provider_immutable_id="", gmail_message_id="",
            )

    def test_sync_management_command_targets_one_enrolled_mailbox(self):
        output = StringIO()
        with patch("core.management.commands.sync_gmail_mailbox.sync_mailbox", return_value=2) as run:
            call_command(
                "sync_gmail_mailbox", organization=self.org.slug,
                mailbox=self.mailbox.address, stdout=output,
            )
        run.assert_called_once_with(self.mailbox.pk)
        self.assertIn("Synchronized 2 message event(s)", output.getvalue())

    def test_sync_command_persists_failure_state(self):
        with patch(
            "core.management.commands.sync_gmail_mailbox.sync_mailbox",
            side_effect=GmailError("gmail_http_503", retryable=True),
        ):
            with self.assertRaises(CommandError):
                call_command(
                    "sync_gmail_mailbox", organization=self.org.slug,
                    mailbox=self.mailbox.address,
                )
        self.mailbox.refresh_from_db()
        self.assertEqual(self.mailbox.gmail_sync_status, Mailbox.GmailSyncStatus.ERROR)
        self.assertEqual(self.mailbox.last_error_code, "gmail_http_503")


class GmailEnrollmentTests(TestCase):
    def test_enrollment_verifies_exact_profile_and_preserves_boundary(self):
        org = Organization.objects.create(slug="enroll-test", name="Enroll")
        mailbox = Mailbox.objects.create(
            organization=org, address="inbox@example.com", state=Mailbox.State.PENDING,
        )
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".json", delete=False) as stream:
            json.dump({"client_id": "client-123"}, stream)
            path = stream.name
        class Client:
            def __init__(self, mailbox_id):
                self.mailbox_id = mailbox_id
            def profile(self):
                persisted = Mailbox.objects.get(pk=self.mailbox_id)
                assert persisted.gmail_sync_status == Mailbox.GmailSyncStatus.ENROLLING
                return {"emailAddress": "inbox@example.com", "historyId": "501"}
        try:
            with override_settings(GOOGLE_INGESTION_SERVICE_ACCOUNT_FILE=path), patch(
                "core.management.commands.enroll_gmail_mailbox.GmailClient", Client,
            ):
                call_command("enroll_gmail_mailbox", organization=org.slug, mailbox=mailbox.address)
                Mailbox.objects.filter(pk=mailbox.pk).update(gmail_history_id="555")
                call_command("enroll_gmail_mailbox", organization=org.slug, mailbox=mailbox.address)
        finally:
            os.unlink(path)
        mailbox.refresh_from_db()
        self.assertEqual(mailbox.gmail_enrollment_history_id, "501")
        self.assertEqual(mailbox.gmail_history_id, "555")
        self.assertEqual(mailbox.gmail_sync_status, Mailbox.GmailSyncStatus.INITIALIZING)
        self.assertEqual(mailbox.state, Mailbox.State.ACTIVE)

    def test_mismatched_profile_does_not_activate_mailbox(self):
        org = Organization.objects.create(slug="enroll-mismatch", name="Enroll")
        mailbox = Mailbox.objects.create(organization=org, address="inbox@example.com")
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".json", delete=False) as stream:
            json.dump({"client_id": "client-123"}, stream)
            path = stream.name
        class Client:
            def __init__(self, mailbox_id):
                pass
            def profile(self):
                return {"emailAddress": "different@example.com", "historyId": "501"}
        try:
            with override_settings(GOOGLE_INGESTION_SERVICE_ACCOUNT_FILE=path), patch(
                "core.management.commands.enroll_gmail_mailbox.GmailClient", Client,
            ):
                from django.core.management.base import CommandError
                with self.assertRaises(CommandError):
                    call_command("enroll_gmail_mailbox", organization=org.slug, mailbox=mailbox.address)
        finally:
            os.unlink(path)
        mailbox.refresh_from_db()
        self.assertEqual(mailbox.state, Mailbox.State.ERROR)
        self.assertEqual(mailbox.gmail_enrollment_history_id, "")
