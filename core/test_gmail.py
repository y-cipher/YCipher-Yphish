import base64
import json
import tempfile
from unittest.mock import patch

from django.db import DatabaseError, transaction
from django.core.management import call_command
from django.test import SimpleTestCase, TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from .gmail import GmailClient, GmailError, GmailHistoryExpired
from .gmail_runtime import authorize_automatic_responses, execute_action, ingest_message, sync_mailbox
from .models import ActionExecution, Artifact, EmailCase, Evidence, Mailbox, Organization
from .services import create_email_case


RAW = b"From: sender@example.test\r\nTo: inbox@example.test\r\nSubject: Test\r\nMessage-ID: <synthetic@example.test>\r\n\r\nsynthetic body"


class FakeGmail:
    def __init__(self, *args, **kwargs):
        self.labels = {"INBOX"}
        self.modified = []

    def get_raw_message(self, message_id):
        return {"id": message_id, "threadId": "thread-context-1"}, RAW

    def history_messages(self, cursor):
        yield "message-A", None
        yield "message-B", None
        yield None, "102"

    def get_labels(self, message_id):
        return set(self.labels)

    def modify_labels(self, message_id, *, add=(), remove=()):
        self.modified.append((message_id, set(add), set(remove)))
        self.labels.update(add)
        self.labels.difference_update(remove)


class GmailClientTests(SimpleTestCase):
    def test_raw_decoding_and_message_endpoint(self):
        client = object.__new__(GmailClient)
        class Response:
            status_code = 200
            def json(self):
                return {"id": "message-A", "raw": base64.urlsafe_b64encode(RAW).decode().rstrip("=")}
        class Session:
            def request(self, method, url, **kwargs):
                self_url.append(url)
                return Response()
        self_url = []
        client.session = Session()
        _, raw = client.get_raw_message("message-A")
        self.assertEqual(raw, RAW)
        self.assertEqual(self_url, ["https://gmail.googleapis.com/gmail/v1/users/me/messages/message-A"])

    def test_stale_history_is_explicit(self):
        client = object.__new__(GmailClient)
        class Response:
            status_code = 404
        class Session:
            def request(self, *args, **kwargs):
                return Response()
        client.session = Session()
        with self.assertRaises(GmailHistoryExpired):
            list(client.history_messages("old-cursor"))


class GmailDatabaseTests(TransactionTestCase):
    def setUp(self):
        self.org = Organization.objects.create(
            slug="gmail-tests", name="Gmail Tests", gmail_service_account_client_id="client-123",
            gmail_access_verified_at=timezone.now(), gmail_response_enabled=True,
        )
        self.mailbox = Mailbox.objects.create(
            organization=self.org, address="inbox@example.test", state=Mailbox.State.ACTIVE,
            gmail_history_id="100", gmail_label_id="Label_123",
        )

    def test_message_identity_is_distinct_from_thread(self):
        first, _ = create_email_case(organization=self.org, mailbox=self.mailbox, gmail_message_id="A", gmail_thread_id="same")
        second, _ = create_email_case(organization=self.org, mailbox=self.mailbox, gmail_message_id="B", gmail_thread_id="same")
        again, created = create_email_case(organization=self.org, mailbox=self.mailbox, gmail_message_id="A", gmail_thread_id="different")
        self.assertNotEqual(first.pk, second.pk)
        self.assertEqual(first.pk, again.pk)
        self.assertFalse(created)
        self.assertEqual(again.gmail_thread_id, "same")
        with self.assertRaises(DatabaseError), transaction.atomic():
            EmailCase.objects.create(organization=self.org, mailbox=self.mailbox, provider_immutable_id="", gmail_message_id="")

    def test_history_poll_advances_only_after_messages_are_stored(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(Artifact._meta.get_field("file").storage, "_location", directory):
            with patch("core.gmail_runtime.GmailClient", return_value=FakeGmail()):
                self.assertEqual(sync_mailbox(self.mailbox.pk), 2)
                self.assertEqual(sync_mailbox(self.mailbox.pk), 2)
            self.mailbox.refresh_from_db()
            self.assertEqual(self.mailbox.gmail_history_id, "102")
            self.assertEqual(EmailCase.objects.count(), 2)
            self.assertEqual(Artifact.objects.filter(state=Artifact.State.STORED).count(), 2)
            self.assertEqual(Evidence.objects.count(), 4)
            self.assertEqual(set(EmailCase.objects.values_list("gmail_thread_id", flat=True)), {"thread-context-1"})

    def test_expired_history_reconciles_all_message_ids(self):
        class Expired(FakeGmail):
            def history_messages(self, cursor):
                raise GmailHistoryExpired()
                yield
            def profile(self):
                return {"historyId": "201"}
            def list_messages(self):
                yield {"id": "message-A", "threadId": "same-thread"}
                yield {"id": "message-B", "threadId": "same-thread"}
        with tempfile.TemporaryDirectory() as directory, patch.object(Artifact._meta.get_field("file").storage, "_location", directory):
            with patch("core.gmail_runtime.GmailClient", return_value=Expired()):
                self.assertEqual(sync_mailbox(self.mailbox.pk), 2)
        self.mailbox.refresh_from_db()
        self.assertEqual(self.mailbox.gmail_history_id, "201")
        self.assertEqual(EmailCase.objects.count(), 2)

    def test_automatic_policy_moves_one_message_and_verifies_labels(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(Artifact._meta.get_field("file").storage, "_location", directory):
            case = ingest_message(self.mailbox, "message-A", client=FakeGmail())
            case.verdict = EmailCase.Verdict.MALICIOUS
            case.save(update_fields=["verdict"])
            authorize_automatic_responses()
            authorize_automatic_responses()
            self.assertEqual(ActionExecution.objects.count(), 1)
            execution = ActionExecution.objects.get()
            self.assertEqual(execution.state, ActionExecution.State.AUTHORIZED)
            fake = FakeGmail()
            with patch("core.gmail_runtime.GmailClient", return_value=fake):
                self.assertEqual(execute_action(execution.pk), ActionExecution.State.SUCCEEDED)
            self.assertEqual(fake.modified, [("message-A", {"Label_123"}, {"INBOX"})])
            self.assertEqual(execute_action(execution.pk), ActionExecution.State.SUCCEEDED)

    def test_uncertain_write_reconciles_before_retrying(self):
        case, _ = create_email_case(organization=self.org, mailbox=self.mailbox, gmail_message_id="message-A")
        execution = ActionExecution.objects.create(
            organization=self.org, case=case, idempotency_key="gmail:move:uncertain",
            action=ActionExecution.Action.MOVE, state=ActionExecution.State.AUTHORIZED,
            target={"label_id": "Label_123"}, requested_at=timezone.now(),
        )
        fake = FakeGmail()
        def uncertain_modify(message_id, *, add=(), remove=()):
            fake.labels.update(add)
            fake.labels.difference_update(remove)
            raise GmailError("gmail_transport_error", uncertain=True)
        fake.modify_labels = uncertain_modify
        with patch("core.gmail_runtime.GmailClient", return_value=fake):
            self.assertEqual(execute_action(execution.pk), ActionExecution.State.RECONCILING)
            self.assertEqual(execute_action(execution.pk), ActionExecution.State.SUCCEEDED)
        execution.refresh_from_db()
        self.assertEqual(execution.state, ActionExecution.State.SUCCEEDED)


class GmailEnrollmentTests(TestCase):
    def test_enrollment_verifies_profile_and_preserves_cursor_on_repeat(self):
        org = Organization.objects.create(slug="enroll-test", name="Enroll test")
        mailbox = Mailbox.objects.create(organization=org, address="inbox@example.test", state=Mailbox.State.PENDING)
        class Client:
            def __init__(self, address):
                self.address = address
            def profile(self):
                return {"emailAddress": self.address, "historyId": "100"}
            def ensure_label(self, name):
                return "Label_123"
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".json", delete=False) as stream:
            json.dump({"client_id": "client-123"}, stream)
            credential_path = stream.name
        try:
            with override_settings(GOOGLE_SERVICE_ACCOUNT_FILE=credential_path), patch(
                "core.management.commands.enroll_gmail_mailbox.GmailClient", Client
            ):
                call_command("enroll_gmail_mailbox", organization=org.slug, mailbox=mailbox.address)
                Mailbox.objects.filter(pk=mailbox.pk).update(gmail_history_id="105")
                call_command("enroll_gmail_mailbox", organization=org.slug, mailbox=mailbox.address)
        finally:
            import os
            os.unlink(credential_path)
        mailbox.refresh_from_db()
        org.refresh_from_db()
        self.assertEqual(mailbox.gmail_history_id, "105")
        self.assertEqual(mailbox.gmail_label_id, "Label_123")
        self.assertEqual(mailbox.state, Mailbox.State.ACTIVE)
        self.assertEqual(org.gmail_service_account_client_id, "client-123")
