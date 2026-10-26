"""PostgreSQL-backed queue, retry, and history state tests; no live Gmail."""

import tempfile
from datetime import timedelta
from threading import Event, Thread
from unittest.mock import patch

from django.test import TransactionTestCase, override_settings
from django.utils import timezone
from googleapiclient.errors import HttpError
from google.auth.exceptions import GoogleAuthError
from httplib2 import Response

from .analysis_runtime import reconcile_analysis, run_analysis
from .gmail import GmailClient, GmailError, _http_error
from .gmail_runtime import _mailbox_lock, ingest_message, sync_mailbox
from .models import AnalysisRun, Artifact, EmailCase, Evidence, Mailbox, Organization
from .tasks import dispatch_pending_analysis, poll_gmail, record_sync_failure, retry_delay
from .test_gmail import FakeGmail, Provider, Service


class BackgroundGmailTests(TransactionTestCase):
    def setUp(self):
        self.org = Organization.objects.create(
            slug="background", name="Background", gmail_service_account_client_id="client-1",
            gmail_access_verified_at=timezone.now(),
        )
        self.mailbox = Mailbox.objects.create(
            organization=self.org, address="inbox@example.test", state=Mailbox.State.ACTIVE,
            gmail_sync_status=Mailbox.GmailSyncStatus.READY,
            gmail_enrolled_at=timezone.now(), gmail_enrollment_history_id="100",
            gmail_history_id="100",
        )

    def _storage(self, directory):
        return patch.object(Artifact._meta.get_field("file").storage, "_location", directory)

    def test_duplicate_ingestion_one_durable_job_and_one_analysis(self):
        with tempfile.TemporaryDirectory() as directory, self._storage(directory):
            ingest_message(self.mailbox.pk, "same", client=FakeGmail())
            ingest_message(self.mailbox.pk, "same", client=FakeGmail())
            self.assertEqual(EmailCase.objects.count(), 1)
            self.assertEqual(AnalysisRun.objects.count(), 1)
            run = AnalysisRun.objects.get()
            self.assertTrue(run_analysis(run.pk))
            self.assertFalse(run_analysis(run.pk))
        self.assertEqual(AnalysisRun.objects.get().state, AnalysisRun.State.SUCCEEDED)
        self.assertEqual(EmailCase.objects.get().state, EmailCase.State.ANALYZED)
        self.assertEqual(Evidence.objects.filter(source=Evidence.Source.PARSER).count(), 1)
        self.assertEqual(Evidence.objects.filter(source=Evidence.Source.INGESTION).count(), 1)

    def test_history_labels_and_deletion_never_reanalyze(self):
        fake = FakeGmail(events={"100": [("same", "labels"), ("same", "labels"),
                                         ("same", "deleted"), ("same", "deleted")]})
        with tempfile.TemporaryDirectory() as directory, self._storage(directory):
            ingest_message(self.mailbox.pk, "same", client=fake)
            run_analysis(AnalysisRun.objects.get().pk)
            sync_mailbox(self.mailbox.pk, client=fake)
        case = EmailCase.objects.get()
        self.assertIsNotNone(case.gmail_deleted_at)
        self.assertEqual(AnalysisRun.objects.count(), 1)
        self.assertEqual(AnalysisRun.objects.get().state, AnalysisRun.State.SUCCEEDED)
        self.assertEqual(Evidence.objects.filter(source=Evidence.Source.PARSER).count(), 1)
        self.assertEqual(Evidence.objects.filter(source=Evidence.Source.INGESTION).count(), 1)

    def test_worker_crash_lease_is_reconciled(self):
        with tempfile.TemporaryDirectory() as directory, self._storage(directory):
            ingest_message(self.mailbox.pk, "crash", client=FakeGmail())
            run = AnalysisRun.objects.get()
            run.state = AnalysisRun.State.RUNNING
            run.lease_expires_at = timezone.now() - timedelta(seconds=1)
            run.save(update_fields=["state", "lease_expires_at"])
            EmailCase.objects.update(state=EmailCase.State.PROCESSING)
            self.assertEqual(reconcile_analysis(), 1)
            self.assertTrue(run_analysis(run.pk))
        self.assertEqual(AnalysisRun.objects.get().state, AnalysisRun.State.SUCCEEDED)

    def test_broker_failure_keeps_outbox_for_next_sweep(self):
        with tempfile.TemporaryDirectory() as directory, self._storage(directory):
            ingest_message(self.mailbox.pk, "broker", client=FakeGmail())
            with patch("core.tasks.analyze_gmail_case.delay", side_effect=OSError("broker down")):
                with self.assertRaises(OSError):
                    dispatch_pending_analysis()
            self.assertEqual(AnalysisRun.objects.get().state, AnalysisRun.State.QUEUED)
            self.assertIsNone(AnalysisRun.objects.get().last_dispatched_at)
            with patch("core.tasks.analyze_gmail_case.delay") as publish:
                self.assertEqual(dispatch_pending_analysis(), 1)
            publish.assert_called_once()
        self.assertIsNotNone(AnalysisRun.objects.get().last_dispatched_at)

    def test_missing_outbox_for_saved_case_is_repaired(self):
        case = EmailCase.objects.create(
            organization=self.org, mailbox=self.mailbox,
            provider_immutable_id="orphan", gmail_message_id="orphan",
        )
        AnalysisRun.objects.create(
            organization=self.org, case=case, attempt=1,
            idempotency_key="other:engine:v1",
        )
        self.assertEqual(reconcile_analysis(), 1)
        repaired = AnalysisRun.objects.get(case=case, idempotency_key="gmail:parse:v1")
        self.assertEqual(repaired.attempt, 2)
        self.assertEqual(repaired.state, AnalysisRun.State.QUEUED)

    def test_overlapping_sync_does_not_change_cursor_or_failure_state(self):
        entered, release = Event(), Event()
        errors = []

        def holder():
            from django.db import close_old_connections
            close_old_connections()
            try:
                with _mailbox_lock(self.mailbox.pk):
                    entered.set()
                    release.wait(10)
            except Exception as exc:
                errors.append(exc)
            finally:
                close_old_connections()

        thread = Thread(target=holder)
        thread.start()
        try:
            self.assertTrue(entered.wait(10))
            with self.assertRaises(GmailError) as caught:
                sync_mailbox(self.mailbox.pk, client=FakeGmail())
            self.assertEqual(caught.exception.code, "gmail_sync_already_running")
            record_sync_failure(self.mailbox.pk, caught.exception)
            self.mailbox.refresh_from_db()
            self.assertEqual(self.mailbox.gmail_history_id, "100")
            self.assertEqual(self.mailbox.gmail_sync_status, Mailbox.GmailSyncStatus.READY)
        finally:
            release.set()
            thread.join(10)
        self.assertFalse(errors)

    def test_rate_limit_retry_after_and_failure_states(self):
        response = Response({"status": 403, "Retry-After": "120"})
        error = HttpError(response, b'{"error":{"errors":[{"reason":"userRateLimitExceeded"}]}}')
        classified = _http_error(error)
        self.assertEqual(classified.code, "gmail_rate_limited")
        self.assertEqual(classified.retry_after_seconds, 120)
        self.assertTrue(classified.retryable)
        with override_settings(GMAIL_RETRY_BASE_SECONDS=1, GMAIL_RETRY_MAX_SECONDS=10):
            self.assertGreaterEqual(retry_delay(3, 120), 120)
            record_sync_failure(self.mailbox.pk, classified)
        self.mailbox.refresh_from_db()
        self.assertEqual(self.mailbox.gmail_sync_status, Mailbox.GmailSyncStatus.THROTTLED)
        self.assertGreaterEqual((self.mailbox.gmail_next_sync_at - timezone.now()).total_seconds(), 119)
        record_sync_failure(self.mailbox.pk, GmailError("gmail_transport_error", retryable=True))
        self.mailbox.refresh_from_db()
        self.assertEqual(self.mailbox.gmail_sync_status, Mailbox.GmailSyncStatus.DISCONNECTED)
        record_sync_failure(self.mailbox.pk, GmailError("gmail_http_503", retryable=True))
        self.mailbox.refresh_from_db()
        self.assertEqual(self.mailbox.gmail_sync_status, Mailbox.GmailSyncStatus.UNAVAILABLE)
        record_sync_failure(self.mailbox.pk, GmailError("gmail_http_401"))
        self.mailbox.refresh_from_db()
        self.assertEqual(self.mailbox.gmail_sync_status, Mailbox.GmailSyncStatus.AUTHORIZATION_FAILED)
        with patch("core.tasks.sync_gmail_mailbox.delay") as publish:
            self.assertEqual(poll_gmail(), 0)
        publish.assert_not_called()

    def test_expired_google_credentials_become_authorization_failure(self):
        service = Service(raw=GoogleAuthError("expired"))
        client = GmailClient(self.mailbox.pk, credential_provider=Provider(), service=service)
        with self.assertRaises(GmailError) as caught:
            client.get_raw_message("some-message")
        self.assertEqual(caught.exception.code, "gmail_authorization_failed")
        self.assertFalse(caught.exception.retryable)

    def test_deleted_history_event_is_emitted_by_client(self):
        service = Service(history_pages=[{
            "history": [{"messagesDeleted": [{"message": {"id": "gone"}}]}],
            "historyId": "913",
        }])
        client = GmailClient(self.mailbox.pk, credential_provider=Provider(), service=service)
        self.assertEqual(list(client.history_messages("100")), [("gone", "deleted"), (None, "913")])

    def test_due_poll_queues_only_enrolled_mailboxes(self):
        Mailbox.objects.create(organization=self.org, address="pending@example.test")
        with patch("core.tasks.sync_gmail_mailbox.delay") as publish:
            self.assertEqual(poll_gmail(), 1)
        publish.assert_called_once_with(str(self.mailbox.pk))
