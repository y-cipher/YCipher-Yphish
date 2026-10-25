from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from django.db import DatabaseError, IntegrityError, connections, transaction
from django.test import SimpleTestCase, TransactionTestCase
from django.utils import timezone

from .models import ActionExecution, AnalysisRun, Artifact, AuditEvent, EmailCase, Evidence, Mailbox, Organization, artifact_upload_path
from .services import (
    IdempotencyConflict, InvalidActionTransition, InvalidRelationship,
    create_action_execution, create_email_case, mark_action_failure,
    mark_action_skipped, record_evidence,
)
from .storage import PrivateArtifactStorage


class PrivateStorageTests(SimpleTestCase):
    def test_storage_has_no_url_and_upload_path_ignores_filename(self):
        with self.assertRaises(ValueError):
            PrivateArtifactStorage().url("example")
        artifact = Artifact(organization_id="11111111-1111-1111-1111-111111111111", case_id="22222222-2222-2222-2222-222222222222")
        path = artifact_upload_path(artifact, "../../sensitive.eml")
        self.assertTrue(path.startswith(f"{artifact.organization_id}/{artifact.case_id}/"))
        self.assertNotIn("sensitive", path)


class DatabaseIntegrityTests(TransactionTestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="One", slug="one")
        self.other_org = Organization.objects.create(name="Two", slug="two")
        self.mailbox = Mailbox.objects.create(organization=self.org, address="Inbox@example.com")
        self.case = EmailCase.objects.create(organization=self.org, mailbox=self.mailbox, gmail_message_id="baseline", provider_immutable_id="baseline")

    def test_case_cannot_link_to_another_organizations_mailbox(self):
        with self.assertRaises(DatabaseError), transaction.atomic():
            EmailCase.objects.create(organization=self.other_org, mailbox=self.mailbox, gmail_message_id="cross-org", provider_immutable_id="cross-org")

    def test_mailbox_address_is_case_insensitively_unique_within_organization(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            Mailbox.objects.create(organization=self.org, address="inbox@EXAMPLE.com")

    def test_stored_artifact_requires_file_size_and_digest(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            Artifact.objects.create(
                organization=self.org, case=self.case,
                kind=Artifact.Kind.ORIGINAL_MIME, state=Artifact.State.STORED,
            )

    def test_audit_event_is_append_only(self):
        event = AuditEvent.objects.create(
            organization=self.org,
            case=self.case,
            event_type="case.created",
            occurred_at=timezone.now(),
        )
        with self.assertRaises(DatabaseError), transaction.atomic():
            AuditEvent.objects.filter(pk=event.pk).update(event_type="changed")
        with self.assertRaises(DatabaseError), transaction.atomic():
            AuditEvent.objects.filter(pk=event.pk).delete()


class TransactionalServiceTests(TransactionTestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="One", slug="service-one")
        self.other_org = Organization.objects.create(name="Two", slug="service-two")
        self.mailbox = Mailbox.objects.create(organization=self.org, address="one@example.com")
        self.other_mailbox = Mailbox.objects.create(organization=self.other_org, address="two@example.com")
        self.case, _ = create_email_case(
            organization=self.org, mailbox=self.mailbox, gmail_message_id="baseline"
        )

    def _concurrent(self, operation):
        barrier = Barrier(2)

        def worker():
            connections.close_all()
            try:
                barrier.wait(timeout=10)
                row, created = operation()
                return row.pk, created
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(worker)
            second = executor.submit(worker)
            return first.result(timeout=20), second.result(timeout=20)

    def test_case_duplicate_returns_original_without_overwriting_metadata(self):
        first, created = create_email_case(
            organization=self.org, mailbox=self.mailbox,
            gmail_message_id="immutable-1", subject="Original",
        )
        again, created_again = create_email_case(
            organization=self.org, mailbox=self.mailbox,
            gmail_message_id="immutable-1", subject="Changed on retry",
        )
        self.assertTrue(created)
        self.assertFalse(created_again)
        self.assertEqual(first.pk, again.pk)
        self.assertEqual(again.subject, "Original")
        self.assertEqual(AuditEvent.objects.filter(subject_id=first.pk, event_type="case.created").count(), 1)

    def test_same_immutable_id_in_different_mailboxes_is_distinct(self):
        first, _ = create_email_case(
            organization=self.org, mailbox=self.mailbox, gmail_message_id="shared-id"
        )
        second, created = create_email_case(
            organization=self.other_org, mailbox=self.other_mailbox, gmail_message_id="shared-id"
        )
        self.assertTrue(created)
        self.assertNotEqual(first.pk, second.pk)

    def test_concurrent_case_requests_return_one_row(self):
        results = self._concurrent(lambda: create_email_case(
            organization=self.org, mailbox=self.mailbox, gmail_message_id="racing-case"
        ))
        self.assertEqual(results[0][0], results[1][0])
        self.assertEqual(sorted(result[1] for result in results), [False, True])
        self.assertEqual(EmailCase.objects.filter(gmail_message_id="racing-case").count(), 1)

    def test_evidence_duplicate_and_concurrent_requests(self):
        observed_at = timezone.now()
        operation = lambda: record_evidence(
            organization=self.org, case=self.case, idempotency_key="parser:header:1",
            source=Evidence.Source.PARSER, label="Header", observed_at=observed_at,
            details={"result": "present"},
        )
        results = self._concurrent(operation)
        self.assertEqual(results[0][0], results[1][0])
        self.assertEqual(sorted(result[1] for result in results), [False, True])
        again, created = operation()
        self.assertFalse(created)
        self.assertEqual(again.pk, results[0][0])
        with self.assertRaises(IdempotencyConflict):
            record_evidence(
                organization=self.org, case=self.case, idempotency_key="parser:header:1",
                source=Evidence.Source.PARSER, label="Different", observed_at=observed_at,
            )

    def test_action_duplicate_concurrent_and_conflicting_key(self):
        operation = lambda: create_action_execution(
            organization=self.org, case=self.case, idempotency_key="case-action-1",
            action=ActionExecution.Action.MOVE, target={"folder": "suspicious"},
        )
        results = self._concurrent(operation)
        self.assertEqual(results[0][0], results[1][0])
        self.assertEqual(sorted(result[1] for result in results), [False, True])
        with self.assertRaises(IdempotencyConflict):
            create_action_execution(
                organization=self.org, case=self.case, idempotency_key="case-action-1",
                action=ActionExecution.Action.RESTORE,
            )
        self.assertEqual(ActionExecution.objects.filter(idempotency_key="case-action-1").count(), 1)

    def test_invalid_organization_and_case_relationships(self):
        with self.assertRaises(InvalidRelationship):
            create_email_case(
                organization=self.other_org, mailbox=self.mailbox, gmail_message_id="wrong-org"
            )
        with self.assertRaises(InvalidRelationship):
            record_evidence(
                organization=self.other_org, case=self.case, idempotency_key="wrong-org",
                source=Evidence.Source.PARSER, label="Header", observed_at=timezone.now(),
            )
        other_case, _ = create_email_case(
            organization=self.org, mailbox=self.mailbox, gmail_message_id="other-case"
        )
        other_run = AnalysisRun.objects.create(organization=self.org, case=other_case)
        with self.assertRaises(InvalidRelationship):
            create_action_execution(
                organization=self.org, case=self.case, idempotency_key="wrong-run",
                action=ActionExecution.Action.MOVE, analysis_run=other_run,
            )
        with self.assertRaises(InvalidRelationship):
            create_action_execution(
                organization=self.other_org, case=self.case, idempotency_key="wrong-org-action",
                action=ActionExecution.Action.MOVE,
            )

    def test_action_failure_states_distinguish_uncertain_and_definite(self):
        execution, _ = create_action_execution(
            organization=self.org, case=self.case, idempotency_key="failure-1",
            action=ActionExecution.Action.MOVE,
        )
        ActionExecution.objects.filter(pk=execution.pk).update(state=ActionExecution.State.RUNNING)
        uncertain = mark_action_failure(execution=execution, error_code="provider_timeout", uncertain=True)
        self.assertEqual(uncertain.state, ActionExecution.State.RECONCILING)
        failed = mark_action_failure(execution=execution, error_code="not_applied")
        self.assertEqual(failed.state, ActionExecution.State.FAILED)
        self.assertEqual(mark_action_failure(execution=execution, error_code="not_applied").pk, failed.pk)
        with self.assertRaises(InvalidActionTransition):
            mark_action_failure(execution=execution, error_code="provider_timeout", uncertain=True)
        with self.assertRaises(IntegrityError), transaction.atomic():
            ActionExecution.objects.filter(pk=execution.pk).update(error_code="")

    def test_skipped_action_never_enters_running_or_failed(self):
        execution, _ = create_action_execution(
            organization=self.org, case=self.case, idempotency_key="skip-1",
            action=ActionExecution.Action.MOVE,
        )
        with self.assertRaises(InvalidActionTransition):
            mark_action_failure(execution=execution, error_code="not_started")
        skipped = mark_action_skipped(execution=execution, reason_code="policy_denied")
        self.assertEqual(skipped.state, ActionExecution.State.SKIPPED)
        self.assertEqual(mark_action_skipped(execution=execution, reason_code="policy_denied").pk, skipped.pk)
        with self.assertRaises(InvalidActionTransition):
            mark_action_failure(execution=execution, error_code="not_started")

    def test_database_guards_evidence_and_action_relationships(self):
        with self.assertRaises(DatabaseError), transaction.atomic():
            Evidence.objects.create(
                organization=self.other_org, case=self.case,
                idempotency_key="cross-org-evidence", source=Evidence.Source.PARSER,
                label="Header", observed_at=timezone.now(),
            )
        with self.assertRaises(DatabaseError), transaction.atomic():
            ActionExecution.objects.create(
                organization=self.other_org, case=self.case,
                idempotency_key="cross-org-action", action=ActionExecution.Action.MOVE,
                requested_at=timezone.now(),
            )
        with self.assertRaises(DatabaseError), transaction.atomic():
            EmailCase.objects.create(organization=self.org, mailbox=self.mailbox, gmail_message_id="")
