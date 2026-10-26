"""Synthetic PostgreSQL and mocked-provider tests for message-level response."""

from datetime import timedelta
from unittest.mock import MagicMock, mock_open, patch

from django.test import TestCase, override_settings
from django.utils import timezone

from .gmail import GmailError
from .gmail_credentials import (
    ADMIN_RESPONSE_SCOPE, LABELS_SCOPE, CredentialPurpose,
    WorkspaceDelegatedCredentialProvider,
)
from .gmail_response import GmailResponseClient, SUSPICIOUS_LABEL
from .models import (
    ActionExecution, AnalysisRun, EmailCase, Evidence, Feedback,
    InvestigationRun, Mailbox, Organization, ResponseControl,
)
from .response_policy import evaluate_case
from .response_runtime import (
    execute_response, pending_response_case_ids, pending_restoration_case_ids, prepare_response,
    prepare_restoration, reconcile_response_work,
)


class FakeMailboxState:
    def __init__(self):
        self.messages = {}
        self.history = {}
        self.label_id = "Label_Yphish"
        self.label_name = SUSPICIOUS_LABEL
        self.modifications = []
        self.fail_before = None
        self.fail_after = None

    def add(self, message_id, labels):
        self.messages[message_id] = set(labels)
        self.history[message_id] = 100

    def get_message_metadata(self, message_id):
        if message_id not in self.messages:
            raise GmailError("gmail_http_404")
        return {"id": message_id, "labelIds": sorted(self.messages[message_id]),
                "historyId": str(self.history[message_id])}

    def ensure_suspicious_label(self):
        return self.label_id

    def canonical_label_exists(self, label_id):
        return label_id == self.label_id and self.label_name == SUSPICIOUS_LABEL

    def modify_case(self, case_id, *, add_label_ids, remove_label_ids, yphish_label_id):
        message_id = EmailCase.objects.get(pk=case_id).gmail_message_id
        self.modifications.append((message_id, tuple(add_label_ids), tuple(remove_label_ids)))
        if self.fail_before:
            error, self.fail_before = self.fail_before, None
            raise error
        if message_id not in self.messages:
            raise GmailError("gmail_http_404")
        self.messages[message_id].update(add_label_ids)
        self.messages[message_id].difference_update(remove_label_ids)
        self.history[message_id] += 1
        if self.fail_after:
            error, self.fail_after = self.fail_after, None
            raise error
        return {"id": message_id, "labelIds": sorted(self.messages[message_id])}


class ResponseTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.org = Organization.objects.create(
            name="Response", slug="response", gmail_access_verified_at=self.now,
            gmail_service_account_client_id="ingest-client",
            gmail_response_enabled=True,
            gmail_response_service_account_client_id="response-client",
            gmail_response_scope=ADMIN_RESPONSE_SCOPE,
            gmail_response_labels_scope=LABELS_SCOPE,
        )
        self.mailbox = Mailbox.objects.create(
            organization=self.org, address="inbox@example.com", state=Mailbox.State.ACTIVE,
            gmail_sync_status=Mailbox.GmailSyncStatus.READY,
            gmail_enrolled_at=self.now, gmail_enrollment_history_id="100",
            gmail_response_enabled=True, gmail_response_remove_inbox=True,
        )
        self.case, self.analysis = self._qualified_case("malicious")
        self.state = FakeMailboxState()
        self.state.add("malicious", {"INBOX", "UNREAD", "OTHER"})

    def _qualified_case(self, message_id, *, mailbox=None, thread="shared-thread", operational=True):
        mailbox = mailbox or self.mailbox
        case = EmailCase.objects.create(
            organization=mailbox.organization, mailbox=mailbox,
            provider_immutable_id=message_id, gmail_message_id=message_id,
            gmail_thread_id=thread, state=EmailCase.State.ANALYZED,
        )
        analysis = AnalysisRun.objects.create(
            organization=case.organization, case=case, attempt=1,
            state=AnalysisRun.State.SUCCEEDED, engine_version="rules-v1",
            finished_at=self.now,
        )
        InvestigationRun.objects.create(
            organization=case.organization, mailbox=mailbox, case=case, analysis_run=analysis,
            policy_version="explicit-v1", state=InvestigationRun.State.COMPLETED,
            stopping_reason="policy_complete", finished_at=self.now,
        )
        Evidence.objects.create(
            organization=case.organization, case=case, analysis_run=analysis,
            idempotency_key=f"indicator:{message_id}", source=Evidence.Source.RULE,
            state=Evidence.State.OBSERVED, trust=Evidence.Trust.UNTRUSTED,
            label="Exact indicator", rule_id="INDICATOR_EXACT", source_version="1",
            source_field="mime.body", observed_at=self.now,
            provenance={"source_kind": "operational" if operational else "synthetic",
                        "fetched_at": (self.now - timedelta(hours=1)).isoformat(),
                        "expires_at": (self.now + timedelta(hours=1)).isoformat()},
        )
        Evidence.objects.create(
            organization=case.organization, case=case, analysis_run=analysis,
            idempotency_key=f"link:{message_id}", source=Evidence.Source.RULE,
            state=Evidence.State.OBSERVED, trust=Evidence.Trust.UNTRUSTED,
            label="Destination mismatch", rule_id="LINK_VISIBLE_DESTINATION",
            source_version="1", source_field="mime.body", observed_at=self.now,
        )
        return case, analysis

    def _prepare(self, case=None):
        return prepare_response((case or self.case).pk, read_client=self.state,
                                write_client=self.state)

    def _execute(self, action):
        return execute_response(action.pk, read_client=self.state, write_client=self.state)

    def _legitimate_feedback(self):
        return Feedback.objects.create(
            organization=self.org, case=self.case,
            proposed_verdict=EmailCase.Verdict.LEGITIMATE,
            reason="Reviewed correction", state=Feedback.State.REVIEWED,
            reviewed_at=timezone.now(),
        )

    def test_only_qualifying_message_in_mixed_thread_is_modified(self):
        legitimate = EmailCase.objects.create(
            organization=self.org, mailbox=self.mailbox,
            provider_immutable_id="legitimate", gmail_message_id="legitimate",
            gmail_thread_id=self.case.gmail_thread_id, state=EmailCase.State.ANALYZED,
        )
        self.state.add("legitimate", {"INBOX", "UNREAD", "PERSONAL"})
        self.assertFalse(evaluate_case(legitimate).qualifies)
        action = self._prepare()
        self.assertEqual(action.state, ActionExecution.State.AUTHORIZED)
        self.assertEqual(action.target["before_label_ids"], ["INBOX", "OTHER", "UNREAD"])
        self.assertEqual(action.target["add_label_ids"], ["Label_Yphish"])
        self.assertEqual(action.target["remove_label_ids"], ["INBOX"])
        self.assertTrue(self._execute(action))
        action.refresh_from_db()
        self.assertEqual(action.state, ActionExecution.State.SUCCEEDED)
        self.assertIsNotNone(action.verified_at)
        self.assertEqual(self.state.messages["malicious"], {"Label_Yphish", "OTHER", "UNREAD"})
        self.assertEqual(self.state.messages["legitimate"], {"INBOX", "UNREAD", "PERSONAL"})
        self.assertEqual(self.state.modifications, [("malicious", ("Label_Yphish",), ("INBOX",))])
        self.assertFalse(self._execute(action))

    def test_restoration_reverses_only_owned_changes(self):
        apply = self._prepare()
        self.assertTrue(self._execute(apply))
        self._legitimate_feedback()
        self.assertIn(self.case.pk, pending_restoration_case_ids())
        self.state.messages["malicious"].add("USER_ADDED")
        restore = prepare_restoration(self.case.pk, read_client=self.state,
                                      write_client=self.state)
        self.assertEqual(restore.target["add_label_ids"], ["INBOX"])
        self.assertEqual(restore.target["remove_label_ids"], ["Label_Yphish"])
        self.assertEqual(restore.target["source_action_id"], str(apply.pk))
        self.assertTrue(self._execute(restore))
        self.assertEqual(self.state.messages["malicious"],
                         {"INBOX", "OTHER", "UNREAD", "USER_ADDED"})
        self.assertIsNone(self._prepare())
        self.assertNotIn(self.case.pk, pending_restoration_case_ids())

    def test_pending_case_and_duplicate_preparation(self):
        self.assertIn(self.case.pk, pending_response_case_ids())
        first = self._prepare()
        self.assertEqual(self._prepare().pk, first.pk)
        self.assertNotIn(self.case.pk, pending_response_case_ids())

    def test_preexisting_label_is_never_removed_on_restore(self):
        self.state.messages["malicious"].add("Label_Yphish")
        apply = self._prepare()
        self.assertFalse(apply.target["yphish_added_label"])
        self.assertTrue(self._execute(apply))
        self._legitimate_feedback()
        restore = prepare_restoration(self.case.pk, read_client=self.state,
                                      write_client=self.state)
        self.assertEqual(restore.target["remove_label_ids"], [])
        self.assertTrue(self._execute(restore))
        self.assertIn("Label_Yphish", self.state.messages["malicious"])

    def test_renamed_or_deleted_label_is_not_removed(self):
        apply = self._prepare()
        self.assertTrue(self._execute(apply))
        self._legitimate_feedback()
        self.state.label_name = "User renamed label"
        restore = prepare_restoration(self.case.pk, read_client=self.state,
                                      write_client=self.state)
        self.assertEqual(restore.target["remove_label_ids"], [])
        self.assertTrue(self._execute(restore))
        self.assertIn("Label_Yphish", self.state.messages["malicious"])
        self.assertIn("INBOX", self.state.messages["malicious"])

    def test_spam_or_trash_never_resurrected(self):
        apply = self._prepare()
        self.assertTrue(self._execute(apply))
        self._legitimate_feedback()
        self.state.messages["malicious"].add("TRASH")
        restore = prepare_restoration(self.case.pk, read_client=self.state,
                                      write_client=self.state)
        self.assertEqual(restore.state, ActionExecution.State.SKIPPED)
        self.assertEqual(restore.error_code, "restoration_blocked_spam_trash")
        self.assertNotIn("INBOX", self.state.messages["malicious"])

    def test_ambiguous_timeout_reconciles_without_second_modify(self):
        action = self._prepare()
        self.state.fail_after = GmailError("gmail_transport_error", retryable=True)
        self.assertTrue(self._execute(action))
        action.refresh_from_db()
        self.assertEqual(action.state, ActionExecution.State.RECONCILING)
        ActionExecution.objects.filter(pk=action.pk).update(next_retry_at=self.now - timedelta(seconds=1))
        self.assertTrue(self._execute(action))
        action.refresh_from_db()
        self.assertEqual(action.state, ActionExecution.State.SUCCEEDED)
        self.assertEqual(len(self.state.modifications), 1)

    def test_timeout_before_modify_retries_after_provider_delay(self):
        action = self._prepare()
        self.state.fail_before = GmailError(
            "gmail_rate_limited", retryable=True, retry_after_seconds=180,
        )
        self.assertTrue(self._execute(action))
        action.refresh_from_db()
        self.assertEqual(action.state, ActionExecution.State.RECONCILING)
        self.assertGreaterEqual(action.next_retry_at, timezone.now() + timedelta(seconds=175))
        ActionExecution.objects.filter(pk=action.pk).update(
            next_retry_at=self.now - timedelta(seconds=1),
        )
        self.assertTrue(self._execute(action))
        action.refresh_from_db()
        self.assertEqual(action.state, ActionExecution.State.SUCCEEDED)
        self.assertEqual(len(self.state.modifications), 2)

    def test_expired_worker_lease_reconciles_applied_delta(self):
        action = self._prepare()
        self.state.messages["malicious"].add("Label_Yphish")
        self.state.messages["malicious"].remove("INBOX")
        self.state.history["malicious"] += 1
        ActionExecution.objects.filter(pk=action.pk).update(
            state=ActionExecution.State.RUNNING,
            lease_expires_at=self.now - timedelta(seconds=1),
            executed_at=self.now - timedelta(minutes=1),
        )
        self.assertEqual(reconcile_response_work(), 1)
        self.assertTrue(self._execute(action))
        action.refresh_from_db()
        self.assertEqual(action.state, ActionExecution.State.SUCCEEDED)
        self.assertEqual(self.state.modifications, [])

    def test_concurrent_user_change_blocks_modify(self):
        action = self._prepare()
        self.state.messages["malicious"].remove("INBOX")
        self.state.history["malicious"] += 1
        self.assertTrue(self._execute(action))
        action.refresh_from_db()
        self.assertEqual(action.state, ActionExecution.State.FAILED)
        self.assertEqual(action.error_code, "concurrent_tracked_change")
        self.assertEqual(self.state.modifications, [])

    def test_missing_message_is_recorded_and_not_retried(self):
        action = self._prepare()
        self.state.messages.pop("malicious")
        self.assertTrue(self._execute(action))
        action.refresh_from_db()
        self.case.refresh_from_db()
        self.assertEqual(action.error_code, "gmail_http_404")
        self.assertEqual(action.state, ActionExecution.State.FAILED)
        self.assertIsNotNone(self.case.gmail_deleted_at)

    def test_rate_limit_and_circuit_breaker(self):
        second, _ = self._qualified_case("second")
        self.state.add("second", {"INBOX"})
        first_action = self._prepare()
        second_action = self._prepare(second)
        with override_settings(GMAIL_RESPONSE_MAILBOX_HOURLY_LIMIT=1):
            self.assertTrue(self._execute(first_action))
            self.assertFalse(self._execute(second_action))
        second_action.refresh_from_db()
        self.assertEqual(second_action.state, ActionExecution.State.AUTHORIZED)
        self.assertIsNotNone(second_action.next_retry_at)
        self.assertEqual([item[0] for item in self.state.modifications], ["malicious"])

        ActionExecution.objects.filter(pk=second_action.pk).update(next_retry_at=self.now - timedelta(seconds=1))
        self.state.fail_before = GmailError("gmail_http_403")
        with override_settings(GMAIL_RESPONSE_FAILURE_THRESHOLD=1,
                               GMAIL_RESPONSE_MAILBOX_HOURLY_LIMIT=2):
            self.assertTrue(self._execute(second_action))
        self.assertTrue(ResponseControl.objects.filter(mailbox=self.mailbox,
                                                      circuit_open_until__gt=timezone.now()).exists())

    def test_synthetic_indicator_and_incomplete_investigation_never_qualify(self):
        synthetic, _ = self._qualified_case("synthetic", operational=False)
        self.assertFalse(evaluate_case(synthetic).qualifies)
        self.assertIsNone(self._prepare(synthetic))
        InvestigationRun.objects.filter(case=self.case).update(stopping_reason="round_budget_exhausted")
        self.assertFalse(evaluate_case(self.case).qualifies)

    def test_response_credential_requires_exact_two_scopes(self):
        with override_settings(GOOGLE_RESPONSE_SERVICE_ACCOUNT_FILE="response.json",
                               GOOGLE_INGESTION_SERVICE_ACCOUNT_FILE="ingest.json"):
            credentials = MagicMock()
            credentials.with_subject.return_value = credentials
            with (patch("builtins.open", mock_open(read_data='{"client_id": "response-client"}')),
                  patch("core.gmail_credentials.service_account.Credentials.from_service_account_info",
                        return_value=credentials) as create):
                result = WorkspaceDelegatedCredentialProvider().for_mailbox(
                    self.mailbox.pk, CredentialPurpose.RESPONSE,
                )
            self.assertIs(result, credentials)
            self.assertEqual(create.call_args.kwargs["scopes"],
                             [ADMIN_RESPONSE_SCOPE, LABELS_SCOPE])
            credentials.with_subject.assert_called_once_with(self.mailbox.address)

    def test_gmail_client_modifies_only_the_case_message(self):
        service = MagicMock()
        service.users.return_value.labels.return_value.list.return_value.execute.return_value = {
            "labels": [{"id": "Label_Yphish", "name": SUSPICIOUS_LABEL, "type": "user"}],
        }
        service.users.return_value.messages.return_value.modify.return_value.execute.return_value = {
            "id": "malicious",
        }
        provider = MagicMock()
        client = GmailResponseClient(self.mailbox.pk, credential_provider=provider,
                                     service=service)
        client.modify_case(self.case.pk, add_label_ids=["Label_Yphish"],
                           remove_label_ids=["INBOX"], yphish_label_id="Label_Yphish")
        provider.for_mailbox.assert_called_once_with(self.mailbox.pk, CredentialPurpose.RESPONSE)
        service.users.return_value.messages.return_value.modify.assert_called_once_with(
            userId=self.mailbox.address, id="malicious",
            body={"addLabelIds": ["Label_Yphish"], "removeLabelIds": ["INBOX"]},
        )
        service.users.return_value.threads.assert_not_called()
        service.users.return_value.messages.return_value.trash.assert_not_called()

    def test_missing_custom_label_is_created_and_recorded(self):
        service = MagicMock()
        service.users.return_value.labels.return_value.list.return_value.execute.return_value = {
            "labels": [],
        }
        service.users.return_value.labels.return_value.create.return_value.execute.return_value = {
            "id": "New_Label",
        }
        client = GmailResponseClient(self.mailbox.pk, credential_provider=MagicMock(), service=service)
        self.assertEqual(client.ensure_suspicious_label(), "New_Label")
        self.mailbox.refresh_from_db()
        self.assertEqual(self.mailbox.gmail_label_id, "New_Label")
        service.users.return_value.labels.return_value.create.assert_called_once_with(
            userId=self.mailbox.address,
            body={"name": SUSPICIOUS_LABEL, "labelListVisibility": "labelShow",
                  "messageListVisibility": "show"},
        )

    def test_cross_mailbox_case_and_forbidden_delta_are_rejected(self):
        other = Mailbox.objects.create(
            organization=self.org, address="other@example.com", state=Mailbox.State.ACTIVE,
            gmail_sync_status=Mailbox.GmailSyncStatus.READY,
            gmail_enrolled_at=self.now, gmail_enrollment_history_id="101",
            gmail_response_enabled=True,
        )
        service = MagicMock()
        client = GmailResponseClient(other.pk, credential_provider=MagicMock(), service=service)
        with self.assertRaisesMessage(GmailError, "gmail_response_case_outside_mailbox"):
            client.modify_case(self.case.pk, add_label_ids=["Label_Yphish"],
                               remove_label_ids=[], yphish_label_id="Label_Yphish")
        own = GmailResponseClient(self.mailbox.pk, credential_provider=MagicMock(), service=service)
        with self.assertRaisesMessage(GmailError, "gmail_response_changes_invalid"):
            own.modify_case(self.case.pk, add_label_ids=["SPAM"],
                            remove_label_ids=[], yphish_label_id="Label_Yphish")
        service.users.return_value.messages.return_value.modify.assert_not_called()

    def test_response_credentials_require_mailbox_enablement_before_impersonation(self):
        self.mailbox.gmail_response_enabled = False
        self.mailbox.save(update_fields=["gmail_response_enabled"])
        with patch("builtins.open") as read_key:
            with self.assertRaisesMessage(Exception, "gmail_response_not_enabled"):
                WorkspaceDelegatedCredentialProvider().for_mailbox(
                    self.mailbox.pk, CredentialPurpose.RESPONSE,
                )
        read_key.assert_not_called()
