"""PostgreSQL-backed dashboard boundaries and operator write tests."""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .gmail_credentials import ADMIN_RESPONSE_SCOPE, LABELS_SCOPE
from .models import (
    ActionExecution, AnalysisRun, AuditEvent, EmailCase, Evidence, Feedback,
    InvestigationRun,
    Mailbox, Membership, Organization,
)
from .response_policy import POLICY_VERSION
from .response_runtime import APPLY_PREFIX, RESTORE_PREFIX


class DashboardTests(TestCase):
    def setUp(self):
        now = timezone.now()
        users = get_user_model()
        self.owner = users.objects.create_user("dash_owner")
        self.analyst = users.objects.create_user("dash_analyst")
        self.viewer = users.objects.create_user("dash_viewer")
        self.outsider = users.objects.create_user("dash_outsider")
        self.org = Organization.objects.create(
            name="North", slug="north", gmail_access_verified_at=now,
            gmail_service_account_client_id="read-client", gmail_response_enabled=True,
            gmail_response_service_account_client_id="write-client",
            gmail_response_scope=ADMIN_RESPONSE_SCOPE,
            gmail_response_labels_scope=LABELS_SCOPE,
        )
        self.other = Organization.objects.create(name="South", slug="south")
        for user, role in ((self.owner, Membership.Role.OWNER),
                           (self.analyst, Membership.Role.ANALYST),
                           (self.viewer, Membership.Role.VIEWER)):
            Membership.objects.create(organization=self.org, user=user, role=role)
        self.mailbox = Mailbox.objects.create(
            organization=self.org, address="team@example.com", state=Mailbox.State.ACTIVE,
            gmail_sync_status=Mailbox.GmailSyncStatus.READY,
            gmail_enrolled_at=now, gmail_enrollment_history_id="100", gmail_history_id="200",
            gmail_last_synced_at=now, gmail_label_id="Label_Yphish",
        )
        self.other_mailbox = Mailbox.objects.create(
            organization=self.other, address="private@other.example",
        )
        self.case = EmailCase.objects.create(
            organization=self.org, mailbox=self.mailbox,
            gmail_message_id="gmail-A", provider_immutable_id="gmail-A",
            gmail_thread_id="thread-shared", subject="<script>alert(1)</script> Invoice",
            sender_address="person@sender.example", state=EmailCase.State.ANALYZED,
            gmail_initial_label_ids=["INBOX", "UNREAD"],
            gmail_label_ids=["INBOX", "UNREAD"],
        )
        self.other_case = EmailCase.objects.create(
            organization=self.other, mailbox=self.other_mailbox,
            gmail_message_id="gmail-secret", provider_immutable_id="gmail-secret",
            subject="Hidden tenant subject", state=EmailCase.State.QUEUED,
        )
        self.queue_patch = patch("core.dashboard_views._queue_health",
                                 return_value={"status": "ready", "workers": 1})
        self.queue_patch.start()
        self.addCleanup(self.queue_patch.stop)

    def _url(self, name, *args):
        return reverse(name, args=[self.org.slug, *args])

    def _successful_apply(self):
        return ActionExecution.objects.create(
            organization=self.org, case=self.case,
            idempotency_key=APPLY_PREFIX + str(self.case.pk),
            action=ActionExecution.Action.MOVE,
            policy_version=POLICY_VERSION, state=ActionExecution.State.SUCCEEDED,
            requested_at=timezone.now(), verified_at=timezone.now(),
            target={"gmail_message_id": self.case.gmail_message_id,
                    "before_label_ids": ["INBOX", "UNREAD"],
                    "add_label_ids": ["Label_Yphish"], "remove_label_ids": ["INBOX"],
                    "yphish_label_id": "Label_Yphish", "yphish_added_label": True,
                    "yphish_removed_inbox": True},
            result={"after_label_ids": ["Label_Yphish", "UNREAD"], "verified": True},
        )

    def test_login_membership_and_organization_isolation(self):
        url = self._url("dashboard_case_list")
        self.assertEqual(self.client.get(url).status_code, 302)
        self.client.force_login(self.outsider)
        self.assertEqual(self.client.get(url).status_code, 404)
        self.client.force_login(self.viewer)
        self.assertEqual(self.client.get(self._url("dashboard_overview")).status_code, 200)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invoice")
        self.assertNotContains(response, "Hidden tenant subject")
        self.assertEqual(self.client.get(self._url("dashboard_case_detail", self.other_case.pk)).status_code, 404)
        self.assertEqual(self.client.get(reverse("dashboard_overview", args=[self.other.slug])).status_code, 404)
        response = self.client.get(url, {"q": "Hidden tenant subject"})
        self.assertContains(response, "No matching messages")

    def test_case_filters_and_pagination_remain_scoped(self):
        self.client.force_login(self.viewer)
        url = self._url("dashboard_case_list")
        self.assertContains(self.client.get(url, {"mailbox": str(self.mailbox.pk), "label": "INBOX"}), "Invoice")
        self.assertContains(self.client.get(url, {"label": "TRASH"}), "No matching messages")
        self.assertContains(self.client.get(url, {"state": EmailCase.State.QUEUED}), "No matching messages")
        self.assertContains(self.client.get(url, {"mailbox": str(self.other_mailbox.pk)}), "filters are invalid")
        for number in range(26):
            EmailCase.objects.create(
                organization=self.org, mailbox=self.mailbox,
                gmail_message_id=f"page-{number}", provider_immutable_id=f"page-{number}",
            )
        page = self.client.get(url, {"page": 2})
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "Page 2 of 2")

    def test_detail_escapes_content_and_exposes_coverage_and_versions(self):
        AnalysisRun.objects.create(
            organization=self.org, case=self.case, attempt=1,
            state=AnalysisRun.State.FAILED, engine_version="rules-v1",
            error_code="artifact_unavailable",
        )
        Evidence.objects.create(
            organization=self.org, case=self.case, idempotency_key="unavailable-evidence",
            source=Evidence.Source.RULE, state=Evidence.State.UNAVAILABLE,
            trust=Evidence.Trust.UNTRUSTED, label="<img src=x onerror=alert(1)>",
            details={"text": "<script>bad</script>"}, observed_at=timezone.now(),
        )
        self.client.force_login(self.analyst)
        with patch("core.dashboard_views._body_preview",
                   return_value=("<script>message body</script>", "Bounded preview")):
            response = self.client.get(self._url("dashboard_case_detail", self.case.pk))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "&lt;script&gt;message body&lt;/script&gt;")
        self.assertNotContains(response, "<script>message body</script>")
        self.assertContains(response, "&lt;img src=x onerror=alert(1)&gt;")
        self.assertContains(response, "Some evidence or analysis is incomplete")
        self.assertContains(response, "rules-v1")
        self.assertContains(response, "At first ingestion")
        self.assertContains(response, "INBOX")
        self.assertEqual(response["Cache-Control"].find("no-store") >= 0, True)
        self.client.force_login(self.viewer)
        response = self.client.get(self._url("dashboard_case_detail", self.case.pk))
        self.assertContains(response, "requires an analyst or manager role")

    def test_viewer_cannot_read_investigation_or_audit_details(self):
        analysis = AnalysisRun.objects.create(
            organization=self.org, case=self.case, attempt=1,
            state=AnalysisRun.State.SUCCEEDED, engine_version="rules-v1",
        )
        InvestigationRun.objects.create(
            organization=self.org, mailbox=self.mailbox, case=self.case,
            analysis_run=analysis, policy_version="explicit-v1",
            state=InvestigationRun.State.COMPLETED, stopping_reason="private_trace_marker",
        )
        AuditEvent.objects.create(
            organization=self.org, case=self.case, actor=self.analyst,
            event_type="private.audit", details={"marker": "private_audit_marker"},
            occurred_at=timezone.now(),
        )
        self.client.force_login(self.viewer)
        viewer_response = self.client.get(self._url("dashboard_case_detail", self.case.pk))
        self.assertNotContains(viewer_response, "private_trace_marker")
        self.assertNotContains(viewer_response, "private_audit_marker")
        self.client.force_login(self.analyst)
        analyst_response = self.client.get(self._url("dashboard_case_detail", self.case.pk))
        self.assertContains(analyst_response, "private_trace_marker")
        self.assertContains(analyst_response, "private_audit_marker")

    def test_settings_show_expired_authorization_and_missing_label(self):
        self.mailbox.gmail_sync_status = Mailbox.GmailSyncStatus.AUTHORIZATION_FAILED
        self.mailbox.gmail_label_id = ""
        self.mailbox.gmail_response_enabled = True
        self.mailbox.save(update_fields=["gmail_sync_status", "gmail_label_id", "gmail_response_enabled"])
        self.client.force_login(self.owner)
        response = self.client.get(self._url("dashboard_settings"))
        self.assertContains(response, "authorization failed")
        self.assertContains(response, "label ID is not recorded")
        data = {f"{self.mailbox.pk}-enabled": "on"}
        self.client.post(self._url("dashboard_response_settings", self.mailbox.pk), data)
        self.mailbox.refresh_from_db()
        self.assertTrue(self.mailbox.gmail_response_enabled)
        self.assertFalse(AuditEvent.objects.filter(event_type="response.mailbox_settings_changed").exists())

    def test_manager_can_enable_message_response_with_audit(self):
        self.client.force_login(self.viewer)
        url = self._url("dashboard_response_settings", self.mailbox.pk)
        data = {f"{self.mailbox.pk}-enabled": "on",
                f"{self.mailbox.pk}-remove_inbox": "on"}
        self.assertEqual(self.client.post(url, data).status_code, 403)
        self.client.force_login(self.owner)
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 302)
        self.mailbox.refresh_from_db()
        self.assertTrue(self.mailbox.gmail_response_enabled)
        self.assertTrue(self.mailbox.gmail_response_remove_inbox)
        self.assertTrue(AuditEvent.objects.filter(
            organization=self.org, actor=self.owner,
            event_type="response.mailbox_settings_changed",
            subject_id=self.mailbox.pk,
        ).exists())

    def test_role_boundaries_and_feedback_audit_without_model_training(self):
        submit_url = self._url("dashboard_feedback_submit", self.case.pk)
        self.client.force_login(self.viewer)
        self.assertEqual(self.client.post(submit_url, {"proposed_verdict": "legitimate",
                                                       "reason": "This is a legitimate invoice"}).status_code, 403)
        self.client.force_login(self.analyst)
        self.client.post(submit_url, {"proposed_verdict": "legitimate", "reason": "short"})
        self.assertFalse(Feedback.objects.exists())
        self.client.post(submit_url, {"proposed_verdict": "legitimate",
                                      "reason": "Verified this supplier invoice with the team."})
        feedback = Feedback.objects.get()
        self.assertEqual(feedback.submitted_by, self.analyst)
        self.assertEqual(feedback.state, Feedback.State.SUBMITTED)
        self.assertEqual(self.case.verdict, EmailCase.Verdict.UNKNOWN)
        self.assertTrue(AuditEvent.objects.filter(event_type="feedback.submitted",
                                                  actor=self.analyst, case=self.case).exists())
        review_url = self._url("dashboard_feedback_review", feedback.pk)
        self.assertEqual(self.client.post(review_url, {"decision": "approve",
                                                       "reason": "Reviewed with finance operations."}).status_code, 403)
        self.client.force_login(self.owner)
        with patch("core.dashboard_views.prepare_gmail_restoration.delay") as enqueue:
            self.client.post(review_url, {"decision": "approve",
                                          "reason": "Reviewed with finance operations."})
        feedback.refresh_from_db()
        self.assertEqual(feedback.state, Feedback.State.REVIEWED)
        self.assertEqual(feedback.reviewed_by, self.owner)
        self.assertEqual(self.case.verdict, EmailCase.Verdict.UNKNOWN)
        enqueue.assert_called_once_with(str(self.case.pk))
        self.assertTrue(AuditEvent.objects.filter(event_type="feedback.reviewed",
                                                  actor=self.owner, case=self.case).exists())

    def test_feedback_post_requires_csrf(self):
        strict_client = Client(enforce_csrf_checks=True)
        strict_client.force_login(self.analyst)
        response = strict_client.post(
            self._url("dashboard_feedback_submit", self.case.pk),
            {"proposed_verdict": "legitimate", "reason": "Verified with the sender."},
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Feedback.objects.exists())

    def test_restoration_requires_review_and_only_queues_worker(self):
        source = self._successful_apply()
        Mailbox.objects.filter(pk=self.mailbox.pk).update(gmail_response_enabled=True)
        self.client.force_login(self.owner)
        url = self._url("dashboard_restore", self.case.pk)
        with patch("core.dashboard_views.prepare_gmail_restoration.delay") as enqueue:
            self.client.post(url)
            enqueue.assert_not_called()
            Feedback.objects.create(
                organization=self.org, case=self.case,
                proposed_verdict=EmailCase.Verdict.LEGITIMATE,
                reason="Verified with sender", state=Feedback.State.REVIEWED,
                submitted_by=self.analyst, reviewed_by=self.owner,
                reviewed_at=timezone.now(),
            )
            self.client.post(url)
            self.client.post(url)
            self.assertEqual(enqueue.call_count, 2)
            ActionExecution.objects.create(
                organization=self.org, case=self.case,
                idempotency_key=RESTORE_PREFIX + str(source.pk),
                action=ActionExecution.Action.RESTORE,
                policy_version=POLICY_VERSION, state=ActionExecution.State.FAILED,
                error_code="gmail_response_label_changed", requested_at=timezone.now(),
            )
            self.client.post(url)
            self.assertEqual(enqueue.call_count, 2)
        self.assertEqual(AuditEvent.objects.filter(
            event_type="response.restoration_requested", actor=self.owner,
            subject_id=source.pk,
        ).count(), 1)
        self.assertFalse(ActionExecution.objects.filter(action=ActionExecution.Action.RESTORE,
                                                        state=ActionExecution.State.SUCCEEDED).exists())
        self.client.force_login(self.analyst)
        self.assertEqual(self.client.post(url).status_code, 403)

    def test_response_filters_and_status_do_not_claim_thread_containment(self):
        self._successful_apply()
        EmailCase.objects.create(
            organization=self.org, mailbox=self.mailbox,
            gmail_message_id="untouched", provider_immutable_id="untouched",
            subject="Unchanged message", state=EmailCase.State.ANALYZED,
        )
        self.client.force_login(self.viewer)
        response = self.client.get(self._url("dashboard_case_list"), {"response": "inbox_removed"})
        self.assertContains(response, "Labeled; INBOX removed")
        self.assertNotContains(response, "conversation contained")
        self.assertContains(self.client.get(self._url("dashboard_case_list"),
                                            {"response": "none"}), "Unchanged message")
        self.assertContains(self.client.get(self._url("dashboard_case_list"),
                                            {"response": "restored"}), "No matching messages")
        ActionExecution.objects.create(
            organization=self.org, case=self.case,
            idempotency_key=RESTORE_PREFIX + "test", action=ActionExecution.Action.RESTORE,
            policy_version=POLICY_VERSION, state=ActionExecution.State.SUCCEEDED,
            requested_at=timezone.now(), verified_at=timezone.now(),
            target={"add_label_ids": ["INBOX"], "remove_label_ids": ["Label_Yphish"]},
        )
        detail = self.client.get(self._url("dashboard_case_detail", self.case.pk))
        self.assertContains(detail, "Yphish changes restored")
