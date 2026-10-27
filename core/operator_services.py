"""Audited, tenant-scoped operator writes; never touches a Gmail credential."""

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .gmail_credentials import ADMIN_RESPONSE_SCOPE, LABELS_SCOPE
from .models import ActionExecution, AuditEvent, EmailCase, Feedback, Mailbox, Membership
from .response_runtime import APPLY_PREFIX


MANAGER_ROLES = {Membership.Role.OWNER, Membership.Role.ADMIN}
REVIEW_ROLES = MANAGER_ROLES | {Membership.Role.ANALYST}


class OperatorDenied(PermissionError):
    pass


class OperatorInvalid(ValueError):
    pass


def _require_role(actor, organization, roles):
    if not actor.is_authenticated or not actor.is_active or not Membership.objects.filter(
        user=actor, organization=organization, organization__is_active=True,
        is_active=True, role__in=roles,
    ).exists():
        raise OperatorDenied("Active organization membership and role required")


def _reason(value):
    value = (value or "").strip()
    if not 10 <= len(value) <= 1000:
        raise OperatorInvalid("Provide a reason of 10 to 1000 characters.")
    return value


def _audit(*, organization, actor, case=None, event_type, subject, details):
    return AuditEvent.objects.create(
        organization=organization, case=case, actor=actor, event_type=event_type,
        subject_type=type(subject).__name__, subject_id=subject.pk,
        occurred_at=timezone.now(), details=details,
    )


@transaction.atomic
def submit_feedback(*, actor, case_id, proposed_verdict, reason):
    case = EmailCase.objects.select_for_update().select_related("organization").get(pk=case_id)
    _require_role(actor, case.organization, REVIEW_ROLES)
    if proposed_verdict not in {
        EmailCase.Verdict.LEGITIMATE, EmailCase.Verdict.SUSPICIOUS,
        EmailCase.Verdict.MALICIOUS,
    }:
        raise OperatorInvalid("Select a proposed verdict.")
    feedback = Feedback.objects.create(
        organization=case.organization, case=case, submitted_by=actor,
        proposed_verdict=proposed_verdict, reason=_reason(reason),
        state=Feedback.State.SUBMITTED,
    )
    _audit(organization=case.organization, actor=actor, case=case,
           event_type="feedback.submitted", subject=feedback,
           details={"proposed_verdict": proposed_verdict, "reason": feedback.reason})
    return feedback


@transaction.atomic
def review_feedback(*, actor, feedback_id, decision, reason):
    feedback = Feedback.objects.select_for_update().select_related("organization", "case").get(pk=feedback_id)
    _require_role(actor, feedback.organization, MANAGER_ROLES)
    if feedback.state != Feedback.State.SUBMITTED:
        raise OperatorInvalid("This feedback has already been reviewed.")
    if decision not in {"approve", "reject"}:
        raise OperatorInvalid("Select approve or reject.")
    review_reason = _reason(reason)
    feedback.state = Feedback.State.REVIEWED if decision == "approve" else Feedback.State.REJECTED
    feedback.reviewed_by = actor
    feedback.reviewed_at = timezone.now()
    feedback.save(update_fields=["state", "reviewed_by", "reviewed_at"])
    _audit(organization=feedback.organization, actor=actor, case=feedback.case,
           event_type=f"feedback.{feedback.state}", subject=feedback,
           details={"proposed_verdict": feedback.proposed_verdict, "reason": review_reason})
    # Reviewed legitimate feedback is a durable restoration trigger for Beat.
    # It never changes the case verdict or a classifier training set here.
    return feedback


@transaction.atomic
def request_restoration(*, actor, case_id):
    case = EmailCase.objects.select_for_update().select_related("organization").get(pk=case_id)
    _require_role(actor, case.organization, MANAGER_ROLES)
    if not Feedback.objects.filter(
        case=case, state=Feedback.State.REVIEWED,
        proposed_verdict=EmailCase.Verdict.LEGITIMATE,
    ).exists():
        raise OperatorInvalid("A reviewed legitimate correction is required.")
    source = ActionExecution.objects.filter(
        case=case, organization=case.organization,
        idempotency_key=APPLY_PREFIX + str(case.pk),
        state=ActionExecution.State.SUCCEEDED,
    ).first()
    if not source:
        raise OperatorInvalid("There is no successful Yphish action to restore.")
    restoration = ActionExecution.objects.filter(
        case=case, action=ActionExecution.Action.RESTORE,
    ).order_by("-requested_at").first()
    if restoration:
        if restoration.state == ActionExecution.State.SUCCEEDED:
            raise OperatorInvalid("This message was already restored.")
        if restoration.state in {ActionExecution.State.FAILED, ActionExecution.State.SKIPPED}:
            raise OperatorInvalid("The recorded restoration failed or was skipped; inspect its action history.")
    if (not settings.GMAIL_RESPONSE_ENABLED or not case.organization.gmail_response_enabled
            or not case.mailbox.gmail_response_enabled):
        raise OperatorInvalid("Response is paused for this organization or mailbox.")
    if not AuditEvent.objects.filter(
        organization=case.organization, case=case, event_type="response.restoration_requested",
        subject_id=source.pk,
    ).exists():
        _audit(organization=case.organization, actor=actor, case=case,
               event_type="response.restoration_requested", subject=source,
               details={"gmail_message_id": case.gmail_message_id})
    return case


@transaction.atomic
def update_mailbox_response(*, actor, mailbox_id, enabled, remove_inbox):
    mailbox = Mailbox.objects.select_for_update().select_related("organization").get(pk=mailbox_id)
    _require_role(actor, mailbox.organization, MANAGER_ROLES)
    if remove_inbox and not enabled:
        raise OperatorInvalid("Enable response before enabling INBOX removal.")
    if enabled:
        organization = mailbox.organization
        if (mailbox.provider != Mailbox.Provider.GMAIL or mailbox.state != Mailbox.State.ACTIVE
                or mailbox.gmail_sync_status != Mailbox.GmailSyncStatus.READY
                or not mailbox.gmail_enrolled_at or not mailbox.gmail_enrollment_history_id
                or not organization.gmail_access_verified_at
                or not organization.gmail_response_enabled
                or organization.gmail_response_scope != ADMIN_RESPONSE_SCOPE
                or organization.gmail_response_labels_scope != LABELS_SCOPE
                or not organization.gmail_response_service_account_client_id
                or organization.gmail_response_service_account_client_id == organization.gmail_service_account_client_id):
            raise OperatorInvalid("Complete Gmail enrollment and separate response authorization first.")
    if (mailbox.gmail_response_enabled, mailbox.gmail_response_remove_inbox) != (enabled, remove_inbox):
        mailbox.gmail_response_enabled = enabled
        mailbox.gmail_response_remove_inbox = remove_inbox
        mailbox.save(update_fields=["gmail_response_enabled", "gmail_response_remove_inbox", "updated_at"])
        _audit(organization=mailbox.organization, actor=actor,
               event_type="response.mailbox_settings_changed", subject=mailbox,
               details={"enabled": enabled, "remove_inbox": remove_inbox})
    return mailbox
