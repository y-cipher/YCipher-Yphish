"""Transactional, idempotent write boundaries for Module 1.

Call these functions from future ingestion, analysis, and response workers. They do
not contact a mail provider or authorize an action.
"""

from django.db import transaction
from django.utils import timezone

from .models import ActionExecution, AnalysisRun, Artifact, AuditEvent, EmailCase, Evidence, Mailbox


class InvalidRelationship(ValueError):
    """A referenced row does not belong to the requested organization or case."""


class InvalidIdempotencyKey(ValueError):
    """A stable, nonblank request identifier is required."""


class IdempotencyConflict(ValueError):
    """A key was already used for a different request."""


class InvalidActionTransition(ValueError):
    """The requested failure state cannot follow the stored action state."""


def _require_key(value, *, max_length):
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise InvalidIdempotencyKey(f"Expected a nonblank string of at most {max_length} characters")
    return value


def _require_mailbox(organization, mailbox):
    if not Mailbox.objects.filter(pk=mailbox.pk, organization_id=organization.pk).exists():
        raise InvalidRelationship("Mailbox does not belong to the organization")


def _require_case(organization, case):
    if not EmailCase.objects.filter(pk=case.pk, organization_id=organization.pk).exists():
        raise InvalidRelationship("Case does not belong to the organization")


def _require_case_child(model, organization, case, child, label):
    if child is not None and not model.objects.filter(
        pk=child.pk, organization_id=organization.pk, case_id=case.pk
    ).exists():
        raise InvalidRelationship(f"{label} does not belong to the case and organization")


def _audit(organization, case, event_type, subject):
    AuditEvent.objects.create(
        organization=organization,
        case=case,
        event_type=event_type,
        subject_type=subject._meta.model_name,
        subject_id=subject.pk,
        occurred_at=timezone.now(),
    )


@transaction.atomic
def create_email_case(
    *, organization, mailbox, gmail_message_id,
    gmail_thread_id="", internet_message_id="", subject="", sender_address="", received_at=None,
):
    """Return ``(case, created)`` for one Gmail message in one mailbox.

    Retries return the original row without changing metadata or processing state.
    The nonblank key and database unique constraint settle concurrent inserts.
    """
    immutable_id = _require_key(gmail_message_id, max_length=512)
    _require_mailbox(organization, mailbox)
    if mailbox.provider != Mailbox.Provider.GMAIL:
        raise InvalidRelationship("Mailbox is not enrolled for Gmail")
    case, created = EmailCase.objects.get_or_create(
        organization=organization,
        mailbox=mailbox,
        gmail_message_id=immutable_id,
        defaults={
            "provider_immutable_id": immutable_id,
            "gmail_thread_id": gmail_thread_id,
            "internet_message_id": internet_message_id,
            "subject": subject,
            "sender_address": sender_address,
            "received_at": received_at,
        },
    )
    if created:
        _audit(organization, case, "case.created", case)
    return case, created


@transaction.atomic
def record_evidence(
    *, organization, case, idempotency_key, source, label, observed_at,
    state=Evidence.State.OBSERVED, trust=Evidence.Trust.UNTRUSTED,
    source_version="", details=None, analysis_run=None, artifact=None,
):
    """Return ``(evidence, created)``; reject conflicting reuse of its case key."""
    key = _require_key(idempotency_key, max_length=200)
    _require_case(organization, case)
    _require_case_child(AnalysisRun, organization, case, analysis_run, "Analysis run")
    _require_case_child(Artifact, organization, case, artifact, "Artifact")
    if observed_at is None or timezone.is_naive(observed_at):
        raise ValueError("observed_at must be timezone-aware")
    if source not in Evidence.Source.values or state not in Evidence.State.values or trust not in Evidence.Trust.values:
        raise ValueError("Invalid evidence source, state, or trust")
    if not label:
        raise ValueError("Evidence label is required")
    details = {} if details is None else details
    values = {
        "source": source,
        "label": label,
        "observed_at": observed_at,
        "state": state,
        "trust": trust,
        "source_version": source_version,
        "details": details,
        "analysis_run_id": analysis_run.pk if analysis_run else None,
        "artifact_id": artifact.pk if artifact else None,
    }
    evidence, created = Evidence.objects.get_or_create(
        organization=organization, case=case, idempotency_key=key, defaults=values
    )
    if not created and any(getattr(evidence, name) != value for name, value in values.items()):
        raise IdempotencyConflict("Evidence key is already bound to different data")
    if created:
        _audit(organization, case, "evidence.recorded", evidence)
    return evidence, created


@transaction.atomic
def create_action_execution(
    *, organization, case, idempotency_key, action, analysis_run=None,
    policy_version="", target=None, requested_at=None,
):
    """Return ``(execution, created)`` in the proposed state.

    This records intent only. Authorization and provider execution are later work.
    An organization-wide key cannot be reused with different case/action inputs.
    """
    key = _require_key(idempotency_key, max_length=200)
    _require_case(organization, case)
    _require_case_child(AnalysisRun, organization, case, analysis_run, "Analysis run")
    if action not in ActionExecution.Action.values:
        raise ValueError("Invalid action type")
    target = {} if target is None else target
    if requested_at is None:
        requested_at = timezone.now()
    elif timezone.is_naive(requested_at):
        raise ValueError("requested_at must be timezone-aware")
    values = {
        "case_id": case.pk,
        "action": action,
        "analysis_run_id": analysis_run.pk if analysis_run else None,
        "policy_version": policy_version,
        "target": target,
    }
    execution, created = ActionExecution.objects.get_or_create(
        organization=organization,
        idempotency_key=key,
        defaults={**values, "requested_at": requested_at},
    )
    if not created and any(getattr(execution, name) != value for name, value in values.items()):
        raise IdempotencyConflict("Action key is already bound to a different request")
    if created:
        _audit(organization, case, "action.proposed", execution)
    return execution, created


@transaction.atomic
def mark_action_failure(*, execution, error_code, uncertain=False):
    """Record a definite failure or an outcome that requires reconciliation.

    ``failed`` means the attempt is known not to have succeeded. ``reconciling``
    means the external outcome is unknown; callers must inspect provider state
    before another attempt. Repeating the same transition returns the same row.
    """
    code = _require_key(error_code, max_length=100)
    current = ActionExecution.objects.select_for_update().get(pk=execution.pk)
    next_state = ActionExecution.State.RECONCILING if uncertain else ActionExecution.State.FAILED
    if current.state == next_state and current.error_code == code:
        return current
    allowed = (
        {ActionExecution.State.RUNNING}
        if uncertain else
        {ActionExecution.State.RUNNING, ActionExecution.State.RECONCILING}
    )
    if current.state not in allowed:
        raise InvalidActionTransition(f"Cannot mark {current.state} as {next_state}")
    current.state = next_state
    current.error_code = code
    current.save(update_fields=["state", "error_code"])
    _audit(current.organization, current.case, f"action.{next_state}", current)
    return current


@transaction.atomic
def mark_action_skipped(*, execution, reason_code):
    """Record that a proposed or authorized action was never attempted."""
    code = _require_key(reason_code, max_length=100)
    current = ActionExecution.objects.select_for_update().get(pk=execution.pk)
    if current.state == ActionExecution.State.SKIPPED and current.error_code == code:
        return current
    if current.state not in {ActionExecution.State.PROPOSED, ActionExecution.State.AUTHORIZED}:
        raise InvalidActionTransition(f"Cannot skip an action in state {current.state}")
    current.state = ActionExecution.State.SKIPPED
    current.error_code = code
    current.save(update_fields=["state", "error_code"])
    _audit(current.organization, current.case, "action.skipped", current)
    return current
