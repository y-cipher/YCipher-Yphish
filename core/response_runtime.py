"""Durable message-level Gmail label response with conservative reconciliation."""

from datetime import timedelta
from uuid import uuid4

from django.conf import settings
from django.db import transaction
from django.db.models import Exists, OuterRef, Q
from django.utils import timezone

from .gmail import GmailClient, GmailError
from .gmail_credentials import CredentialProviderError, enrolled_mailbox
from .gmail_response import GmailResponseClient
from .models import (
    ActionExecution, AuditEvent, EmailCase, Evidence, Feedback, Mailbox,
    Organization, ResponseControl,
)
from .response_policy import POLICY_VERSION, evaluate_case
from .services import create_action_execution, mark_action_skipped


APPLY_PREFIX = f"gmail-response:apply:{POLICY_VERSION}:"
RESTORE_PREFIX = f"gmail-response:restore:{POLICY_VERSION}:"
LABEL_BLOCKERS = {"SPAM", "TRASH"}


def _audit(action, event, details=None):
    AuditEvent.objects.create(
        organization_id=action.organization_id, case_id=action.case_id,
        event_type=event, subject_type="ActionExecution", subject_id=action.pk,
        occurred_at=timezone.now(), details=details or {},
    )


def _scoped_case(case_id):
    case = EmailCase.objects.select_related("mailbox__organization").get(pk=case_id)
    try:
        mailbox = enrolled_mailbox(case.mailbox_id)
    except CredentialProviderError as exc:
        raise GmailError(exc.code) from None
    if case.organization_id != mailbox.organization_id or case.gmail_deleted_at or not case.gmail_message_id:
        raise GmailError("gmail_response_case_outside_mailbox")
    return case, mailbox


def _live_labels(case, read_client):
    data = read_client.get_message_metadata(case.gmail_message_id)
    if data.get("id") != case.gmail_message_id:
        raise GmailError("gmail_response_message_id_mismatch")
    values = data.get("labelIds", [])
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        raise GmailError("gmail_response_labels_invalid")
    history = data.get("historyId", "")
    if history and not isinstance(history, str):
        raise GmailError("gmail_response_history_invalid")
    return set(values), history


def _clients(mailbox, read_client, write_client):
    return (read_client or GmailClient(mailbox.pk),
            write_client or GmailResponseClient(mailbox.pk))


def _circuit_open(mailbox):
    return ResponseControl.objects.filter(
        organization_id=mailbox.organization_id,
    ).filter(Q(mailbox__isnull=True) | Q(mailbox_id=mailbox.pk)).filter(
        circuit_open_until__gt=timezone.now(),
    ).exists()


def _preparation_failure(mailbox, code):
    with transaction.atomic():
        Organization.objects.select_for_update().get(pk=mailbox.organization_id)
        Mailbox.objects.select_for_update().get(pk=mailbox.pk)
        controls = [
            ResponseControl.objects.get_or_create(organization_id=mailbox.organization_id,
                                                  mailbox__isnull=True,
                                                  defaults={"mailbox": None})[0],
            ResponseControl.objects.get_or_create(organization_id=mailbox.organization_id,
                                                  mailbox_id=mailbox.pk)[0],
        ]
        for control in controls:
            control.consecutive_failures += 1
            if (code in {"gmail_http_401", "gmail_http_403", "gmail_authorization_failed",
                         "gmail_response_scope_invalid", "gmail_response_labels_scope_invalid"}
                    or control.consecutive_failures >= settings.GMAIL_RESPONSE_FAILURE_THRESHOLD):
                control.circuit_open_until = timezone.now() + timedelta(
                    seconds=settings.GMAIL_RESPONSE_CIRCUIT_SECONDS,
                )
            control.save(update_fields=["consecutive_failures", "circuit_open_until", "updated_at"])


def _target(case, before, history, add, remove, label_id, *, source_action_id="", evidence_ids=(),
            analysis_run_id="", remove_inbox_config=False):
    return {
        "gmail_message_id": case.gmail_message_id,
        "mailbox_id": str(case.mailbox_id),
        "before_label_ids": sorted(before),
        "history_id_before": history,
        "add_label_ids": sorted(add), "remove_label_ids": sorted(remove),
        "yphish_label_id": label_id,
        "yphish_added_label": label_id in add,
        "yphish_removed_inbox": "INBOX" in remove,
        "source_action_id": source_action_id,
        "evidence_ids": [str(item) for item in evidence_ids],
        "evidence_versions": {"rules": "rules-v1/1", "investigation": "explicit-v1"},
        "analysis_run_id": str(analysis_run_id) if analysis_run_id else "",
        "remove_inbox_config": remove_inbox_config,
    }


def prepare_response(case_id, *, read_client=None, write_client=None):
    """Create the exact action intent and snapshot before any message modify."""
    case, mailbox = _scoped_case(case_id)
    decision = evaluate_case(case)
    if not decision.qualifies:
        return None
    key = APPLY_PREFIX + str(case.pk)
    existing = ActionExecution.objects.filter(organization_id=case.organization_id,
                                              idempotency_key=key).first()
    if existing:
        return existing
    if ActionExecution.objects.filter(case=case, action=ActionExecution.Action.RESTORE,
                                      state=ActionExecution.State.SUCCEEDED).exists():
        return None  # A correction suppresses automatic reapplication.
    if _circuit_open(mailbox):
        return None
    try:
        read_client, write_client = _clients(mailbox, read_client, write_client)
        label_id = write_client.ensure_suspicious_label()
        before, history = _live_labels(case, read_client)
    except GmailError as exc:
        _preparation_failure(mailbox, exc.code)
        raise
    if before & LABEL_BLOCKERS:
        return None
    add = {label_id} - before
    remove = {"INBOX"} if decision.remove_inbox and "INBOX" in before else set()
    target = _target(case, before, history, add, remove, label_id,
                     evidence_ids=decision.evidence_ids,
                     analysis_run_id=decision.analysis_run_id,
                     remove_inbox_config=decision.remove_inbox)
    with transaction.atomic():
        case = EmailCase.objects.select_for_update().get(pk=case.pk)
        existing = ActionExecution.objects.filter(
            organization_id=case.organization_id, idempotency_key=key,
        ).first()
        if existing:
            return existing
        # Recheck the policy after the provider reads, before committing intent.
        if not evaluate_case(case).qualifies:
            return None
        analysis = case.analysis_runs.get(pk=decision.analysis_run_id)
        action, created = create_action_execution(
            organization=case.organization, case=case, analysis_run=analysis,
            idempotency_key=key,
            action=ActionExecution.Action.MOVE if decision.remove_inbox else ActionExecution.Action.CATEGORIZE,
            policy_version=POLICY_VERSION, target=target,
        )
        if created:
            if not add and not remove:
                action = mark_action_skipped(execution=action, reason_code="already_in_desired_state")
            else:
                action.state = ActionExecution.State.AUTHORIZED
                action.save(update_fields=["state"])
                _audit(action, "response.authorized", {"policy_version": POLICY_VERSION})
        return action


def prepare_restoration(case_id, *, read_client=None, write_client=None):
    case, mailbox = _scoped_case(case_id)
    if not Feedback.objects.filter(case=case, state=Feedback.State.REVIEWED,
                                   proposed_verdict=EmailCase.Verdict.LEGITIMATE).exists():
        return None
    source = ActionExecution.objects.filter(
        case=case, organization_id=case.organization_id,
        idempotency_key=APPLY_PREFIX + str(case.pk), state=ActionExecution.State.SUCCEEDED,
    ).first()
    if not source:
        return None
    key = RESTORE_PREFIX + str(source.pk)
    existing = ActionExecution.objects.filter(organization_id=case.organization_id,
                                              idempotency_key=key).first()
    if existing:
        return existing
    if _circuit_open(mailbox):
        return None
    try:
        read_client, write_client = _clients(mailbox, read_client, write_client)
        before, history = _live_labels(case, read_client)
        old_label_id = source.target.get("yphish_label_id", "")
        label_can_remove = bool(old_label_id and write_client.canonical_label_exists(old_label_id))
    except GmailError as exc:
        _preparation_failure(mailbox, exc.code)
        raise
    add = {"INBOX"} if (source.target.get("yphish_removed_inbox")
                        and "INBOX" not in before and not before & LABEL_BLOCKERS) else set()
    remove = {old_label_id} if (source.target.get("yphish_added_label")
                                and label_can_remove and old_label_id in before
                                and not before & LABEL_BLOCKERS) else set()
    target = _target(case, before, history, add, remove, old_label_id,
                     source_action_id=str(source.pk),
                     evidence_ids=source.target.get("evidence_ids", []),
                     analysis_run_id=source.analysis_run_id,
                     remove_inbox_config=source.target.get("remove_inbox_config", False))
    with transaction.atomic():
        case = EmailCase.objects.select_for_update().get(pk=case.pk)
        existing = ActionExecution.objects.filter(
            organization_id=case.organization_id, idempotency_key=key,
        ).first()
        if existing:
            return existing
        if not Feedback.objects.filter(
            case=case, state=Feedback.State.REVIEWED,
            proposed_verdict=EmailCase.Verdict.LEGITIMATE,
        ).exists():
            return None
        action, created = create_action_execution(
            organization=case.organization, case=case, analysis_run=source.analysis_run,
            idempotency_key=key, action=ActionExecution.Action.RESTORE,
            policy_version=POLICY_VERSION, target=target,
        )
        if created:
            if before & LABEL_BLOCKERS:
                action = mark_action_skipped(execution=action, reason_code="restoration_blocked_spam_trash")
            elif not add and not remove:
                action = mark_action_skipped(execution=action, reason_code="nothing_owned_to_restore")
            else:
                action.state = ActionExecution.State.AUTHORIZED
                action.save(update_fields=["state"])
                _audit(action, "response.restoration_authorized", {"source_action_id": str(source.pk)})
        return action


def _reserve_rate(action):
    now = timezone.now()
    # Lock parent rows in a stable order before get_or_create for concurrent tasks.
    Organization.objects.select_for_update().get(pk=action.organization_id)
    Mailbox.objects.select_for_update().get(pk=action.case.mailbox_id)
    controls = [
        (ResponseControl.objects.get_or_create(organization_id=action.organization_id,
                                               mailbox__isnull=True,
                                               defaults={"mailbox": None})[0],
         settings.GMAIL_RESPONSE_ORG_HOURLY_LIMIT),
        (ResponseControl.objects.get_or_create(organization_id=action.organization_id,
                                               mailbox_id=action.case.mailbox_id)[0],
         settings.GMAIL_RESPONSE_MAILBOX_HOURLY_LIMIT),
    ]
    for control, limit in controls:
        if control.circuit_open_until and control.circuit_open_until > now:
            return control.circuit_open_until, "circuit_open"
        if not control.window_started_at or now - control.window_started_at >= timedelta(hours=1):
            control.window_started_at = now
            control.operations_in_window = 0
        if control.operations_in_window >= limit:
            return control.window_started_at + timedelta(hours=1), "rate_limited"
    for control, _ in controls:
        control.operations_in_window += 1
        control.save(update_fields=["window_started_at", "operations_in_window", "updated_at"])
    return None, ""


def _record_result_health(action, *, success=False, auth_failure=False):
    now = timezone.now()
    with transaction.atomic():
        controls = list(ResponseControl.objects.select_for_update().filter(
            organization_id=action.organization_id,
        ).filter(Q(mailbox__isnull=True) | Q(mailbox_id=action.case.mailbox_id)))
        for control in controls:
            if success:
                control.consecutive_failures = 0
                control.circuit_open_until = None
            else:
                control.consecutive_failures += 1
                if auth_failure or control.consecutive_failures >= settings.GMAIL_RESPONSE_FAILURE_THRESHOLD:
                    control.circuit_open_until = now + timedelta(seconds=settings.GMAIL_RESPONSE_CIRCUIT_SECONDS)
            control.save(update_fields=["consecutive_failures", "circuit_open_until", "updated_at"])


def _finish(action_id, token, *, state, code="", after=None, history="",
            retry_after_seconds=None):
    with transaction.atomic():
        action = ActionExecution.objects.select_for_update().select_related("case").get(pk=action_id)
        if action.state != ActionExecution.State.RUNNING or action.lease_token != token:
            return False
        action.state = state
        action.error_code = code
        action.lease_token = None
        action.lease_expires_at = None
        backoff = min(3600, 60 * 2 ** min(action.retry_count, 5))
        action.next_retry_at = (
            timezone.now() + timedelta(seconds=max(backoff, retry_after_seconds or 0))
            if state == ActionExecution.State.RECONCILING else None
        )
        if state == ActionExecution.State.SUCCEEDED:
            action.verified_at = timezone.now()
            action.result = {"after_label_ids": sorted(after), "history_id_after": history,
                             "verified": True}
            EmailCase.objects.filter(pk=action.case_id).update(gmail_label_ids=sorted(after))
        if state in {ActionExecution.State.FAILED, ActionExecution.State.RECONCILING}:
            action.retry_count += 1
        action.save(update_fields=[
            "state", "error_code", "lease_token", "lease_expires_at", "next_retry_at",
            "verified_at", "result", "retry_count",
        ])
        _audit(action, f"response.{state}", {"error_code": code} if code else {})
    if state == ActionExecution.State.SUCCEEDED:
        _record_result_health(action, success=True)
    elif state in {ActionExecution.State.FAILED, ActionExecution.State.RECONCILING}:
        _record_result_health(action, auth_failure=code in {
            "gmail_authorization_failed", "gmail_http_401", "gmail_http_403",
            "gmail_response_scope_invalid", "gmail_response_labels_scope_invalid",
        })
    return True


def _desired(labels, target):
    return set(target["add_label_ids"]).issubset(labels) and not set(target["remove_label_ids"]) & labels


def _tracked(labels, target):
    return labels & {"INBOX", target["yphish_label_id"]}


def execute_response(action_id, *, read_client=None, write_client=None):
    """Claim once, reconcile uncertainty first, then modify one Gmail message."""
    token = uuid4()
    with transaction.atomic():
        action = ActionExecution.objects.select_for_update().select_related("case").get(pk=action_id)
        if action.state not in {ActionExecution.State.AUTHORIZED, ActionExecution.State.RECONCILING}:
            return False
        now = timezone.now()
        if action.next_retry_at and action.next_retry_at > now:
            return False
        if not settings.GMAIL_RESPONSE_ENABLED or action.policy_version != POLICY_VERSION:
            if action.state == ActionExecution.State.AUTHORIZED:
                mark_action_skipped(execution=action, reason_code="response_disabled_or_policy_changed")
            return False
        case, mailbox = _scoped_case(action.case_id)
        target = action.target
        if (action.organization_id != case.organization_id or
                target.get("mailbox_id") != str(mailbox.pk) or
                target.get("gmail_message_id") != case.gmail_message_id):
            raise GmailError("gmail_response_action_scope_invalid")
        if not mailbox.organization.gmail_response_enabled or not mailbox.gmail_response_enabled:
            return False
        if action.action != ActionExecution.Action.RESTORE:
            decision = evaluate_case(case)
            if not decision.qualifies or decision.remove_inbox != target.get("remove_inbox_config"):
                if action.state == ActionExecution.State.AUTHORIZED:
                    mark_action_skipped(execution=action, reason_code="policy_no_longer_qualifies")
                return False
        prior_state = action.state
        deferred_until, _reason = _reserve_rate(action)
        if deferred_until:
            action.next_retry_at = deferred_until
            action.save(update_fields=["next_retry_at"])
            return False
        action.state = ActionExecution.State.RUNNING
        action.lease_token = token
        action.lease_expires_at = now + timedelta(seconds=settings.GMAIL_RESPONSE_LEASE_SECONDS)
        action.next_retry_at = None
        action.save(update_fields=["state", "lease_token", "lease_expires_at", "next_retry_at"])
    try:
        case, mailbox = _scoped_case(action.case_id)
        read_client, write_client = _clients(mailbox, read_client, write_client)
        current, history = _live_labels(case, read_client)
        target = action.target
        if current & LABEL_BLOCKERS:
            return _finish(action_id, token, state=ActionExecution.State.FAILED,
                           code="message_now_spam_or_trash")
        if prior_state == ActionExecution.State.RECONCILING:
            if _desired(current, target):
                return _finish(action_id, token, state=ActionExecution.State.SUCCEEDED,
                               after=current, history=history)
            # An ambiguous write is retried only when the provider cursor and
            # tracked label state still match the persisted pre-write snapshot.
            if (not target.get("history_id_before") or history != target["history_id_before"]
                    or _tracked(current, target) != _tracked(set(target["before_label_ids"]), target)):
                return _finish(action_id, token, state=ActionExecution.State.FAILED,
                               code="ambiguous_concurrent_change")
        elif _tracked(current, target) != _tracked(set(target["before_label_ids"]), target):
            return _finish(action_id, token, state=ActionExecution.State.FAILED,
                           code="concurrent_tracked_change")
        # Persist that the external attempt is beginning before making the call.
        with transaction.atomic():
            claimed = ActionExecution.objects.select_for_update().get(pk=action_id)
            if claimed.state != ActionExecution.State.RUNNING or claimed.lease_token != token:
                return False
            claimed.executed_at = timezone.now()
            claimed.save(update_fields=["executed_at"])
        write_client.modify_case(
            case.pk, add_label_ids=target["add_label_ids"],
            remove_label_ids=target["remove_label_ids"],
            yphish_label_id=target["yphish_label_id"],
        )
        after, after_history = _live_labels(case, read_client)
        if not _desired(after, target):
            return _finish(action_id, token, state=ActionExecution.State.RECONCILING,
                           code="verification_mismatch")
        return _finish(action_id, token, state=ActionExecution.State.SUCCEEDED,
                       after=after, history=after_history)
    except GmailError as exc:
        if exc.code == "gmail_http_404":
            EmailCase.objects.filter(pk=action.case_id, gmail_deleted_at__isnull=True).update(
                gmail_deleted_at=timezone.now(),
            )
        state = (ActionExecution.State.RECONCILING if exc.retryable
                 else ActionExecution.State.FAILED)
        return _finish(action_id, token, state=state, code=exc.code,
                       retry_after_seconds=exc.retry_after_seconds)
    except Exception:
        return _finish(action_id, token, state=ActionExecution.State.RECONCILING,
                       code="response_outcome_unknown")


def reconcile_response_work():
    now = timezone.now()
    with transaction.atomic():
        expired = list(ActionExecution.objects.select_for_update(skip_locked=True).filter(
            policy_version=POLICY_VERSION, state=ActionExecution.State.RUNNING,
            lease_expires_at__lt=now,
        ))
        for action in expired:
            action.state = ActionExecution.State.RECONCILING
            action.error_code = "response_worker_lease_expired"
            action.lease_token = None
            action.lease_expires_at = None
            action.next_retry_at = now
            action.last_dispatched_at = None
            action.save(update_fields=["state", "error_code", "lease_token",
                                       "lease_expires_at", "next_retry_at", "last_dispatched_at"])
    return len(expired)


def pending_response_action_ids(limit=100):
    now = timezone.now()
    redispatch = now - timedelta(seconds=120)
    return list(ActionExecution.objects.filter(
        policy_version=POLICY_VERSION,
        state__in=[ActionExecution.State.AUTHORIZED, ActionExecution.State.RECONCILING],
    ).filter(Q(next_retry_at__isnull=True) | Q(next_retry_at__lte=now)).filter(
        Q(last_dispatched_at__isnull=True) | Q(last_dispatched_at__lte=redispatch),
    ).order_by("requested_at").values_list("pk", flat=True)[:limit])


def pending_response_case_ids(limit=100):
    from .models import InvestigationRun

    cutoff = timezone.now() - timedelta(hours=settings.GMAIL_RESPONSE_MAX_CASE_AGE_HOURS)
    indicator = Evidence.objects.filter(
        case_id=OuterRef("case_id"), source=Evidence.Source.RULE,
        rule_id="INDICATOR_EXACT", state=Evidence.State.OBSERVED,
        provenance__source_kind="operational",
    )
    signal = Evidence.objects.filter(
        case_id=OuterRef("case_id"), source=Evidence.Source.RULE,
        rule_id__in=["LINK_VISIBLE_DESTINATION", "PAYMENT_REDIRECTION_NO_LINK"],
        state=Evidence.State.OBSERVED,
    )
    return list(InvestigationRun.objects.filter(
        state=InvestigationRun.State.COMPLETED, stopping_reason="policy_complete",
        case__created_at__gte=cutoff, case__gmail_is_historical=False,
        case__mailbox__gmail_response_enabled=True,
        case__mailbox__organization__gmail_response_enabled=True,
    ).annotate(has_indicator=Exists(indicator), has_signal=Exists(signal)).filter(
        has_indicator=True, has_signal=True,
    ).exclude(case__action_executions__idempotency_key__startswith=APPLY_PREFIX).order_by(
        "finished_at",
    ).values_list("case_id", flat=True)[:limit])


def pending_restoration_case_ids(limit=100):
    return list(Feedback.objects.filter(
        state=Feedback.State.REVIEWED, proposed_verdict=EmailCase.Verdict.LEGITIMATE,
        case__action_executions__idempotency_key__startswith=APPLY_PREFIX,
        case__action_executions__state=ActionExecution.State.SUCCEEDED,
    ).exclude(case__action_executions__idempotency_key__startswith=RESTORE_PREFIX).order_by(
        "created_at",
    ).values_list("case_id", flat=True).distinct()[:limit])
