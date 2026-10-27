"""Organization-scoped HTML dashboard. No Gmail API calls occur in web views."""

import json
from email import policy
from email.parser import BytesParser
from uuid import UUID

from celery import current_app
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.core.paginator import Paginator
from django.db.models import Exists, OuterRef, Q, Subquery
from django.http import Http404, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST
from kombu import Connection

from .dashboard_forms import CaseFilterForm, FeedbackForm, ResponseMailboxForm, ReviewForm
from .ml_features import extract_document
from .models import (
    ActionExecution, AnalysisRun, Artifact, AuditEvent, EmailCase, Evidence,
    Feedback, InvestigationRun, Mailbox, Membership, ResponseControl,
)
from .operator_services import (
    MANAGER_ROLES, REVIEW_ROLES, OperatorDenied, OperatorInvalid,
    request_restoration, review_feedback, submit_feedback, update_mailbox_response,
)
from .response_policy import POLICY_VERSION
from .response_runtime import APPLY_PREFIX
from .tasks import prepare_gmail_restoration
from django.utils import timezone


def _scope(request, slug):
    if not request.user.is_active:
        raise Http404
    membership = get_object_or_404(
        Membership.objects.select_related("organization"), user=request.user,
        organization__slug=slug, organization__is_active=True, is_active=True,
    )
    return membership.organization, membership


def _base(request, organization, membership):
    return {
        "organization": organization, "membership": membership,
        "can_feedback": membership.role in REVIEW_ROLES,
        "can_manage": membership.role in MANAGER_ROLES,
        "memberships": Membership.objects.select_related("organization").filter(
            user=request.user, is_active=True, organization__is_active=True,
        ).order_by("organization__name"),
    }


def _case_status(case, actions):
    if case.gmail_deleted_at:
        return "unavailable", "Message unavailable"
    if not actions:
        return "none", "No automatic action"
    newest = actions[0]
    if newest.state == ActionExecution.State.FAILED:
        return "failed", "Failed action"
    if newest.state in {ActionExecution.State.PROPOSED, ActionExecution.State.AUTHORIZED,
                        ActionExecution.State.RUNNING, ActionExecution.State.RECONCILING}:
        return "pending", "Response pending" if newest.action != ActionExecution.Action.RESTORE else "Restoration pending"
    if newest.action == ActionExecution.Action.RESTORE and newest.state == ActionExecution.State.SUCCEEDED:
        return "restored", "Yphish changes restored"
    successful = next((item for item in actions if item.action != ActionExecution.Action.RESTORE
                       and item.state == ActionExecution.State.SUCCEEDED), None)
    if successful:
        added = successful.target.get("yphish_added_label", False)
        removed = successful.target.get("yphish_removed_inbox", False)
        if added and removed:
            return "inbox_removed", "Labeled; INBOX removed"
        if removed:
            return "inbox_removed", "INBOX removed"
        if added:
            return "labeled", "Yphish label applied"
    return "none", "No automatic action"


def _queue_health():
    cached = cache.get("yphish:dashboard:queue-health")
    if cached is not None:
        return cached
    status = "unavailable"
    workers = 0
    try:
        with Connection(current_app.conf.broker_url, connect_timeout=1) as connection:
            connection.ensure_connection(max_retries=1)
        workers = len(current_app.control.ping(timeout=1) or [])
        status = "ready" if workers else "no workers responding"
    except Exception:
        # Transport errors may contain credentials; render only a fixed state.
        pass
    value = {"status": status, "workers": workers}
    cache.set("yphish:dashboard:queue-health", value, 30)
    return value


def _json_preview(value, limit=3000):
    try:
        content = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)
    except (TypeError, ValueError):
        return "Unavailable"
    return content[:limit] + ("…" if len(content) > limit else "")


def _body_preview(case):
    artifact = Artifact.objects.filter(
        case=case, organization=case.organization,
        kind=Artifact.Kind.ORIGINAL_MIME, state=Artifact.State.STORED,
    ).first()
    if not artifact or not artifact.file:
        return "", "Original MIME is unavailable."
    if artifact.size_bytes is None or artifact.size_bytes > 1_000_000:
        return "", "Preview unavailable for messages over 1 MB."
    try:
        with artifact.file.open("rb") as stream:
            raw = stream.read(1_000_001)
        if len(raw) > 1_000_000:
            return "", "Preview unavailable for messages over 1 MB."
        document = extract_document(BytesParser(policy=policy.default).parsebytes(raw))
        text = document.body_text[:2500]
        return text, "Preview limited to 2,500 characters; HTML is rendered as escaped text."
    except (OSError, ValueError, TypeError, UnicodeError, LookupError):
        return "", "Original MIME could not be previewed."


def _enqueue_restoration(case_id):
    try:
        prepare_gmail_restoration.delay(str(case_id))
        return True
    except Exception:
        # The periodic durable sweep will discover reviewed corrections.
        return False


@login_required
@never_cache
def home(request):
    membership = Membership.objects.select_related("organization").filter(
        user=request.user, is_active=True, organization__is_active=True,
    ).order_by("organization__name").first()
    if not membership:
        return render(request, "core/dashboard/no_access.html", status=403)
    return redirect("dashboard_overview", slug=membership.organization.slug)


@login_required
@never_cache
def overview(request, slug):
    organization, membership = _scope(request, slug)
    now = timezone.now()
    mailboxes = list(Mailbox.objects.filter(organization=organization, provider=Mailbox.Provider.GMAIL)
                     .order_by("address"))
    mailbox_rows = [
        {"mailbox": mailbox,
         "lag_seconds": int((now - mailbox.gmail_last_synced_at).total_seconds())
         if mailbox.gmail_last_synced_at else None,
         "authorization_failed": mailbox.gmail_sync_status == Mailbox.GmailSyncStatus.AUTHORIZATION_FAILED}
        for mailbox in mailboxes
    ]
    analyses = AnalysisRun.objects.filter(organization=organization)
    oldest_queued = analyses.filter(state=AnalysisRun.State.QUEUED).order_by("created_at").first()
    actions = ActionExecution.objects.filter(organization=organization,
                                             policy_version=POLICY_VERSION)
    controls = ResponseControl.objects.filter(organization=organization,
                                              circuit_open_until__gt=now).select_related("mailbox")
    context = _base(request, organization, membership) | {
        "section": "overview",
        "mailbox_rows": mailbox_rows,
        "enrolled_count": sum(bool(item["mailbox"].gmail_enrollment_history_id) for item in mailbox_rows),
        "incomplete_count": analyses.filter(state__in=[AnalysisRun.State.QUEUED,
                                                        AnalysisRun.State.RUNNING,
                                                        AnalysisRun.State.FAILED]).count(),
        "queued_count": analyses.filter(state=AnalysisRun.State.QUEUED).count(),
        "failed_count": analyses.filter(state=AnalysisRun.State.FAILED).count(),
        "stale_analysis_leases": analyses.filter(state=AnalysisRun.State.RUNNING,
                                                  lease_expires_at__lt=now).count(),
        "oldest_queued_seconds": int((now - oldest_queued.created_at).total_seconds())
                                 if oldest_queued else None,
        "action_success_count": actions.filter(state=ActionExecution.State.SUCCEEDED).exclude(
            action=ActionExecution.Action.RESTORE).count(),
        "action_failed_count": actions.filter(state=ActionExecution.State.FAILED).count(),
        "restored_count": actions.filter(state=ActionExecution.State.SUCCEEDED,
                                         action=ActionExecution.Action.RESTORE).count(),
        "pending_action_count": actions.filter(state__in=[ActionExecution.State.AUTHORIZED,
                                                          ActionExecution.State.RUNNING,
                                                          ActionExecution.State.RECONCILING]).count(),
        "circuits": controls,
        "queue_health": _queue_health(),
        "recent_cases": EmailCase.objects.filter(organization=organization).select_related("mailbox")
                        .order_by("-created_at")[:8],
    }
    return render(request, "core/dashboard/overview.html", context)


@login_required
@never_cache
def case_list(request, slug):
    organization, membership = _scope(request, slug)
    mailboxes = list(Mailbox.objects.filter(organization=organization,
                                            provider=Mailbox.Provider.GMAIL).order_by("address"))
    form = CaseFilterForm(request.GET or None, mailboxes=mailboxes)
    cases = EmailCase.objects.filter(organization=organization).select_related("mailbox")
    if form.is_valid():
        data = form.cleaned_data
        if data["q"]:
            query = data["q"].strip()
            search = (Q(subject__icontains=query) | Q(sender_address__icontains=query)
                      | Q(gmail_message_id__iexact=query))
            try:
                search |= Q(pk=UUID(query))
            except ValueError:
                pass
            cases = cases.filter(search)
        if data["mailbox"]:
            cases = cases.filter(mailbox_id=data["mailbox"])
        if data["verdict"]:
            cases = cases.filter(verdict=data["verdict"])
        if data["state"]:
            cases = cases.filter(state=data["state"])
        if data["label"]:
            if data["label"] == "yphish":
                predicate = Q(pk__in=[])
                for mailbox in mailboxes:
                    if mailbox.gmail_label_id:
                        predicate |= Q(mailbox_id=mailbox.pk,
                                       gmail_label_ids__contains=[mailbox.gmail_label_id])
                cases = cases.filter(predicate)
            else:
                cases = cases.filter(gmail_label_ids__contains=[data["label"]])
        response = data["response"]
        if response:
            all_actions = ActionExecution.objects.filter(organization=organization,
                                                          case_id=OuterRef("pk"),
                                                          policy_version=POLICY_VERSION)
            latest_action = all_actions.order_by("-requested_at", "-pk")
            apply_success = all_actions.filter(state=ActionExecution.State.SUCCEEDED).exclude(
                action=ActionExecution.Action.RESTORE)
            cases = cases.annotate(applied=Exists(apply_success),
                                   yphish_labeled=Exists(apply_success.filter(
                                       target__yphish_added_label=True)),
                                   removed_inbox=Exists(apply_success.filter(
                                       target__yphish_removed_inbox=True)),
                                   latest_action_state=Subquery(latest_action.values("state")[:1]),
                                   latest_action_type=Subquery(latest_action.values("action")[:1]))
            nonblocking_action = (
                Q(latest_action_state__isnull=True)
                | (~Q(latest_action_state__in=[
                    ActionExecution.State.FAILED,
                    ActionExecution.State.PROPOSED,
                    ActionExecution.State.AUTHORIZED,
                    ActionExecution.State.RUNNING,
                    ActionExecution.State.RECONCILING,
                ])
                   & ~(Q(latest_action_state=ActionExecution.State.SUCCEEDED)
                       & Q(latest_action_type=ActionExecution.Action.RESTORE)))
            )
            visible_action = Q(gmail_deleted_at__isnull=True) & nonblocking_action
            conditions = {
                "labeled": visible_action & Q(yphish_labeled=True),
                "inbox_removed": visible_action & Q(removed_inbox=True),
                "restored": Q(gmail_deleted_at__isnull=True,
                              latest_action_state=ActionExecution.State.SUCCEEDED,
                              latest_action_type=ActionExecution.Action.RESTORE),
                "pending": Q(gmail_deleted_at__isnull=True,
                             latest_action_state__in=[ActionExecution.State.PROPOSED,
                                                      ActionExecution.State.AUTHORIZED,
                                                      ActionExecution.State.RUNNING,
                                                      ActionExecution.State.RECONCILING]),
                "failed": Q(gmail_deleted_at__isnull=True,
                            latest_action_state=ActionExecution.State.FAILED),
                "unavailable": Q(gmail_deleted_at__isnull=False),
                "none": visible_action & Q(applied=False),
            }
            cases = cases.filter(conditions[response])
    page = Paginator(cases.order_by("-created_at", "-pk"), 25).get_page(request.GET.get("page"))
    ids = [case.pk for case in page.object_list]
    actions_by_case = {}
    for action in ActionExecution.objects.filter(organization=organization, case_id__in=ids,
                                                 policy_version=POLICY_VERSION).order_by("-requested_at", "-pk"):
        actions_by_case.setdefault(action.case_id, []).append(action)
    rows = []
    for case in page.object_list:
        code, label = _case_status(case, actions_by_case.get(case.pk, []))
        rows.append({"case": case, "response_code": code, "response_label": label,
                     "sender_domain": case.sender_address.rsplit("@", 1)[-1] if case.sender_address else "Unknown",
                     "subject_excerpt": (case.subject[:80] + "…") if len(case.subject) > 80 else case.subject})
    query = request.GET.copy()
    query.pop("page", None)
    context = _base(request, organization, membership) | {
        "section": "cases",
        "form": form, "page": page, "rows": rows,
        "pagination_query": query.urlencode() + "&" if query else "",
    }
    return render(request, "core/dashboard/cases.html", context)


@login_required
@never_cache
def case_detail(request, slug, case_id):
    organization, membership = _scope(request, slug)
    case = get_object_or_404(EmailCase.objects.select_related("mailbox"),
                             pk=case_id, organization=organization)
    actions = list(ActionExecution.objects.filter(case=case, organization=organization)
                   .order_by("-requested_at", "-pk")[:40])
    evidence = list(Evidence.objects.filter(case=case, organization=organization)
                    .select_related("analysis_run").order_by("-observed_at")[:100])
    for item in evidence:
        item.details_display = _json_preview(item.details)
        item.provenance_display = _json_preview(item.provenance)
        item.span_display = _json_preview(item.source_span)
    analyses = list(AnalysisRun.objects.filter(case=case, organization=organization)
                    .order_by("-created_at")[:20])
    can_view_investigation = membership.role in REVIEW_ROLES
    investigations = (list(InvestigationRun.objects.filter(case=case, organization=organization)
                           .order_by("-created_at")[:10]) if can_view_investigation else [])
    for investigation in investigations:
        investigation.visible_steps = list(investigation.steps.order_by("call_number")[:50])
        for step in investigation.visible_steps:
            step.arguments_display = _json_preview(step.arguments, 1000)
            step.result_display = _json_preview(step.result, 1500)
    feedback = list(Feedback.objects.filter(case=case, organization=organization)
                    .select_related("submitted_by", "reviewed_by").order_by("-created_at")[:30])
    audit = (list(AuditEvent.objects.filter(case=case, organization=organization)
                  .select_related("actor").order_by("-occurred_at")[:50])
             if can_view_investigation else [])
    for event in audit:
        event.details_display = _json_preview(event.details, 1000)
    code, label = _case_status(case, actions)
    preview, preview_note = _body_preview(case) if membership.role in REVIEW_ROLES else (
        "", "Message preview requires an analyst or manager role.")
    successful_apply = next((item for item in actions if item.action != ActionExecution.Action.RESTORE
                             and item.state == ActionExecution.State.SUCCEEDED
                             and item.idempotency_key.startswith(APPLY_PREFIX)), None)
    can_restore = (membership.role in MANAGER_ROLES and bool(successful_apply)
                   and settings.GMAIL_RESPONSE_ENABLED
                   and organization.gmail_response_enabled and case.mailbox.gmail_response_enabled
                   and any(item.state == Feedback.State.REVIEWED
                           and item.proposed_verdict == EmailCase.Verdict.LEGITIMATE for item in feedback)
                   and not any(item.action == ActionExecution.Action.RESTORE
                               and item.state in {ActionExecution.State.SUCCEEDED,
                                                  ActionExecution.State.FAILED,
                                                  ActionExecution.State.SKIPPED} for item in actions))
    context = _base(request, organization, membership) | {
        "section": "cases",
        "case": case, "actions": actions, "evidence": evidence,
        "analyses": analyses, "investigations": investigations,
        "feedback_items": feedback, "audit_events": audit,
        "can_view_investigation": can_view_investigation,
        "response_code": code, "response_label": label,
        "preview": preview, "preview_note": preview_note,
        "pre_action_labels": successful_apply.target.get("before_label_ids") if successful_apply else None,
        "can_restore": can_restore,
        "feedback_form": FeedbackForm(), "review_form": ReviewForm(),
        "evidence_incomplete": any(item.state != Evidence.State.OBSERVED for item in evidence)
                               or any(item.state != AnalysisRun.State.SUCCEEDED for item in analyses),
    }
    return render(request, "core/dashboard/detail.html", context)


@login_required
@never_cache
def dashboard_settings(request, slug):
    organization, membership = _scope(request, slug)
    mailboxes = Mailbox.objects.filter(organization=organization,
                                       provider=Mailbox.Provider.GMAIL).order_by("address")
    rows = [{"mailbox": mailbox,
             "form": ResponseMailboxForm(prefix=str(mailbox.pk), initial={
                 "enabled": mailbox.gmail_response_enabled,
                 "remove_inbox": mailbox.gmail_response_remove_inbox,
             }),
             "authorization_failed": mailbox.gmail_sync_status == Mailbox.GmailSyncStatus.AUTHORIZATION_FAILED,
             "label_missing": mailbox.gmail_response_enabled and not mailbox.gmail_label_id}
            for mailbox in mailboxes]
    context = _base(request, organization, membership) | {
        "section": "settings",
        "rows": rows, "policy_version": POLICY_VERSION,
        "response_scope_ok": (organization.gmail_response_scope ==
                              "https://www.googleapis.com/auth/gmail.modify.restricted"
                              and organization.gmail_response_labels_scope ==
                              "https://www.googleapis.com/auth/gmail.labels"
                              and bool(organization.gmail_response_service_account_client_id)
                              and organization.gmail_response_service_account_client_id !=
                              organization.gmail_service_account_client_id),
        "poll_seconds": settings.GMAIL_POLL_INTERVAL_SECONDS,
        "response_sweep_seconds": settings.GMAIL_RESPONSE_SWEEP_INTERVAL_SECONDS,
        "global_response_enabled": settings.GMAIL_RESPONSE_ENABLED,
        "response_hourly_limit": settings.GMAIL_RESPONSE_MAILBOX_HOURLY_LIMIT,
        "circuits": ResponseControl.objects.filter(organization=organization,
                                                    circuit_open_until__gt=timezone.now()).select_related("mailbox"),
    }
    return render(request, "core/dashboard/settings.html", context)


@login_required
@require_POST
@never_cache
def submit_case_feedback(request, slug, case_id):
    organization, membership = _scope(request, slug)
    if membership.role not in REVIEW_ROLES:
        return HttpResponseForbidden("Analyst or manager role required.")
    case = get_object_or_404(EmailCase, pk=case_id, organization=organization)
    form = FeedbackForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Feedback needs a verdict and a reason of at least 10 characters.")
    else:
        try:
            submit_feedback(actor=request.user, case_id=case.pk, **form.cleaned_data)
            messages.success(request, "Feedback submitted for review; the model was not retrained.")
        except (OperatorDenied, OperatorInvalid) as exc:
            messages.error(request, str(exc))
    return redirect("dashboard_case_detail", slug=slug, case_id=case_id)


@login_required
@require_POST
@never_cache
def review_case_feedback(request, slug, feedback_id):
    organization, membership = _scope(request, slug)
    if membership.role not in MANAGER_ROLES:
        return HttpResponseForbidden("Manager role required.")
    feedback = get_object_or_404(Feedback, pk=feedback_id, organization=organization)
    form = ReviewForm(request.POST)
    if not form.is_valid():
        messages.error(request, "A decision and review reason are required.")
    else:
        try:
            reviewed = review_feedback(actor=request.user, feedback_id=feedback.pk,
                                       **form.cleaned_data)
            if (reviewed.state == Feedback.State.REVIEWED
                    and reviewed.proposed_verdict == EmailCase.Verdict.LEGITIMATE):
                _enqueue_restoration(reviewed.case_id)
            messages.success(request, "Feedback review recorded with actor and reason.")
        except (OperatorDenied, OperatorInvalid) as exc:
            messages.error(request, str(exc))
    return redirect("dashboard_case_detail", slug=slug, case_id=feedback.case_id)


@login_required
@require_POST
@never_cache
def restore_case(request, slug, case_id):
    organization, membership = _scope(request, slug)
    if membership.role not in MANAGER_ROLES:
        return HttpResponseForbidden("Manager role required.")
    case = get_object_or_404(EmailCase, pk=case_id, organization=organization)
    try:
        request_restoration(actor=request.user, case_id=case.pk)
        dispatched = _enqueue_restoration(case.pk)
        messages.success(request, "Restoration requested. The worker will verify current Gmail labels before changing this message." if dispatched else
                         "Restoration recorded. The scheduled worker sweep will retry dispatch.")
    except (OperatorDenied, OperatorInvalid) as exc:
        messages.error(request, str(exc))
    return redirect("dashboard_case_detail", slug=slug, case_id=case_id)


@login_required
@require_POST
@never_cache
def update_response_settings(request, slug, mailbox_id):
    organization, membership = _scope(request, slug)
    if membership.role not in MANAGER_ROLES:
        return HttpResponseForbidden("Manager role required.")
    mailbox = get_object_or_404(Mailbox, pk=mailbox_id, organization=organization)
    form = ResponseMailboxForm(request.POST, prefix=str(mailbox.pk))
    if form.is_valid():
        try:
            update_mailbox_response(actor=request.user, mailbox_id=mailbox.pk,
                                    **form.cleaned_data)
            messages.success(request, "Mailbox response settings saved and audited.")
        except (OperatorDenied, OperatorInvalid) as exc:
            messages.error(request, str(exc))
    else:
        messages.error(request, "Response settings are invalid; check enablement and INBOX removal.")
    return redirect("dashboard_settings", slug=slug)
