"""Versioned, conservative message-level Gmail response eligibility."""

from dataclasses import dataclass
from datetime import datetime, timedelta

from django.conf import settings
from django.utils import timezone

from .investigation import _target_time
from .models import (
    AnalysisRun, EmailCase, Evidence, Feedback, InvestigationRun,
    InvestigationStep, Mailbox,
)


POLICY_VERSION = "gmail-response-v1"
EVIDENCE_RULE_VERSION = "1"
INDEPENDENT_SIGNALS = {"LINK_VISIBLE_DESTINATION", "PAYMENT_REDIRECTION_NO_LINK"}


@dataclass(frozen=True)
class PolicyDecision:
    qualifies: bool
    reason: str
    analysis_run_id: object = None
    evidence_ids: tuple = ()
    remove_inbox: bool = False


def evaluate_case(case):
    mailbox = Mailbox.objects.select_related("organization").get(pk=case.mailbox_id)
    if (not settings.GMAIL_RESPONSE_ENABLED or not mailbox.organization.is_active
            or not mailbox.organization.gmail_response_enabled or not mailbox.gmail_response_enabled):
        return PolicyDecision(False, "response_not_enabled")
    if (mailbox.provider != Mailbox.Provider.GMAIL or mailbox.state != Mailbox.State.ACTIVE
            or mailbox.gmail_sync_status != Mailbox.GmailSyncStatus.READY
            or not mailbox.gmail_enrolled_at or not mailbox.gmail_enrollment_history_id
            or not mailbox.organization.gmail_access_verified_at):
        return PolicyDecision(False, "mailbox_not_ready")
    if (case.organization_id != mailbox.organization_id or not case.gmail_message_id
            or case.gmail_is_historical or case.gmail_deleted_at):
        return PolicyDecision(False, "case_not_eligible")
    if timezone.now() - case.created_at > timedelta(hours=settings.GMAIL_RESPONSE_MAX_CASE_AGE_HOURS):
        return PolicyDecision(False, "case_too_old")
    if Feedback.objects.filter(case=case, state=Feedback.State.REVIEWED,
                               proposed_verdict=EmailCase.Verdict.LEGITIMATE).exists():
        return PolicyDecision(False, "legitimate_feedback")
    analysis = AnalysisRun.objects.filter(
        case=case, organization_id=case.organization_id,
        state=AnalysisRun.State.SUCCEEDED, engine_version="rules-v1",
    ).order_by("-finished_at").first()
    if not analysis:
        return PolicyDecision(False, "analysis_unavailable")
    investigation = InvestigationRun.objects.filter(
        case=case, analysis_run=analysis, policy_version="explicit-v1",
        state=InvestigationRun.State.COMPLETED, stopping_reason="policy_complete",
    ).first()
    if not investigation or InvestigationStep.objects.filter(
        investigation=investigation, state__in=[InvestigationStep.State.ERROR,
                                                InvestigationStep.State.REJECTED],
    ).exists():
        return PolicyDecision(False, "investigation_incomplete")
    cutoff = _target_time(case)
    indicators, independent = [], []
    for item in Evidence.objects.filter(
        organization_id=case.organization_id, case=case, analysis_run=analysis,
        source=Evidence.Source.RULE, state=Evidence.State.OBSERVED,
        source_version=EVIDENCE_RULE_VERSION,
    ):
        if item.rule_id == "INDICATOR_EXACT":
            provenance = item.provenance if isinstance(item.provenance, dict) else {}
            if provenance.get("source_kind") != "operational":
                continue
            try:
                fetched = datetime.fromisoformat(provenance["fetched_at"])
                expiry = datetime.fromisoformat(provenance["expires_at"])
            except (KeyError, TypeError, ValueError):
                continue
            if fetched <= cutoff < expiry:
                indicators.append(item.pk)
        elif item.rule_id in INDEPENDENT_SIGNALS:
            independent.append(item.pk)
    if not indicators or not independent:
        return PolicyDecision(False, "insufficient_independent_evidence")
    return PolicyDecision(True, "operational_indicator_and_independent_rule",
                          analysis.pk, tuple(sorted({*indicators, *independent}, key=str)),
                          mailbox.gmail_response_remove_inbox)
