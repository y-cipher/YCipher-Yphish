"""Periodic Gmail polling and durable, idempotent MIME analysis."""

import random
from datetime import timedelta

from celery import shared_task
from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from .analysis_runtime import pending_analysis_ids, reconcile_analysis, run_analysis
from .gmail import GmailError
from .gmail_runtime import sync_mailbox
from .investigation import (
    execute_investigation, pending_investigation_ids, reconcile_investigations,
)
from .models import AnalysisRun, InvestigationRun, Mailbox, ServiceHeartbeat
from .models import ActionExecution
from .response_runtime import (
    execute_response, pending_response_action_ids, pending_response_case_ids,
    pending_restoration_case_ids, prepare_response, prepare_restoration,
    reconcile_response_work,
)
from .retention import prune_private_artifacts as prune_artifacts


POLLABLE = [
    Mailbox.GmailSyncStatus.INITIALIZING, Mailbox.GmailSyncStatus.READY,
    Mailbox.GmailSyncStatus.COVERAGE_GAP, Mailbox.GmailSyncStatus.ERROR,
    Mailbox.GmailSyncStatus.DISCONNECTED, Mailbox.GmailSyncStatus.THROTTLED,
    Mailbox.GmailSyncStatus.UNAVAILABLE,
]


def retry_delay(attempt, provider_seconds=None):
    base = settings.GMAIL_RETRY_BASE_SECONDS
    maximum = settings.GMAIL_RETRY_MAX_SECONDS
    exponential = min(maximum, base * 2 ** min(attempt - 1, 20))
    return max(exponential + random.uniform(0, min(base, exponential)), provider_seconds or 0)


def failure_status(error):
    if error.code in {"gmail_http_401", "gmail_http_403", "gmail_authorization_failed",
                      "gmail_credentials_invalid", "gmail_credentials_not_configured",
                      "gmail_client_id_mismatch", "gmail_impersonated_mailbox_mismatch"}:
        return Mailbox.GmailSyncStatus.AUTHORIZATION_FAILED
    if error.code == "gmail_rate_limited":
        return Mailbox.GmailSyncStatus.THROTTLED
    if error.code == "gmail_transport_error":
        return Mailbox.GmailSyncStatus.DISCONNECTED
    return Mailbox.GmailSyncStatus.UNAVAILABLE if error.retryable else Mailbox.GmailSyncStatus.ERROR


_NO_GUARD = object()


def record_sync_failure(mailbox_id, error, *, expected_last_success=_NO_GUARD):
    if error.code == "gmail_sync_already_running":
        return
    with transaction.atomic():
        mailbox = Mailbox.objects.select_for_update().filter(pk=mailbox_id).first()
        if not mailbox or (expected_last_success is not _NO_GUARD
                           and mailbox.gmail_last_synced_at != expected_last_success):
            return
        count = mailbox.gmail_retry_count + 1 if error.retryable else mailbox.gmail_retry_count
        now = timezone.now()
        mailbox.gmail_sync_status = failure_status(error)
        mailbox.last_error_code = error.code
        mailbox.gmail_last_attempt_at = now
        mailbox.gmail_retry_count = count
        mailbox.gmail_next_sync_at = (
            now + timedelta(seconds=retry_delay(count, error.retry_after_seconds))
            if error.retryable else None
        )
        mailbox.save(update_fields=[
            "gmail_sync_status", "last_error_code", "gmail_last_attempt_at",
            "gmail_retry_count", "gmail_next_sync_at", "updated_at",
        ])


@shared_task
def poll_gmail():
    now = timezone.now()
    queued = 0
    for mailbox_id in Mailbox.objects.filter(
        provider=Mailbox.Provider.GMAIL, state=Mailbox.State.ACTIVE,
        gmail_sync_status__in=POLLABLE, organization__is_active=True,
        organization__gmail_access_verified_at__isnull=False,
    ).filter(Q(gmail_next_sync_at__isnull=True) | Q(gmail_next_sync_at__lte=now)).exclude(
        gmail_enrollment_history_id="",
    ).values_list("id", flat=True).iterator():
        sync_gmail_mailbox.delay(str(mailbox_id))
        queued += 1
    return queued


@shared_task
def sync_gmail_mailbox(mailbox_id):
    last_success = Mailbox.objects.filter(pk=mailbox_id).values_list("gmail_last_synced_at", flat=True).first()
    try:
        return sync_mailbox(mailbox_id)
    except GmailError as error:
        record_sync_failure(mailbox_id, error, expected_last_success=last_success)
        return 0


@shared_task
def dispatch_pending_analysis():
    reconcile_analysis()
    dispatched = 0
    for run_id in pending_analysis_ids():
        # A broker failure leaves the run queued for the next sweep.
        analyze_gmail_case.delay(str(run_id))
        AnalysisRun.objects.filter(pk=run_id, state=AnalysisRun.State.QUEUED).update(
            last_dispatched_at=timezone.now(),
        )
        dispatched += 1
    return dispatched


@shared_task
def analyze_gmail_case(run_id):
    return run_analysis(run_id)


@shared_task
def dispatch_pending_investigation():
    if not settings.INVESTIGATION_ENABLED:
        return 0
    reconcile_investigations()
    dispatched = 0
    for run_id in pending_investigation_ids():
        investigate_gmail_case.delay(str(run_id))
        InvestigationRun.objects.filter(pk=run_id, state=InvestigationRun.State.QUEUED).update(
            last_dispatched_at=timezone.now(),
        )
        dispatched += 1
    return dispatched


@shared_task
def investigate_gmail_case(run_id):
    return execute_investigation(run_id)


@shared_task
def dispatch_pending_response():
    if not settings.GMAIL_RESPONSE_ENABLED:
        return 0
    reconcile_response_work()
    dispatched = 0
    for case_id in pending_response_case_ids():
        prepare_gmail_response.delay(str(case_id))
        dispatched += 1
    for case_id in pending_restoration_case_ids():
        prepare_gmail_restoration.delay(str(case_id))
        dispatched += 1
    for action_id in pending_response_action_ids():
        execute_gmail_response.delay(str(action_id))
        ActionExecution.objects.filter(pk=action_id).update(last_dispatched_at=timezone.now())
        dispatched += 1
    return dispatched


@shared_task
def prepare_gmail_response(case_id):
    action = prepare_response(case_id)
    return str(action.pk) if action else None


@shared_task
def prepare_gmail_restoration(case_id):
    action = prepare_restoration(case_id)
    return str(action.pk) if action else None


@shared_task
def execute_gmail_response(action_id):
    return execute_response(action_id)


@shared_task
def prune_private_artifacts():
    if not settings.ARTIFACT_RETENTION_ENABLED:
        return {"eligible": 0, "deleted": 0, "file_errors": 0}
    return prune_artifacts()


@shared_task
def scheduler_heartbeat():
    ServiceHeartbeat.objects.update_or_create(
        name="beat", defaults={"last_seen_at": timezone.now()},
    )
