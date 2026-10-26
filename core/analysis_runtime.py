"""Database-backed Gmail MIME analysis outbox and crash recovery."""

from datetime import timedelta
from collections import defaultdict
from email import policy
from email.parser import BytesParser
from uuid import uuid4

from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.db.models import Max
from django.utils import timezone

from .models import AnalysisRun, Artifact, EmailCase, Evidence
from .models import Indicator
from .indicators import active_snapshots
from .detection import ENGINE_VERSION, detect, summarize
from .ml_features import FEATURE_SCHEMA_VERSION, extract_document
from .services import record_evidence


ANALYSIS_KEY = "gmail:parse:v1"
RULES_KEY = "gmail:rules:v1"
RUN_KEYS = (ANALYSIS_KEY, RULES_KEY)


def _classifier_observation(message):
    try:
        from .ml_pipeline import classify_document
        result = classify_document(extract_document(message))
        return {"status": result.status, "code": result.code,
                "probability_phishing": result.probability_phishing,
                "threshold": result.threshold, "model_version": result.version,
                "model_sha256": result.model_sha256,
                "feature_schema": FEATURE_SCHEMA_VERSION}
    except Exception:
        # Optional model failures must not interrupt deterministic rule evidence.
        return {"status": "unavailable", "code": "classifier_runtime_unavailable",
                "probability_phishing": None, "threshold": None,
                "model_version": "", "model_sha256": "",
                "feature_schema": FEATURE_SCHEMA_VERSION}


def ensure_analysis_run(case):
    """Create one durable parser run, even if another engine used attempt 1."""
    with transaction.atomic():
        locked = EmailCase.objects.select_for_update().get(pk=case.pk)
        existing = AnalysisRun.objects.filter(case=locked, idempotency_key=ANALYSIS_KEY).first()
        if existing:
            return existing, False
        attempt = (AnalysisRun.objects.filter(case=locked).aggregate(Max("attempt"))["attempt__max"] or 0) + 1
        return AnalysisRun.objects.create(
            organization_id=locked.organization_id, case=locked, attempt=attempt,
            idempotency_key=ANALYSIS_KEY, engine_version="mime-v1",
        ), True


def ensure_rule_backfill_run(case):
    """Queue deterministic detection for a previously parsed Gmail case."""
    with transaction.atomic():
        locked = EmailCase.objects.select_for_update().get(pk=case.pk)
        prior = AnalysisRun.objects.filter(case=locked, idempotency_key=RULES_KEY).first()
        if prior:
            return prior, False
        if AnalysisRun.objects.filter(case=locked, engine_version=ENGINE_VERSION, state=AnalysisRun.State.SUCCEEDED).exists():
            return None, False
        attempt = (AnalysisRun.objects.filter(case=locked).aggregate(Max("attempt"))["attempt__max"] or 0) + 1
        return AnalysisRun.objects.create(
            organization_id=locked.organization_id, case=locked, attempt=attempt,
            idempotency_key=RULES_KEY, engine_version=ENGINE_VERSION,
        ), True


def reconcile_analysis():
    """Repair old/non-dispatched cases and expired worker leases."""
    now = timezone.now()
    repaired = 0
    for case in EmailCase.objects.filter(
        mailbox__provider="gmail", gmail_is_historical=False,
        state=EmailCase.State.QUEUED,
    ).exclude(analysis_runs__idempotency_key=ANALYSIS_KEY).iterator():
        _run, created = ensure_analysis_run(case)
        repaired += int(created)
    with transaction.atomic():
        expired = list(AnalysisRun.objects.select_for_update(skip_locked=True).filter(
            idempotency_key__in=RUN_KEYS, state=AnalysisRun.State.RUNNING,
            lease_expires_at__lt=now,
        ).select_related("case"))
        for run in expired:
            run.state = AnalysisRun.State.QUEUED
            run.lease_token = None
            run.lease_expires_at = None
            run.next_retry_at = now
            run.error_code = "analysis_worker_lease_expired"
            run.save(update_fields=["state", "lease_token", "lease_expires_at", "next_retry_at", "error_code"])
            if run.idempotency_key == ANALYSIS_KEY:
                EmailCase.objects.filter(pk=run.case_id, state=EmailCase.State.PROCESSING).update(state=EmailCase.State.QUEUED)
            repaired += 1
    return repaired


def pending_analysis_ids(limit=None):
    now = timezone.now()
    limit = limit or settings.GMAIL_ANALYSIS_DISPATCH_BATCH_SIZE
    resend_before = now - timedelta(seconds=settings.GMAIL_ANALYSIS_REDISPATCH_SECONDS)
    return list(AnalysisRun.objects.filter(
        idempotency_key__in=RUN_KEYS, state=AnalysisRun.State.QUEUED,
    ).filter(
        Q(next_retry_at__isnull=True) | Q(next_retry_at__lte=now),
        Q(last_dispatched_at__isnull=True) | Q(last_dispatched_at__lte=resend_before),
    ).order_by("created_at").values_list("pk", flat=True)[:limit])


def run_analysis(run_id):
    """Claim with a fenced lease; a repeated delivery cannot repeat evidence."""
    now = timezone.now()
    token = uuid4()
    with transaction.atomic():
        run = AnalysisRun.objects.select_for_update().select_related("case").get(pk=run_id)
        if run.idempotency_key not in RUN_KEYS or run.state != AnalysisRun.State.QUEUED:
            return False
        if run.next_retry_at and run.next_retry_at > now:
            return False
        run.state = AnalysisRun.State.RUNNING
        run.started_at = now
        run.lease_token = token
        run.lease_expires_at = now + timedelta(seconds=settings.GMAIL_ANALYSIS_LEASE_SECONDS)
        run.save(update_fields=["state", "started_at", "lease_token", "lease_expires_at"])
        if run.idempotency_key == ANALYSIS_KEY:
            EmailCase.objects.filter(pk=run.case_id, state=EmailCase.State.QUEUED).update(
                state=EmailCase.State.PROCESSING, processing_started_at=now,
            )
    try:
        artifact = Artifact.objects.get(case_id=run.case_id, kind=Artifact.Kind.ORIGINAL_MIME, state=Artifact.State.STORED)
        with artifact.file.open("rb") as stream:
            raw = stream.read(40 * 1024 * 1024 + 1)
        if len(raw) > 40 * 1024 * 1024:
            raise ValueError("mime_too_large")
        message = BytesParser(policy=policy.default).parsebytes(raw)
        summary = {
            "has_message_id_header": bool(message.get("Message-ID")),
            "has_sender": bool(message.get("From")),
            "attachment_count": sum(1 for part in message.walk() if part.get_content_disposition() == "attachment"),
        }
        snapshots = list(active_snapshots(settings.DETECTION_INDICATOR_MODE))
        matches = defaultdict(list)
        for indicator in Indicator.objects.filter(snapshot__in=snapshots).select_related("snapshot"):
            matches[(indicator.indicator_type, indicator.value)].append(indicator.snapshot)
        observations = detect(
            message, gmail_label_ids=run.case.gmail_label_ids,
            indicator_matches=matches, indicator_cache_available=bool(snapshots),
            auth_results_mode=settings.DETECTION_AUTH_RESULTS_MODE,
        )
        summary["detection"] = summarize(observations)
        summary["detection"]["indicator_snapshot_ids"] = sorted(str(snapshot.pk) for snapshot in snapshots)
        summary["detection"]["auth_results_mode"] = settings.DETECTION_AUTH_RESULTS_MODE
        summary["classifier"] = _classifier_observation(message)
    except (OSError, Artifact.DoesNotExist):
        return _fail(run_id, token, "artifact_unavailable", retryable=True)
    except (ValueError, TypeError, LookupError, UnicodeError):
        return _fail(run_id, token, "mime_or_rule_parse_failed", retryable=False)
    with transaction.atomic():
        run = AnalysisRun.objects.select_for_update().select_related("case__organization").get(pk=run_id)
        if run.state != AnalysisRun.State.RUNNING or run.lease_token != token:
            return False
        if run.idempotency_key == ANALYSIS_KEY:
            record_evidence(
                organization=run.case.organization, case=run.case, artifact=artifact,
                analysis_run=run, idempotency_key="gmail:analysis_headers:v1",
                source=Evidence.Source.PARSER, label="MIME headers parsed",
                observed_at=run.started_at, trust=Evidence.Trust.UNTRUSTED,
                details={key: value for key, value in summary.items() if key not in {"detection", "classifier"}},
            )
        for index, item in enumerate(observations):
            record_evidence(
                organization=run.case.organization, case=run.case, artifact=artifact,
                analysis_run=run, idempotency_key=f"gmail:rule:{run.pk}:{index}",
                source=Evidence.Source.RULE, label=item.label,
                observed_at=run.started_at, trust=Evidence.Trust.UNTRUSTED,
                state=item.status, source_version=item.version,
                rule_id=item.rule_id, source_field=item.source_field,
                source_span=item.source_span,
                provenance={**item.provenance, "artifact_id": str(artifact.pk),
                            "artifact_sha256": artifact.sha256,
                            "gmail_message_id": run.case.gmail_message_id},
                limitations=list(item.limitations),
                details={"category": item.category, "facts": item.facts},
            )
        classifier = summary["classifier"]
        record_evidence(
            organization=run.case.organization, case=run.case, artifact=artifact,
            analysis_run=run, idempotency_key=f"gmail:classifier:{run.pk}",
            source=Evidence.Source.MODEL,
            label="Classifier probability recorded" if classifier["status"] == "observed" else "Classifier unavailable",
            observed_at=run.started_at, trust=Evidence.Trust.INTERNAL,
            state=classifier["status"], source_version=classifier["model_version"],
            details=classifier,
        )
        run.state = AnalysisRun.State.SUCCEEDED
        run.summary = summary
        run.engine_version = ENGINE_VERSION
        run.finished_at = timezone.now()
        run.error_code = ""
        run.lease_token = None
        run.lease_expires_at = None
        run.save(update_fields=["state", "summary", "engine_version", "finished_at", "error_code", "lease_token", "lease_expires_at"])
        if run.idempotency_key == ANALYSIS_KEY:
            EmailCase.objects.filter(pk=run.case_id, state=EmailCase.State.PROCESSING).update(
                state=EmailCase.State.ANALYZED, last_error_code="",
            )
        elif run.case.gmail_is_historical:
            EmailCase.objects.filter(pk=run.case_id, state=EmailCase.State.QUEUED).update(
                state=EmailCase.State.ANALYZED, last_error_code="",
            )
        if settings.INVESTIGATION_ENABLED and not run.case.gmail_is_historical:
            from .investigation import InvestigationAccessError, ensure_investigation_run
            try:
                ensure_investigation_run(run.case, run)
            except InvestigationAccessError:
                # A mailbox de-enrolled during analysis is not investigated.
                pass
    return True


def _fail(run_id, token, code, *, retryable):
    with transaction.atomic():
        run = AnalysisRun.objects.select_for_update().get(pk=run_id)
        if run.state != AnalysisRun.State.RUNNING or run.lease_token != token:
            return False
        run.retry_count += 1
        again = retryable and run.retry_count < 5
        run.state = AnalysisRun.State.QUEUED if again else AnalysisRun.State.FAILED
        run.next_retry_at = timezone.now() + timedelta(seconds=min(3600, 2 ** run.retry_count)) if again else None
        run.finished_at = None if again else timezone.now()
        run.error_code = code
        run.lease_token = None
        run.lease_expires_at = None
        run.save(update_fields=["retry_count", "state", "next_retry_at", "finished_at", "error_code", "lease_token", "lease_expires_at"])
        if run.idempotency_key == ANALYSIS_KEY:
            EmailCase.objects.filter(pk=run.case_id).update(
                state=EmailCase.State.QUEUED if again else EmailCase.State.FAILED,
                last_error_code=code,
            )
    return False
