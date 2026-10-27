"""Durable Gmail ingestion and history synchronization. No mailbox mutations."""

import hashlib
from contextlib import contextmanager
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
from uuid import UUID

from django.core.files.base import ContentFile
from django.db import connection, transaction
from django.utils import timezone

from .gmail import GmailClient, GmailError, GmailHistoryExpired
from .gmail_credentials import CredentialProviderError, enrolled_mailbox
from .analysis_runtime import ensure_analysis_run
from .models import Artifact, AuditEvent, EmailCase, Evidence, Mailbox
from .services import create_email_case, record_evidence


def _metadata(raw):
    message = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
    received_at = None
    try:
        received_at = parsedate_to_datetime(str(message.get("Date", "")))
        if received_at and timezone.is_naive(received_at):
            received_at = None
    except (TypeError, ValueError, IndexError):
        pass
    return {
        "internet_message_id": str(message.get("Message-ID", ""))[:512],
        "subject": str(message.get("Subject", ""))[:998],
        "sender_address": parseaddr(str(message.get("From", "")))[1][:320],
        "received_at": received_at,
    }


def _provider_metadata(data):
    internal_date = data.get("internalDate", "")
    if not isinstance(internal_date, str) or (
        internal_date and (not internal_date.isdecimal() or len(internal_date) > 32)
    ):
        raise GmailError("gmail_internal_date_invalid")
    labels = data.get("labelIds", [])
    if not isinstance(labels, list) or any(not isinstance(item, str) for item in labels):
        raise GmailError("gmail_labels_invalid")
    thread_id = data.get("threadId", "")
    if not isinstance(thread_id, str) or len(thread_id) > 512:
        raise GmailError("gmail_thread_id_invalid")
    return thread_id, sorted(set(labels)), internal_date


def ingest_message(mailbox_id, gmail_message_id, *, client=None, historical=False, added_after_enrollment=False):
    """Fetch one Gmail ID and commit case, MIME, and evidence before returning."""
    try:
        mailbox = enrolled_mailbox(mailbox_id)
    except CredentialProviderError as exc:
        raise GmailError(exc.code) from None
    client = client or GmailClient(mailbox.pk)
    data, raw = client.get_raw_message(gmail_message_id)
    thread_id, labels, internal_date = _provider_metadata(data)
    with transaction.atomic():
        case, created = create_email_case(
            organization=mailbox.organization, mailbox=mailbox,
            gmail_message_id=gmail_message_id, gmail_thread_id=thread_id,
            **_metadata(raw),
        )
        case = EmailCase.objects.select_for_update().get(pk=case.pk)
        changes = []
        if created or (not case.gmail_thread_id and thread_id):
            case.gmail_thread_id = thread_id
            changes.append("gmail_thread_id")
        if case.gmail_label_ids != labels:
            case.gmail_label_ids = labels
            changes.append("gmail_label_ids")
        if created:
            case.gmail_initial_label_ids = labels
            changes.append("gmail_initial_label_ids")
        if case.gmail_internal_date_ms != internal_date:
            case.gmail_internal_date_ms = internal_date
            changes.append("gmail_internal_date_ms")
        if created:
            case.gmail_is_historical = historical
            changes.append("gmail_is_historical")
        elif added_after_enrollment and case.gmail_is_historical:
            case.gmail_is_historical = False
            changes.append("gmail_is_historical")
        if changes:
            case.save(update_fields=changes)
        artifact, _ = Artifact.objects.get_or_create(
            organization=mailbox.organization, case=case, kind=Artifact.Kind.ORIGINAL_MIME,
            defaults={"state": Artifact.State.PENDING, "content_type": "message/rfc822"},
        )
        if artifact.state != Artifact.State.STORED:
            artifact.file.save("message.eml", ContentFile(raw), save=False)
            artifact.sha256 = hashlib.sha256(raw).hexdigest()
            artifact.size_bytes = len(raw)
            artifact.state = Artifact.State.STORED
            artifact.error_code = ""
            artifact.save(update_fields=["file", "sha256", "size_bytes", "state", "error_code"])
        record_evidence(
            organization=mailbox.organization, case=case, artifact=artifact,
            idempotency_key="gmail:original_mime:v1", source=Evidence.Source.INGESTION,
            label="Original Gmail MIME stored privately", observed_at=artifact.created_at,
            trust=Evidence.Trust.INTERNAL,
            details={"size_bytes": artifact.size_bytes, "sha256": artifact.sha256},
        )
        if case.gmail_deleted_at:
            case.gmail_deleted_at = None
            case.save(update_fields=["gmail_deleted_at", "updated_at"])
        # The durable run is the outbox. No broker publish occurs in this
        # transaction; a periodic sweep dispatches after commit.
        if not case.gmail_is_historical:
            ensure_analysis_run(case)
        return case


def _unavailable(mailbox, message_id, phase):
    # A message can disappear between list/history and get. Record that fact
    # before allowing the completed history cursor to advance.
    AuditEvent.objects.create(
        organization=mailbox.organization, event_type="gmail.message_unavailable",
        subject_type="mailbox", subject_id=mailbox.pk, occurred_at=timezone.now(),
        details={"gmail_message_id": message_id, "phase": phase},
    )


def _mark_deleted(mailbox, message_id):
    # A tombstone affects only a previously observed message. A deleted
    # message seen first in history has no MIME to preserve or analyze.
    EmailCase.objects.filter(
        mailbox=mailbox, organization=mailbox.organization,
        gmail_message_id=message_id, gmail_deleted_at__isnull=True,
    ).update(gmail_deleted_at=timezone.now())


def _refresh_labels(mailbox, client, message_id):
    case = EmailCase.objects.filter(
        organization=mailbox.organization, mailbox=mailbox,
        gmail_message_id=message_id,
    ).first()
    if not case:
        return
    data = client.get_message_metadata(message_id)
    _thread, labels, _date = _provider_metadata(data)
    EmailCase.objects.filter(pk=case.pk).update(
        gmail_label_ids=labels, gmail_deleted_at=None,
    )


def _full_scan(mailbox, client):
    count = 0
    for item in client.list_messages():
        message_id = item.get("id")
        if not message_id:
            raise GmailError("gmail_list_message_id_missing")
        try:
            ingest_message(mailbox.pk, message_id, client=client, historical=True)
            count += 1
        except GmailError as exc:
            if exc.code != "gmail_http_404":
                raise
            _unavailable(mailbox, message_id, "full_scan")
    return count


def _history_catchup(mailbox, client, start_history_id):
    count = 0
    completed_cursor = None
    for message_id, kind in client.history_messages(start_history_id):
        if message_id is None:
            completed_cursor = kind
            continue
        if kind == "deleted":
            _mark_deleted(mailbox, message_id)
            count += 1
            continue
        try:
            if kind == "labels":
                _refresh_labels(mailbox, client, message_id)
                count += 1
                continue
            ingest_message(
                mailbox.pk, message_id, client=client,
                historical=kind != "added",
                added_after_enrollment=kind == "added",
            )
            count += 1
        except GmailError as exc:
            if exc.code != "gmail_http_404":
                raise
            _mark_deleted(mailbox, message_id)
            _unavailable(mailbox, message_id, "history")
    if not completed_cursor:
        raise GmailError("gmail_history_cursor_missing", retryable=True)
    return count, completed_cursor


def _mark_gap(mailbox, old_cursor):
    with transaction.atomic():
        current = Mailbox.objects.select_for_update().get(pk=mailbox.pk)
        if not current.gmail_coverage_gap_detected_at:
            current.gmail_coverage_gap_detected_at = timezone.now()
            current.gmail_coverage_gap_from_history_id = old_cursor
            AuditEvent.objects.create(
                organization=current.organization, event_type="gmail.coverage_gap",
                subject_type="mailbox", subject_id=current.pk,
                occurred_at=current.gmail_coverage_gap_detected_at,
                details={"from_history_id": old_cursor},
            )
        current.gmail_sync_status = Mailbox.GmailSyncStatus.COVERAGE_GAP
        current.last_error_code = "gmail_history_expired"
        current.save(update_fields=[
            "gmail_coverage_gap_detected_at", "gmail_coverage_gap_from_history_id",
            "gmail_sync_status", "last_error_code", "updated_at",
        ])


def _recover_expired(mailbox, client, old_cursor):
    _mark_gap(mailbox, old_cursor)
    # Capture a fresh anchor before the scan. Replaying from it catches mail
    # arriving while pages are traversed. The inaccessible interval is still
    # exposed as a coverage gap, including transiently added/deleted messages.
    anchor = client.profile().get("historyId")
    if not isinstance(anchor, str) or not anchor:
        raise GmailError("gmail_history_cursor_missing", retryable=True)
    count = _full_scan(mailbox, client)
    replayed, completed_cursor = _history_catchup(mailbox, client, anchor)
    return count + replayed, completed_cursor


@contextmanager
def _mailbox_lock(mailbox_id):
    raw = UUID(str(mailbox_id)).bytes
    keys = (
        int.from_bytes(raw[:4], "big", signed=True),
        int.from_bytes(raw[4:8], "big", signed=True),
    )
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_try_advisory_lock(%s, %s)", keys)
        acquired = cursor.fetchone()[0]
    if not acquired:
        raise GmailError("gmail_sync_already_running", retryable=True)
    try:
        yield
    finally:
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_unlock(%s, %s)", keys)


def sync_mailbox(mailbox_id, *, client=None):
    """Initial scan or incremental history poll; commit cursor only at the end."""
    with _mailbox_lock(mailbox_id):
        try:
            mailbox = enrolled_mailbox(mailbox_id)
        except CredentialProviderError as exc:
            raise GmailError(exc.code) from None
        client = client or GmailClient(mailbox.pk)
        original_cursor = mailbox.gmail_history_id
        initializing = mailbox.gmail_sync_status == Mailbox.GmailSyncStatus.INITIALIZING or not original_cursor
        if initializing:
            count = _full_scan(mailbox, client)
            try:
                replayed, completed_cursor = _history_catchup(
                    mailbox, client, mailbox.gmail_enrollment_history_id,
                )
                count += replayed
            except GmailHistoryExpired:
                recovered, completed_cursor = _recover_expired(
                    mailbox, client, mailbox.gmail_enrollment_history_id,
                )
                count += recovered
        else:
            try:
                count, completed_cursor = _history_catchup(mailbox, client, original_cursor)
            except GmailHistoryExpired:
                count, completed_cursor = _recover_expired(mailbox, client, original_cursor)
        with transaction.atomic():
            current = Mailbox.objects.select_for_update().get(pk=mailbox.pk)
            if (current.gmail_history_id != original_cursor
                    or current.gmail_enrollment_history_id != mailbox.gmail_enrollment_history_id
                    or current.state != Mailbox.State.ACTIVE):
                raise GmailError("gmail_sync_state_changed", retryable=True)
            current.gmail_history_id = completed_cursor
            current.gmail_last_synced_at = timezone.now()
            current.gmail_last_attempt_at = current.gmail_last_synced_at
            current.gmail_next_sync_at = None
            current.gmail_retry_count = 0
            if initializing:
                current.gmail_initial_sync_completed_at = current.gmail_last_synced_at
            current.gmail_sync_status = (
                Mailbox.GmailSyncStatus.COVERAGE_GAP
                if current.gmail_coverage_gap_detected_at
                else Mailbox.GmailSyncStatus.READY
            )
            current.last_error_code = ""
            current.save(update_fields=[
                "gmail_history_id", "gmail_last_synced_at", "gmail_initial_sync_completed_at",
                "gmail_sync_status", "last_error_code", "gmail_last_attempt_at",
                "gmail_next_sync_at", "gmail_retry_count", "updated_at",
            ])
        return count
