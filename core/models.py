"""Tenant-scoped records for ingestion, analysis, response, and audit."""

import uuid

from django.conf import settings
from django.core.validators import RegexValidator
from django.db import models
from django.db.models import Q
from django.db.models.functions import Lower

from .storage import PrivateArtifactStorage


SHA256_VALIDATOR = RegexValidator(
    regex=r"^[0-9a-f]{64}$", message="Use a lowercase SHA-256 hex digest."
)


def artifact_upload_path(instance, _filename):
    """Never let an untrusted attachment filename select a storage path."""
    return f"{instance.organization_id}/{instance.case_id}/{uuid.uuid4().hex}"


class UUIDModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        abstract = True


class Organization(UUIDModel):
    name = models.CharField(max_length=200)
    slug = models.SlugField(max_length=80, unique=True)
    is_active = models.BooleanField(default=True)
    retention_days = models.PositiveIntegerField(default=90)
    gmail_service_account_client_id = models.CharField(max_length=255, blank=True)
    gmail_access_verified_at = models.DateTimeField(null=True, blank=True)
    gmail_response_enabled = models.BooleanField(default=False)
    gmail_response_service_account_client_id = models.CharField(max_length=255, blank=True)
    gmail_response_scope = models.CharField(max_length=255, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(retention_days__gte=1) & Q(retention_days__lte=3650),
                name="org_retention_days_range",
            ),
        ]

    def __str__(self):
        return self.name


class Membership(UUIDModel):
    class Role(models.TextChoices):
        OWNER = "owner", "Owner"
        ADMIN = "admin", "Administrator"
        ANALYST = "analyst", "Analyst"
        VIEWER = "viewer", "Viewer"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT, related_name="memberships")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="yphish_memberships")
    role = models.CharField(max_length=16, choices=Role.choices)
    is_active = models.BooleanField(default=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["organization", "user"], name="membership_org_user_unique"),
            models.CheckConstraint(condition=Q(role__in=["owner", "admin", "analyst", "viewer"]), name="membership_role_valid"),
        ]
        indexes = [models.Index(fields=["user", "is_active"], name="membership_user_active_idx")]


class Mailbox(UUIDModel):
    class Provider(models.TextChoices):
        LEGACY = "legacy", "Legacy or unconfigured"
        GMAIL = "gmail", "Google Workspace Gmail"

    class State(models.TextChoices):
        PENDING = "pending", "Pending"
        ACTIVE = "active", "Active"
        PAUSED = "paused", "Paused"
        ERROR = "error", "Error"

    class GmailSyncStatus(models.TextChoices):
        NOT_ENROLLED = "not_enrolled", "Not enrolled"
        ENROLLING = "enrolling", "Enrollment verification"
        INITIALIZING = "initializing", "Initial synchronization"
        READY = "ready", "Incremental synchronization"
        COVERAGE_GAP = "coverage_gap", "Coverage gap"
        ERROR = "error", "Synchronization error"
        DISCONNECTED = "disconnected", "Network disconnected"
        AUTHORIZATION_FAILED = "authorization_failed", "Authorization failed"
        THROTTLED = "throttled", "Provider throttled"
        UNAVAILABLE = "unavailable", "Provider unavailable"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT, related_name="mailboxes")
    address = models.EmailField(max_length=320)
    display_name = models.CharField(max_length=200, blank=True)
    provider_mailbox_id = models.CharField(max_length=255, blank=True)
    provider = models.CharField(max_length=16, choices=Provider.choices, default=Provider.GMAIL)
    gmail_history_id = models.CharField(max_length=64, blank=True)
    gmail_label_id = models.CharField(max_length=255, blank=True)
    gmail_last_synced_at = models.DateTimeField(null=True, blank=True)
    gmail_last_attempt_at = models.DateTimeField(null=True, blank=True)
    gmail_next_sync_at = models.DateTimeField(null=True, blank=True)
    gmail_retry_count = models.PositiveIntegerField(default=0)
    gmail_sync_status = models.CharField(max_length=20, choices=GmailSyncStatus.choices, default=GmailSyncStatus.NOT_ENROLLED)
    gmail_enrolled_at = models.DateTimeField(null=True, blank=True)
    gmail_enrollment_history_id = models.CharField(max_length=64, blank=True)
    gmail_initial_sync_completed_at = models.DateTimeField(null=True, blank=True)
    gmail_coverage_gap_from_history_id = models.CharField(max_length=64, blank=True)
    gmail_coverage_gap_detected_at = models.DateTimeField(null=True, blank=True)
    investigation_sender_context_enabled = models.BooleanField(default=False)
    investigation_conversation_enabled = models.BooleanField(default=False)
    state = models.CharField(max_length=16, choices=State.choices, default=State.PENDING)
    last_error_code = models.CharField(max_length=100, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(Lower("address"), "organization", name="mailbox_org_address_ci_unique"),
            models.UniqueConstraint(
                fields=["organization", "provider_mailbox_id"],
                condition=~Q(provider_mailbox_id=""),
                name="mailbox_org_provider_unique",
            ),
            models.CheckConstraint(condition=Q(state__in=["pending", "active", "paused", "error"]), name="mailbox_state_valid"),
            models.CheckConstraint(condition=Q(provider__in=["legacy", "gmail"]), name="mailbox_provider_valid"),
            models.CheckConstraint(condition=Q(gmail_sync_status__in=["not_enrolled", "enrolling", "initializing", "ready", "coverage_gap", "error", "disconnected", "authorization_failed", "throttled", "unavailable"]), name="mailbox_gmail_sync_status_valid"),
        ]
        indexes = [models.Index(fields=["organization", "state"], name="mailbox_org_state_idx"), models.Index(fields=["gmail_sync_status", "gmail_next_sync_at"], name="mailbox_gmail_due_idx")]

    def __str__(self):
        return self.address


class EmailCase(UUIDModel):
    class State(models.TextChoices):
        QUEUED = "queued", "Queued"
        PROCESSING = "processing", "Processing"
        ANALYZED = "analyzed", "Analyzed"
        ACTION_PENDING = "action_pending", "Action pending"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    class Verdict(models.TextChoices):
        UNKNOWN = "unknown", "Unknown"
        LEGITIMATE = "legitimate", "Legitimate"
        SUSPICIOUS = "suspicious", "Suspicious"
        MALICIOUS = "malicious", "Malicious"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT, related_name="email_cases")
    mailbox = models.ForeignKey(Mailbox, on_delete=models.PROTECT, related_name="email_cases")
    provider_immutable_id = models.CharField(
        max_length=512,
        help_text="Legacy identity field; new Gmail cases store their Gmail message ID here too for existing integrity guards.",
    )
    gmail_message_id = models.CharField(max_length=512, blank=True)
    gmail_thread_id = models.CharField(max_length=512, blank=True)
    gmail_label_ids = models.JSONField(default=list, blank=True)
    gmail_internal_date_ms = models.CharField(max_length=32, blank=True)
    gmail_is_historical = models.BooleanField(default=False)
    gmail_deleted_at = models.DateTimeField(null=True, blank=True)
    internet_message_id = models.CharField(max_length=512, blank=True)
    subject = models.CharField(max_length=998, blank=True)
    sender_address = models.EmailField(max_length=320, blank=True)
    received_at = models.DateTimeField(null=True, blank=True)
    state = models.CharField(max_length=20, choices=State.choices, default=State.QUEUED)
    verdict = models.CharField(max_length=16, choices=Verdict.choices, default=Verdict.UNKNOWN)
    last_error_code = models.CharField(max_length=100, blank=True)
    processing_started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "mailbox", "provider_immutable_id"],
                condition=~Q(provider_immutable_id=""),
                name="case_org_mailbox_immutable_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "mailbox", "gmail_message_id"],
                condition=~Q(gmail_message_id=""),
                name="case_org_mailbox_gmail_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(gmail_message_id="") | Q(provider_immutable_id=models.F("gmail_message_id")),
                name="case_gmail_legacy_id_match",
            ),
            models.CheckConstraint(condition=Q(state__in=["queued", "processing", "analyzed", "action_pending", "completed", "failed"]), name="case_state_valid"),
            models.CheckConstraint(condition=Q(verdict__in=["unknown", "legitimate", "suspicious", "malicious"]), name="case_verdict_valid"),
            models.CheckConstraint(
                condition=Q(completed_at__isnull=True) | Q(state__in=["completed", "failed"]),
                name="case_completion_state_valid",
            ),
        ]
        indexes = [
            models.Index(fields=["organization", "state", "-created_at"], name="case_org_state_created_idx"),
            models.Index(fields=["mailbox", "-received_at"], name="case_mailbox_received_idx"),
            models.Index(fields=["mailbox", "gmail_thread_id"], name="case_mailbox_thread_idx"),
        ]


class Artifact(UUIDModel):
    class Kind(models.TextChoices):
        ORIGINAL_MIME = "original_mime", "Original MIME"
        ATTACHMENT = "attachment", "Attachment"
        DERIVED = "derived", "Derived content"
        REPORT = "report", "Report"

    class State(models.TextChoices):
        PENDING = "pending", "Pending"
        STORED = "stored", "Stored"
        FAILED = "failed", "Failed"
        DELETED = "deleted", "Deleted"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT, related_name="artifacts")
    case = models.ForeignKey(EmailCase, on_delete=models.PROTECT, related_name="artifacts")
    kind = models.CharField(max_length=20, choices=Kind.choices)
    state = models.CharField(max_length=16, choices=State.choices, default=State.PENDING)
    file = models.FileField(
        upload_to=artifact_upload_path,
        storage=PrivateArtifactStorage(),
        max_length=500,
        blank=True,
    )
    original_filename = models.CharField(max_length=255, blank=True)
    content_type = models.CharField(max_length=255, blank=True)
    size_bytes = models.BigIntegerField(null=True, blank=True)
    sha256 = models.CharField(max_length=64, blank=True, validators=[SHA256_VALIDATOR])
    error_code = models.CharField(max_length=100, blank=True)

    class Meta:
        constraints = [
            models.CheckConstraint(condition=Q(kind__in=["original_mime", "attachment", "derived", "report"]), name="artifact_kind_valid"),
            models.CheckConstraint(condition=Q(state__in=["pending", "stored", "failed", "deleted"]), name="artifact_state_valid"),
            models.CheckConstraint(condition=Q(size_bytes__isnull=True) | Q(size_bytes__gte=0), name="artifact_size_nonnegative"),
            models.CheckConstraint(
                condition=~Q(state="stored") | (Q(size_bytes__isnull=False) & ~Q(file="") & ~Q(sha256="")),
                name="artifact_stored_metadata_required",
            ),
        ]
        indexes = [
            models.Index(fields=["organization", "case", "kind"], name="artifact_case_kind_idx"),
            models.Index(fields=["organization", "sha256"], name="artifact_org_sha256_idx"),
        ]


class AnalysisRun(UUIDModel):
    class State(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        SUCCEEDED = "succeeded", "Succeeded"
        FAILED = "failed", "Failed"
        CANCELLED = "cancelled", "Cancelled"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT, related_name="analysis_runs")
    case = models.ForeignKey(EmailCase, on_delete=models.PROTECT, related_name="analysis_runs")
    attempt = models.PositiveIntegerField(default=1)
    idempotency_key = models.CharField(max_length=200, blank=True)
    state = models.CharField(max_length=16, choices=State.choices, default=State.QUEUED)
    engine_version = models.CharField(max_length=100, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    summary = models.JSONField(default=dict, blank=True)
    error_code = models.CharField(max_length=100, blank=True)
    lease_expires_at = models.DateTimeField(null=True, blank=True)
    lease_token = models.UUIDField(null=True, blank=True)
    next_retry_at = models.DateTimeField(null=True, blank=True)
    last_dispatched_at = models.DateTimeField(null=True, blank=True)
    retry_count = models.PositiveIntegerField(default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["case", "attempt"], name="run_case_attempt_unique"),
            models.UniqueConstraint(fields=["case", "idempotency_key"], condition=~Q(idempotency_key=""), name="run_case_idempotency_unique"),
            models.CheckConstraint(condition=Q(attempt__gte=1), name="run_attempt_positive"),
            models.CheckConstraint(condition=Q(state__in=["queued", "running", "succeeded", "failed", "cancelled"]), name="run_state_valid"),
            models.CheckConstraint(
                condition=Q(finished_at__isnull=True) | Q(state__in=["succeeded", "failed", "cancelled"]),
                name="run_finish_state_valid",
            ),
        ]
        indexes = [models.Index(fields=["organization", "state", "-created_at"], name="run_org_state_created_idx"), models.Index(fields=["state", "next_retry_at"], name="run_due_retry_idx")]


class InvestigationRun(UUIDModel):
    class State(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT, related_name="investigations")
    mailbox = models.ForeignKey(Mailbox, on_delete=models.PROTECT, related_name="investigations")
    case = models.ForeignKey(EmailCase, on_delete=models.PROTECT, related_name="investigations")
    analysis_run = models.ForeignKey(AnalysisRun, on_delete=models.PROTECT, related_name="investigations")
    policy_version = models.CharField(max_length=50, default="explicit-v1")
    state = models.CharField(max_length=16, choices=State.choices, default=State.QUEUED)
    rounds_used = models.PositiveSmallIntegerField(default=0)
    calls_used = models.PositiveSmallIntegerField(default=0)
    stopping_reason = models.CharField(max_length=100, blank=True)
    error_code = models.CharField(max_length=100, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    lease_token = models.UUIDField(null=True, blank=True)
    lease_expires_at = models.DateTimeField(null=True, blank=True)
    last_dispatched_at = models.DateTimeField(null=True, blank=True)
    summary = models.JSONField(default=dict, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["case", "policy_version"], name="investigation_case_policy_unique"),
            models.CheckConstraint(condition=Q(state__in=["queued", "running", "completed", "failed"]), name="investigation_state_valid"),
            models.CheckConstraint(condition=Q(finished_at__isnull=True) | Q(state__in=["completed", "failed"]), name="investigation_finish_state_valid"),
        ]
        indexes = [models.Index(fields=["state", "last_dispatched_at"], name="investigation_dispatch_idx")]


class InvestigationStep(UUIDModel):
    class State(models.TextChoices):
        OBSERVED = "observed", "Observed"
        UNAVAILABLE = "unavailable", "Unavailable"
        ERROR = "error", "Error"
        REJECTED = "rejected", "Rejected"

    investigation = models.ForeignKey(InvestigationRun, on_delete=models.PROTECT, related_name="steps")
    round_number = models.PositiveSmallIntegerField()
    call_number = models.PositiveSmallIntegerField()
    tool_id = models.CharField(max_length=40)
    arguments = models.JSONField(default=dict)
    result = models.JSONField(default=dict)
    limitations = models.JSONField(default=list)
    state = models.CharField(max_length=16, choices=State.choices)
    state_hash = models.CharField(max_length=64)
    started_at = models.DateTimeField()
    finished_at = models.DateTimeField()

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["investigation", "call_number"], name="investigation_step_number_unique"),
            models.UniqueConstraint(fields=["investigation", "state_hash"], name="investigation_step_state_unique"),
            models.CheckConstraint(condition=Q(round_number__gte=1) & Q(call_number__gte=1), name="investigation_step_numbers_valid"),
            models.CheckConstraint(condition=Q(state__in=["observed", "unavailable", "error", "rejected"]), name="investigation_step_state_valid"),
        ]


class Evidence(UUIDModel):
    class Source(models.TextChoices):
        INGESTION = "ingestion", "Ingestion"
        PARSER = "parser", "Parser"
        RULE = "rule", "Rule"
        MODEL = "model", "Model"
        TOOL = "tool", "Tool"
        OPERATOR = "operator", "Operator"

    class State(models.TextChoices):
        OBSERVED = "observed", "Observed"
        UNAVAILABLE = "unavailable", "Unavailable"
        ERROR = "error", "Error"

    class Trust(models.TextChoices):
        INTERNAL = "internal", "Internal"
        EXTERNAL = "external", "External"
        UNTRUSTED = "untrusted", "Untrusted content"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT, related_name="evidence")
    case = models.ForeignKey(EmailCase, on_delete=models.PROTECT, related_name="evidence")
    idempotency_key = models.CharField(max_length=200)
    analysis_run = models.ForeignKey(AnalysisRun, on_delete=models.PROTECT, null=True, blank=True, related_name="evidence")
    artifact = models.ForeignKey(Artifact, on_delete=models.PROTECT, null=True, blank=True, related_name="evidence")
    source = models.CharField(max_length=16, choices=Source.choices)
    source_version = models.CharField(max_length=100, blank=True)
    rule_id = models.CharField(max_length=100, blank=True)
    source_field = models.CharField(max_length=200, blank=True)
    source_span = models.JSONField(default=dict, blank=True)
    provenance = models.JSONField(default=dict, blank=True)
    limitations = models.JSONField(default=list, blank=True)
    state = models.CharField(max_length=16, choices=State.choices, default=State.OBSERVED)
    trust = models.CharField(max_length=16, choices=Trust.choices, default=Trust.UNTRUSTED)
    label = models.CharField(max_length=200)
    details = models.JSONField(default=dict, blank=True)
    observed_at = models.DateTimeField()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "case", "idempotency_key"],
                condition=~Q(idempotency_key=""),
                name="evidence_case_idempotency_unique",
            ),
            models.CheckConstraint(condition=Q(source__in=["ingestion", "parser", "rule", "model", "tool", "operator"]), name="evidence_source_valid"),
            models.CheckConstraint(condition=Q(state__in=["observed", "unavailable", "error"]), name="evidence_state_valid"),
            models.CheckConstraint(condition=Q(trust__in=["internal", "external", "untrusted"]), name="evidence_trust_valid"),
        ]
        indexes = [models.Index(fields=["organization", "case", "-observed_at"], name="evidence_case_observed_idx")]


class IndicatorSnapshot(UUIDModel):
    """An immutable, timestamped local cache import; never a live lookup."""

    class Kind(models.TextChoices):
        OPERATIONAL = "operational", "Operational feed"
        SYNTHETIC = "synthetic", "Synthetic test feed"

    source_name = models.SlugField(max_length=100)
    kind = models.CharField(max_length=16, choices=Kind.choices)
    fetched_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    sha256 = models.CharField(max_length=64, validators=[SHA256_VALIDATOR])
    is_active = models.BooleanField(default=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["source_name", "kind", "fetched_at"], name="indicator_snapshot_unique"),
            models.CheckConstraint(condition=Q(kind__in=["operational", "synthetic"]), name="indicator_snapshot_kind_valid"),
            models.CheckConstraint(condition=Q(expires_at__gt=models.F("fetched_at")), name="indicator_snapshot_window_valid"),
        ]
        indexes = [models.Index(fields=["kind", "is_active", "expires_at"], name="indicator_snapshot_due_idx")]


class Indicator(UUIDModel):
    class Type(models.TextChoices):
        DOMAIN = "domain", "Exact domain"
        URL = "url", "Exact URL"
        EMAIL = "email", "Exact email address"
        SHA256 = "sha256", "Exact attachment SHA-256"

    snapshot = models.ForeignKey(IndicatorSnapshot, on_delete=models.PROTECT, related_name="indicators")
    indicator_type = models.CharField(max_length=16, choices=Type.choices)
    value = models.CharField(max_length=2048)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["snapshot", "indicator_type", "value"], name="indicator_snapshot_value_unique"),
            models.CheckConstraint(condition=Q(indicator_type__in=["domain", "url", "email", "sha256"]), name="indicator_type_valid"),
        ]
        indexes = [models.Index(fields=["indicator_type", "value"], name="indicator_exact_lookup_idx")]


class ActionExecution(UUIDModel):
    class Action(models.TextChoices):
        CATEGORIZE = "categorize", "Categorize"
        MOVE = "move", "Move"
        RESTORE = "restore", "Restore"

    class State(models.TextChoices):
        PROPOSED = "proposed", "Proposed"
        AUTHORIZED = "authorized", "Authorized"
        RUNNING = "running", "Running"
        RECONCILING = "reconciling", "Reconciling"
        SUCCEEDED = "succeeded", "Succeeded"
        FAILED = "failed", "Failed"
        SKIPPED = "skipped", "Skipped"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT, related_name="action_executions")
    case = models.ForeignKey(EmailCase, on_delete=models.PROTECT, related_name="action_executions")
    analysis_run = models.ForeignKey(AnalysisRun, on_delete=models.PROTECT, null=True, blank=True, related_name="action_executions")
    action = models.CharField(max_length=16, choices=Action.choices)
    state = models.CharField(max_length=16, choices=State.choices, default=State.PROPOSED)
    idempotency_key = models.CharField(max_length=200)
    policy_version = models.CharField(max_length=100, blank=True)
    target = models.JSONField(default=dict, blank=True)
    result = models.JSONField(default=dict, blank=True)
    provider_operation_id = models.CharField(max_length=255, blank=True)
    requested_at = models.DateTimeField()
    executed_at = models.DateTimeField(null=True, blank=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    error_code = models.CharField(max_length=100, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["organization", "idempotency_key"], name="action_org_idempotency_unique"),
            models.CheckConstraint(condition=~Q(idempotency_key=""), name="action_idempotency_required"),
            models.CheckConstraint(condition=Q(action__in=["categorize", "move", "restore"]), name="action_type_valid"),
            models.CheckConstraint(condition=Q(state__in=["proposed", "authorized", "running", "reconciling", "succeeded", "failed", "skipped"]), name="action_state_valid"),
            models.CheckConstraint(condition=Q(verified_at__isnull=True) | Q(state="succeeded"), name="action_verified_success_only"),
            models.CheckConstraint(
                condition=~Q(state__in=["failed", "reconciling", "skipped"]) | ~Q(error_code=""),
                name="action_failure_code_required",
            ),
        ]
        indexes = [models.Index(fields=["organization", "case", "-requested_at"], name="action_case_requested_idx")]


class Feedback(UUIDModel):
    class State(models.TextChoices):
        SUBMITTED = "submitted", "Submitted"
        REVIEWED = "reviewed", "Reviewed"
        REJECTED = "rejected", "Rejected"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT, related_name="feedback")
    case = models.ForeignKey(EmailCase, on_delete=models.PROTECT, related_name="feedback")
    submitted_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="yphish_feedback_submitted")
    proposed_verdict = models.CharField(max_length=16, choices=EmailCase.Verdict.choices)
    reason = models.TextField()
    state = models.CharField(max_length=16, choices=State.choices, default=State.SUBMITTED)
    reviewed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="yphish_feedback_reviewed")
    reviewed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.CheckConstraint(condition=Q(proposed_verdict__in=["unknown", "legitimate", "suspicious", "malicious"]), name="feedback_verdict_valid"),
            models.CheckConstraint(condition=Q(state__in=["submitted", "reviewed", "rejected"]), name="feedback_state_valid"),
            models.CheckConstraint(condition=Q(reviewed_at__isnull=True) | Q(state__in=["reviewed", "rejected"]), name="feedback_review_state_valid"),
        ]
        indexes = [models.Index(fields=["organization", "case", "-created_at"], name="feedback_case_created_idx")]


class AuditEvent(UUIDModel):
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT, related_name="audit_events")
    case = models.ForeignKey(EmailCase, on_delete=models.PROTECT, null=True, blank=True, related_name="audit_events")
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True, related_name="yphish_audit_events")
    event_type = models.CharField(max_length=100)
    subject_type = models.CharField(max_length=100, blank=True)
    subject_id = models.UUIDField(null=True, blank=True)
    correlation_id = models.UUIDField(default=uuid.uuid4)
    details = models.JSONField(default=dict, blank=True)
    occurred_at = models.DateTimeField()

    class Meta:
        constraints = [models.CheckConstraint(condition=~Q(event_type=""), name="audit_event_type_required")]
        indexes = [
            models.Index(fields=["organization", "-occurred_at"], name="audit_org_occurred_idx"),
            models.Index(fields=["organization", "case", "-occurred_at"], name="audit_case_occurred_idx"),
            models.Index(fields=["correlation_id"], name="audit_correlation_idx"),
        ]
