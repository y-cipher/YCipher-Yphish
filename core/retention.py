"""Resumable deletion of aged private artifact files.

Case, evidence, and audit metadata remain in PostgreSQL for review. A separate
approved policy is required before deleting those records.
"""

from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import Artifact, AuditEvent, Organization


def prune_private_artifacts(*, dry_run=False, limit=None, now=None):
    """Mark rows first, then remove files; resume interrupted removals next run."""
    now = now or timezone.now()
    limit = limit or settings.ARTIFACT_RETENTION_BATCH_SIZE
    counts = {"eligible": 0, "deleted": 0, "file_errors": 0}
    for organization in Organization.objects.order_by("pk"):
        cutoff = now - timedelta(days=organization.retention_days)
        candidates = Artifact.objects.filter(
            organization=organization,
            state=Artifact.State.STORED,
            created_at__lt=cutoff,
        ).order_by("created_at").values_list("pk", flat=True)[: max(0, limit - counts["eligible"])]
        for artifact_id in list(candidates):
            counts["eligible"] += 1
            if dry_run:
                continue
            with transaction.atomic():
                artifact = Artifact.objects.select_for_update().filter(
                    pk=artifact_id, state=Artifact.State.STORED,
                ).first()
                if not artifact:
                    continue
                artifact.state = Artifact.State.DELETED
                artifact.save(update_fields=["state"])
                AuditEvent.objects.create(
                    organization=organization, case=artifact.case,
                    event_type="private_artifact_retention_deleted",
                    subject_type="artifact", subject_id=artifact.pk,
                    details={"retention_days": organization.retention_days, "kind": artifact.kind},
                    occurred_at=now,
                )
        if counts["eligible"] >= limit:
            break
    if dry_run:
        return counts
    # A committed deleted row retains its path until the file deletion succeeds.
    # This also recovers a crash after the database transaction above.
    for artifact in Artifact.objects.filter(state=Artifact.State.DELETED).exclude(file="").order_by(
        "created_at",
    )[:limit]:
        try:
            artifact.file.storage.delete(artifact.file.name)
        except OSError:
            counts["file_errors"] += 1
            continue
        Artifact.objects.filter(pk=artifact.pk, state=Artifact.State.DELETED).update(file="")
        counts["deleted"] += 1
    return counts
