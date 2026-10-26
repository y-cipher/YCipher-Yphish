"""Operational Gmail/queue health without mailbox content or credentials."""

import json

from celery import current_app
from django.core.management.base import BaseCommand
from django.db.models import Count
from django.utils import timezone
from kombu import Connection

from core.models import AnalysisRun, Mailbox
from core.analysis_runtime import RUN_KEYS


class Command(BaseCommand):
    help = "Report broker/worker health, analysis backlog, and Gmail synchronization lag."

    def add_arguments(self, parser):
        parser.add_argument("--json", action="store_true")

    def handle(self, *args, **options):
        now = timezone.now()
        broker = "unavailable"
        workers = 0
        try:
            with Connection(current_app.conf.broker_url, connect_timeout=2) as connection:
                connection.ensure_connection(max_retries=1)
                broker = "connected"
            replies = current_app.control.ping(timeout=2) or []
            workers = len(replies)
        except Exception:
            # Intentionally omit exception text; transport URLs may contain credentials.
            pass
        mailboxes = []
        for mailbox in Mailbox.objects.filter(
            provider=Mailbox.Provider.GMAIL, state=Mailbox.State.ACTIVE,
        ).exclude(gmail_enrollment_history_id="").order_by("organization__slug", "address"):
            lag = int((now - mailbox.gmail_last_synced_at).total_seconds()) if mailbox.gmail_last_synced_at else None
            mailboxes.append({
                "organization": mailbox.organization.slug,
                "mailbox": mailbox.address,
                "status": mailbox.gmail_sync_status,
                "last_successful_sync": mailbox.gmail_last_synced_at.isoformat() if mailbox.gmail_last_synced_at else None,
                "sync_lag_seconds": lag,
                "next_sync": mailbox.gmail_next_sync_at.isoformat() if mailbox.gmail_next_sync_at else None,
                "coverage_gap": bool(mailbox.gmail_coverage_gap_detected_at),
            })
        counts = dict(AnalysisRun.objects.filter(idempotency_key__in=RUN_KEYS).values_list(
            "state",
        ).annotate(count=Count("pk")))
        oldest = AnalysisRun.objects.filter(
            idempotency_key__in=RUN_KEYS, state=AnalysisRun.State.QUEUED,
        ).order_by("created_at").first()
        stale_leases = AnalysisRun.objects.filter(
            idempotency_key__in=RUN_KEYS, state=AnalysisRun.State.RUNNING,
            lease_expires_at__lt=now,
        ).count()
        report = {"broker": broker, "workers_responding": workers,
                  "queue_health": "ready" if broker == "connected" and workers else "degraded",
                  "analysis_runs": counts, "oldest_pending_seconds":
                  int((now - oldest.created_at).total_seconds()) if oldest else None,
                  "stale_analysis_leases": stale_leases, "mailboxes": mailboxes}
        if options["json"]:
            self.stdout.write(json.dumps(report, sort_keys=True))
        else:
            self.stdout.write(f"Queue: {report['queue_health']} (broker={broker}, workers={workers})")
            self.stdout.write(f"Analysis runs: {counts}")
            self.stdout.write(f"Oldest pending: {report['oldest_pending_seconds']}s; stale leases: {stale_leases}")
            for item in mailboxes:
                self.stdout.write(
                    f"{item['organization']}/{item['mailbox']}: {item['status']}, "
                    f"lag={item['sync_lag_seconds']}s, last_success={item['last_successful_sync']}"
                )
