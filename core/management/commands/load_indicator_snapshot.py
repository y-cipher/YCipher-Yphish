"""Import a curated local indicator cache file without network access."""

from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from core.indicators import MAX_SNAPSHOT_BYTES, import_snapshot
from core.models import IndicatorSnapshot


class Command(BaseCommand):
    help = "Import a timestamped exact-match indicator JSON snapshot from a local file."

    def add_arguments(self, parser):
        parser.add_argument("path", help="Local JSON snapshot path")
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--operational", action="store_true")
        group.add_argument("--synthetic", action="store_true")

    def handle(self, *args, **options):
        path = Path(options["path"])
        try:
            if path.stat().st_size > MAX_SNAPSHOT_BYTES:
                raise ValueError("Indicator snapshot exceeds the byte limit")
            raw = path.read_bytes()
            snapshot, created = import_snapshot(
                raw, expected_kind=IndicatorSnapshot.Kind.OPERATIONAL
                if options["operational"] else IndicatorSnapshot.Kind.SYNTHETIC,
            )
        except (OSError, ValueError) as exc:
            # Import validation messages contain no indicator values or file bytes.
            raise CommandError(str(exc)) from None
        self.stdout.write(
            f"{'Imported' if created else 'Already loaded'} {snapshot.kind} snapshot "
            f"{snapshot.source_name} ({snapshot.indicators.count()} exact indicators)."
        )
