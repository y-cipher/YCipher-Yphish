from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from core.retention import prune_private_artifacts


class Command(BaseCommand):
    help = "Prune aged private files; metadata and audit history remain."

    def add_arguments(self, parser):
        parser.add_argument("--execute", action="store_true")

    def handle(self, *args, **options):
        if options["execute"] and not settings.ARTIFACT_RETENTION_ENABLED:
            raise CommandError("ARTIFACT_RETENTION_ENABLED must be enabled")
        result = prune_private_artifacts(dry_run=not options["execute"])
        self.stdout.write(
            f"eligible={result['eligible']} deleted={result['deleted']} file_errors={result['file_errors']}"
        )
        if result["file_errors"]:
            raise CommandError("Private file deletion failed; retry after storage repair")
