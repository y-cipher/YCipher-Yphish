"""Sign an explicit local training-data selection after operator approval."""

from django.core.management.base import BaseCommand, CommandError

from core.ml_dataset import DatasetError, create_selection


class Command(BaseCommand):
    help = "Create a signed selection manifest for an explicitly approved local JSONL corpus."

    def add_arguments(self, parser):
        parser.add_argument("--dataset", required=True)
        parser.add_argument("--selection", required=True)
        parser.add_argument("--approved-by", required=True)
        parser.add_argument("--authorization-reference", required=True)
        parser.add_argument("--expires-at", required=True)
        parser.add_argument("--train-before", required=True)
        parser.add_argument("--calibration-before", required=True)
        kind = parser.add_mutually_exclusive_group(required=True)
        kind.add_argument("--curated", action="store_true")
        kind.add_argument("--synthetic", action="store_true")
        parser.add_argument("--private-mailbox-content", action="store_true")

    def handle(self, *args, **options):
        try:
            selection = create_selection(
                dataset_path=options["dataset"], selection_path=options["selection"],
                source_kind="curated" if options["curated"] else "synthetic",
                approved_by=options["approved_by"],
                authorization_reference=options["authorization_reference"],
                expires_at=options["expires_at"], train_before=options["train_before"],
                calibration_before=options["calibration_before"],
                private_mailbox_content=options["private_mailbox_content"],
            )
        except DatasetError as exc:
            raise CommandError(str(exc)) from None
        self.stdout.write(
            f"Signed {selection['source_kind']} dataset selection for {selection['dataset_file']}; "
            f"digest={selection['dataset_sha256']}."
        )
