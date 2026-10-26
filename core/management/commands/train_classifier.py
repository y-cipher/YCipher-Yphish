"""Train only from a configured, signed local dataset selection."""

import json

from django.core.management.base import BaseCommand, CommandError

from core.ml_dataset import DatasetError
from core.ml_pipeline import ModelError, export_model, train_from_selection


class Command(BaseCommand):
    help = "Fit TF-IDF/logistic model, independently calibrate, evaluate, and export a signed version."

    def add_arguments(self, parser):
        parser.add_argument("--model-version", required=True)

    def handle(self, *args, **options):
        try:
            model, metrics, selection = train_from_selection()
            target, manifest = export_model(model, metrics, selection, version=options["model_version"])
        except (DatasetError, ModelError) as exc:
            raise CommandError(str(exc)) from None
        self.stdout.write(f"Exported classifier {manifest['version']} to {target}.")
        self.stdout.write(json.dumps(metrics, sort_keys=True))
