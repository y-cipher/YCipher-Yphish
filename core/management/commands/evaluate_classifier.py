"""Recompute held-out evaluation without fitting on calibration or test data."""

import json

from django.core.management.base import BaseCommand, CommandError

from core.ml_dataset import DatasetError
from core.ml_pipeline import ModelError, evaluate_from_selection


class Command(BaseCommand):
    help = "Re-evaluate a signed model against its authorized chronological holdout."

    def add_arguments(self, parser):
        parser.add_argument("--model-version", required=True)

    def handle(self, *args, **options):
        try:
            report = evaluate_from_selection(options["model_version"])
        except (DatasetError, ModelError) as exc:
            raise CommandError(str(exc)) from None
        self.stdout.write(json.dumps(report, sort_keys=True))
