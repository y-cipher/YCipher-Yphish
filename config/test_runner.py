"""Build isolated static assets before exercising production-style templates."""

from tempfile import TemporaryDirectory

from django.conf import settings
from django.core.management import call_command
from django.test.runner import DiscoverRunner
from django.test.utils import override_settings


class StaticFilesTestRunner(DiscoverRunner):
    def run_tests(self, test_labels, **kwargs):
        # Django tests render with DEBUG=False. Keep the real manifest backend
        # and collect into a fresh directory rather than relying on deployment
        # artifacts or allowing tests to overwrite the running site's files.
        with TemporaryDirectory(prefix="yphish-test-static-") as static_root:
            with override_settings(
                STATIC_ROOT=static_root,
                # Reset cached storage instances to use this isolated root.
                STORAGES=dict(settings.STORAGES),
            ):
                call_command("collectstatic", interactive=False, verbosity=0)
                return super().run_tests(test_labels, **kwargs)
