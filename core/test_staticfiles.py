"""Dashboard rendering must exercise the real, strict staticfiles manifest."""

from django.contrib.staticfiles.storage import staticfiles_storage
from django.test import SimpleTestCase, override_settings
from django.urls import reverse


@override_settings(DEBUG=False, SECURE_SSL_REDIRECT=False)
class StaticFilesManifestTests(SimpleTestCase):
    def test_login_references_existing_hashed_dashboard_assets(self):
        response = self.client.get(reverse("dashboard_login"))
        self.assertEqual(response.status_code, 200)
        for name in (
            "core/bootstrap.min.css",
            "core/dashboard.css",
            "core/dashboard.js",
        ):
            with self.subTest(asset=name):
                hashed_name = staticfiles_storage.stored_name(name)
                self.assertNotEqual(hashed_name, name)
                self.assertTrue(staticfiles_storage.exists(hashed_name))
                self.assertContains(response, staticfiles_storage.url(name))

    def test_missing_asset_still_fails_strict_manifest_validation(self):
        with self.assertRaisesMessage(ValueError, "Missing staticfiles manifest entry"):
            staticfiles_storage.url("core/not-a-shipped-asset.css")
