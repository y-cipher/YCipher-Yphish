"""Real CSRF checks on login, including browser form provenance."""

from django.conf import settings
from django.contrib.auth import SESSION_KEY, get_user_model
from django.test import Client, TestCase, override_settings
from django.urls import reverse


@override_settings(SECURE_SSL_REDIRECT=False)
class LoginCsrfTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.password = "Synthetic-login-test-63!"
        cls.user = get_user_model().objects.create_user(
            username="csrf_login_user", password=cls.password,
        )

    def login_form(self):
        client = Client(enforce_csrf_checks=True)
        response = client.get(reverse("dashboard_login"))
        self.assertEqual(response.status_code, 200)
        token = client.cookies[settings.CSRF_COOKIE_NAME].value
        return client, response, token

    def test_same_origin_form_policy_and_token_allow_login(self):
        client, form, token = self.login_form()
        self.assertContains(form, '<meta name="referrer" content="same-origin">')
        self.assertNotContains(form, 'content="no-referrer"')
        self.assertEqual(form.headers["Referrer-Policy"], "same-origin")
        response = client.post(reverse("dashboard_login"), {
            "username": self.user.username,
            "password": self.password,
            "csrfmiddlewaretoken": token,
        }, HTTP_ORIGIN="http://testserver")
        self.assertRedirects(response, reverse("dashboard_home"), fetch_redirect_response=False)
        self.assertEqual(client.session[SESSION_KEY], str(self.user.pk))

    def test_null_and_foreign_origins_are_rejected_with_valid_token(self):
        for origin in ("null", "https://attacker.example"):
            with self.subTest(origin=origin):
                client, _, token = self.login_form()
                response = client.post(reverse("dashboard_login"), {
                    "username": self.user.username,
                    "password": self.password,
                    "csrfmiddlewaretoken": token,
                }, HTTP_ORIGIN=origin)
                self.assertEqual(response.status_code, 403)
                self.assertNotIn(SESSION_KEY, client.session)

    def test_same_origin_without_token_is_rejected(self):
        client, _, _ = self.login_form()
        response = client.post(reverse("dashboard_login"), {
            "username": self.user.username,
            "password": self.password,
        }, HTTP_ORIGIN="http://testserver")
        self.assertEqual(response.status_code, 403)
        self.assertNotIn(SESSION_KEY, client.session)
