from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import mail
from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from .tokens import default_token_generator, encode_uid

User = get_user_model()

TEST_REST_FRAMEWORK = {
    **settings.REST_FRAMEWORK,
    "DEFAULT_THROTTLE_RATES": {
        **settings.REST_FRAMEWORK.get("DEFAULT_THROTTLE_RATES", {}),
        "auth_login": "1000/min",
        "auth_forgot": "1000/min",
    },
}

@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    REST_FRAMEWORK=TEST_REST_FRAMEWORK,
)
class AuthAPITests(APITestCase):
    def setUp(self):
        super().setUp()
        cache.clear()
    def _extract_uid_token_from_email(self, body: str) -> tuple[str, str]:
        url = next((part for part in body.split() if "uid=" in part and "token=" in part), "")
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        uid = query.get("uid", [None])[0]
        token = query.get("token", [None])[0]
        self.assertIsNotNone(uid)
        self.assertIsNotNone(token)
        return uid, token

    def _register_user(self, email="john@example.com", password="StrongPass123!"):
        payload = {
            "email": email,
            "first_name": "John",
            "last_name": "Doe",
            "password1": password,
            "password2": password,
        }
        return self.client.post(reverse("auth-register"), payload, format="json")

    def _login_user(self, email="john@example.com", password="StrongPass123!"):
        payload = {"email": email, "password": password}
        return self.client.post(reverse("auth-login"), payload, format="json")

    def test_register_ok_and_email_sent(self):
        response = self._register_user()

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["message"], "Verification email sent")
        self.assertEqual(response.data["email"], "john@example.com")
        self.assertEqual(len(mail.outbox), 1)

        user = User.objects.get(email="john@example.com")
        self.assertFalse(user.is_email_verified)

    def test_verify_email_ok(self):
        self._register_user()
        uid, token = self._extract_uid_token_from_email(mail.outbox[-1].body)

        response = self.client.post(
            reverse("auth-email-verify-confirm"),
            {"uid": uid, "token": token},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["message"], "Email verified successfully.")

        user = User.objects.get(email="john@example.com")
        self.assertTrue(user.is_email_verified)

    def test_login_ok_and_refresh_ok(self):
        user = User.objects.create_user(
            email="john@example.com",
            password="StrongPass123!",
            is_email_verified=True,
        )
        self.assertTrue(user.is_email_verified)

        login_response = self._login_user()
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        self.assertIn("access", login_response.data)
        self.assertIn("refresh", login_response.data)

        refresh_response = self.client.post(
            reverse("auth-refresh"),
            {"refresh": login_response.data["refresh"]},
            format="json",
        )
        self.assertEqual(refresh_response.status_code, status.HTTP_200_OK)
        self.assertIn("access", refresh_response.data)

    def test_logout_blacklists_refresh_token(self):
        User.objects.create_user(
            email="john@example.com",
            password="StrongPass123!",
            is_email_verified=True,
        )
        login_response = self._login_user()
        access = login_response.data["access"]
        refresh = login_response.data["refresh"]

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        logout_response = self.client.post(reverse("auth-logout"), {"refresh": refresh}, format="json")
        self.assertEqual(logout_response.status_code, status.HTTP_200_OK)

        refresh_response = self.client.post(reverse("auth-refresh"), {"refresh": refresh}, format="json")
        self.assertEqual(refresh_response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_me_returns_user(self):
        User.objects.create_user(
            email="john@example.com",
            password="StrongPass123!",
            is_email_verified=True,
            first_name="John",
        )
        login_response = self._login_user()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {login_response.data['access']}")

        response = self.client.get(reverse("auth-me"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["email"], "john@example.com")
        self.assertEqual(response.data["first_name"], "John")

    def test_change_password_works(self):
        User.objects.create_user(
            email="john@example.com",
            password="StrongPass123!",
            is_email_verified=True,
        )
        login_response = self._login_user()

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {login_response.data['access']}")
        change_response = self.client.post(
            reverse("auth-password-change"),
            {
                "old_password": "StrongPass123!",
                "new_password1": "NewStrongPass123!",
                "new_password2": "NewStrongPass123!",
            },
            format="json",
        )
        self.assertEqual(change_response.status_code, status.HTTP_200_OK)

        old_login = self._login_user(password="StrongPass123!")
        self.assertEqual(old_login.status_code, status.HTTP_400_BAD_REQUEST)

        new_login = self._login_user(password="NewStrongPass123!")
        self.assertEqual(new_login.status_code, status.HTTP_200_OK)

    def test_forgot_reset_works_and_invalid_expired_token(self):
        user = User.objects.create_user(
            email="john@example.com",
            password="StrongPass123!",
            is_email_verified=True,
        )

        forgot_response = self.client.post(
            reverse("auth-password-forgot"),
            {"email": "john@example.com"},
            format="json",
        )
        self.assertEqual(forgot_response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(mail.outbox), 1)

        uid, token = self._extract_uid_token_from_email(mail.outbox[-1].body)

        reset_response = self.client.post(
            reverse("auth-password-reset"),
            {
                "uid": uid,
                "token": token,
                "new_password1": "AnotherStrongPass123!",
                "new_password2": "AnotherStrongPass123!",
            },
            format="json",
        )
        self.assertEqual(reset_response.status_code, status.HTTP_200_OK)

        relogin_response = self._login_user(password="AnotherStrongPass123!")
        self.assertEqual(relogin_response.status_code, status.HTTP_200_OK)

        invalid_token_response = self.client.post(
            reverse("auth-password-reset"),
            {
                "uid": uid,
                "token": "bad-token",
                "new_password1": "AnotherStrongPass123!",
                "new_password2": "AnotherStrongPass123!",
            },
            format="json",
        )
        self.assertEqual(invalid_token_response.status_code, status.HTTP_400_BAD_REQUEST)
        invalid_detail = invalid_token_response.data["detail"]
        if isinstance(invalid_detail, list):
            invalid_detail = str(invalid_detail[0])
        self.assertEqual(invalid_detail, "Invalid or expired token.")

        fresh_token = default_token_generator.make_token(user)
        fresh_uid = encode_uid(user.pk)
        with override_settings(PASSWORD_RESET_TIMEOUT=-1):
            expired_token_response = self.client.post(
                reverse("auth-password-reset"),
                {
                    "uid": fresh_uid,
                    "token": fresh_token,
                    "new_password1": "ThirdStrongPass123!",
                    "new_password2": "ThirdStrongPass123!",
                },
                format="json",
            )

        self.assertEqual(expired_token_response.status_code, status.HTTP_400_BAD_REQUEST)
        expired_detail = expired_token_response.data["detail"]
        if isinstance(expired_detail, list):
            expired_detail = str(expired_detail[0])
        self.assertEqual(expired_detail, "Invalid or expired token.")

    def test_login_blocked_when_email_not_verified(self):
        User.objects.create_user(
            email="john@example.com",
            password="StrongPass123!",
            is_email_verified=False,
        )

        response = self._login_user()
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["detail"], "Email is not verified.")

    @override_settings(AUTH_REQUIRE_EMAIL_VERIFIED=False)
    def test_login_allowed_when_verification_not_required(self):
        User.objects.create_user(
            email="john@example.com",
            password="StrongPass123!",
            is_email_verified=False,
        )

        response = self._login_user()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
