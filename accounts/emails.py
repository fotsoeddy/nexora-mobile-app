from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from django.conf import settings
from django.core.mail import send_mail

from .tokens import default_token_generator, email_verification_token_generator, encode_uid


def _append_query_params(url: str, params: dict[str, str]) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query))
    query.update(params)
    return urlunparse(parsed._replace(query=urlencode(query)))


def send_verification_email(user) -> None:
    uid = encode_uid(user.pk)
    token = email_verification_token_generator.make_token(user)
    verification_link = _append_query_params(
        settings.FRONTEND_VERIFY_URL,
        {"uid": uid, "token": token},
    )

    send_mail(
        subject="Verify your email",
        message=(
            "Welcome to Nexora. Verify your email by opening this link:\n"
            f"{verification_link}\n\n"
            "This link expires automatically."
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )


def send_password_reset_email(user) -> None:
    uid = encode_uid(user.pk)
    token = default_token_generator.make_token(user)
    reset_link = _append_query_params(
        settings.FRONTEND_RESET_URL,
        {"uid": uid, "token": token},
    )

    send_mail(
        subject="Reset your password",
        message=(
            "A password reset was requested for your Nexora account.\n"
            f"{reset_link}\n\n"
            "If this was not you, ignore this email."
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )
