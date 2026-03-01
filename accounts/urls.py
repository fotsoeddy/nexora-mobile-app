from django.urls import path

from .views import (
    ChangePasswordAPIView,
    EmailVerificationConfirmAPIView,
    EmailVerificationRequestAPIView,
    ForgotPasswordAPIView,
    LoginAPIView,
    LogoutAPIView,
    MeAPIView,
    RefreshTokenAPIView,
    RegisterAPIView,
    ResetPasswordAPIView,
)

urlpatterns = [
    path("register", RegisterAPIView.as_view(), name="auth-register"),
    path("login", LoginAPIView.as_view(), name="auth-login"),
    path("refresh", RefreshTokenAPIView.as_view(), name="auth-refresh"),
    path("logout", LogoutAPIView.as_view(), name="auth-logout"),
    path("me", MeAPIView.as_view(), name="auth-me"),
    path("password/change", ChangePasswordAPIView.as_view(), name="auth-password-change"),
    path("password/forgot", ForgotPasswordAPIView.as_view(), name="auth-password-forgot"),
    path("password/reset", ResetPasswordAPIView.as_view(), name="auth-password-reset"),
    path("email/verify/request", EmailVerificationRequestAPIView.as_view(), name="auth-email-verify-request"),
    path("email/verify/confirm", EmailVerificationConfirmAPIView.as_view(), name="auth-email-verify-confirm"),
]
