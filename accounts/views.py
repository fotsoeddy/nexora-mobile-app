from __future__ import annotations

from django.conf import settings
from django.contrib.auth import get_user_model
from drf_spectacular.utils import OpenApiExample, extend_schema
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView

from .emails import send_password_reset_email, send_verification_email
from .serializers import (
    ChangePasswordSerializer,
    EmailVerificationRequestSerializer,
    EmailVerificationSerializer,
    ForgotPasswordSerializer,
    LoginResponseSerializer,
    LoginSerializer,
    LogoutSerializer,
    MeSerializer,
    MessageSerializer,
    RegisterResponseSerializer,
    RegisterSerializer,
    ResetPasswordSerializer,
)

User = get_user_model()


class RegisterAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        tags=["Auth"],
        request=RegisterSerializer,
        responses={201: RegisterResponseSerializer},
        examples=[
            OpenApiExample(
                "Register response",
                value={
                    "id": 1,
                    "email": "john@example.com",
                    "message": "Verification email sent",
                },
                response_only=True,
            )
        ],
    )
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        send_verification_email(user)

        return Response(
            {
                "id": user.id,
                "email": user.email,
                "message": "Verification email sent",
            },
            status=status.HTTP_201_CREATED,
        )


class LoginAPIView(APIView):
    permission_classes = [permissions.AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth_login"

    @extend_schema(
        tags=["Auth"],
        request=LoginSerializer,
        responses={200: LoginResponseSerializer},
        examples=[
            OpenApiExample(
                "Login response",
                value={
                    "access": "<jwt_access>",
                    "refresh": "<jwt_refresh>",
                    "user": {
                        "id": 1,
                        "email": "john@example.com",
                        "first_name": "John",
                        "last_name": "Doe",
                        "phone": "",
                        "is_email_verified": True,
                    },
                },
                response_only=True,
            )
        ],
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]

        if settings.AUTH_REQUIRE_EMAIL_VERIFIED and not user.is_email_verified:
            return Response(
                {"detail": "Email is not verified."},
                status=status.HTTP_403_FORBIDDEN,
            )

        refresh = RefreshToken.for_user(user)
        payload = {
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": MeSerializer(user).data,
        }
        return Response(payload, status=status.HTTP_200_OK)


class RefreshTokenAPIView(TokenRefreshView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        tags=["Auth"],
        examples=[
            OpenApiExample(
                "Refresh request",
                value={"refresh": "<jwt_refresh>"},
                request_only=True,
            ),
            OpenApiExample(
                "Refresh response",
                value={"access": "<new_jwt_access>", "refresh": "<optional_new_refresh>"},
                response_only=True,
            )
        ],
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


class LogoutAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        tags=["Auth"],
        request=LogoutSerializer,
        responses={200: MessageSerializer},
        examples=[
            OpenApiExample(
                "Logout request",
                value={"refresh": "<jwt_refresh>"},
                request_only=True,
            ),
            OpenApiExample(
                "Logout response",
                value={"message": "Logged out successfully."},
                response_only=True,
            ),
        ],
    )
    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            token = RefreshToken(serializer.validated_data["refresh"])
            token.blacklist()
        except TokenError:
            return Response({"detail": "Invalid refresh token."}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "Logged out successfully."}, status=status.HTTP_200_OK)


class MeAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        tags=["Auth"],
        responses={200: MeSerializer},
        examples=[
            OpenApiExample(
                "Me response",
                value={
                    "id": 1,
                    "email": "john@example.com",
                    "first_name": "John",
                    "last_name": "Doe",
                    "phone": "",
                    "is_email_verified": True,
                },
                response_only=True,
            )
        ],
    )
    def get(self, request):
        return Response(MeSerializer(request.user).data, status=status.HTTP_200_OK)

    @extend_schema(
        tags=["Auth"],
        request=MeSerializer,
        responses={200: MeSerializer},
        examples=[
            OpenApiExample(
                "Me patch request",
                value={"first_name": "Jane", "last_name": "Doe", "phone": "+237123456"},
                request_only=True,
            )
        ],
    )
    def patch(self, request):
        serializer = MeSerializer(request.user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)


class ChangePasswordAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        tags=["Auth"],
        request=ChangePasswordSerializer,
        responses={200: MessageSerializer},
        examples=[
            OpenApiExample(
                "Change password request",
                value={
                    "old_password": "StrongPass123!",
                    "new_password1": "NewStrongPass123!",
                    "new_password2": "NewStrongPass123!",
                },
                request_only=True,
            ),
            OpenApiExample(
                "Change password response",
                value={"message": "Password changed successfully."},
                response_only=True,
            ),
        ],
    )
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)

        request.user.set_password(serializer.validated_data["new_password1"])
        request.user.save(update_fields=["password", "updated_at"])
        return Response({"message": "Password changed successfully."}, status=status.HTTP_200_OK)


class ForgotPasswordAPIView(APIView):
    permission_classes = [permissions.AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth_forgot"

    @extend_schema(
        tags=["Auth"],
        request=ForgotPasswordSerializer,
        responses={200: MessageSerializer},
        examples=[
            OpenApiExample(
                "Forgot password request",
                value={"email": "john@example.com"},
                request_only=True,
            ),
            OpenApiExample(
                "Forgot password response",
                value={"message": "If that email exists, a password reset email has been sent."},
                response_only=True,
            ),
        ],
    )
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = User.objects.filter(email=serializer.validated_data["email"], is_active=True).first()
        if user:
            send_password_reset_email(user)

        return Response(
            {"message": "If that email exists, a password reset email has been sent."},
            status=status.HTTP_200_OK,
        )


class ResetPasswordAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        tags=["Auth"],
        request=ResetPasswordSerializer,
        responses={200: MessageSerializer},
        examples=[
            OpenApiExample(
                "Reset password request",
                value={
                    "uid": "<uid>",
                    "token": "<token>",
                    "new_password1": "AnotherStrongPass123!",
                    "new_password2": "AnotherStrongPass123!",
                },
                request_only=True,
            ),
            OpenApiExample(
                "Reset password response",
                value={"message": "Password reset successful."},
                response_only=True,
            ),
        ],
    )
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]
        user.set_password(serializer.validated_data["new_password1"])
        user.save(update_fields=["password", "updated_at"])

        return Response({"message": "Password reset successful."}, status=status.HTTP_200_OK)


class EmailVerificationRequestAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        tags=["Auth"],
        request=EmailVerificationRequestSerializer,
        responses={200: MessageSerializer},
        examples=[
            OpenApiExample(
                "Email verify request",
                value={"email": "john@example.com"},
                request_only=True,
            ),
            OpenApiExample(
                "Email verify request response",
                value={"message": "If that email exists, a verification email has been sent."},
                response_only=True,
            ),
        ],
    )
    def post(self, request):
        serializer = EmailVerificationRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = User.objects.filter(email=serializer.validated_data["email"], is_active=True).first()
        if user and not user.is_email_verified:
            send_verification_email(user)

        return Response(
            {"message": "If that email exists, a verification email has been sent."},
            status=status.HTTP_200_OK,
        )


class EmailVerificationConfirmAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        tags=["Auth"],
        request=EmailVerificationSerializer,
        responses={200: MessageSerializer},
        examples=[
            OpenApiExample(
                "Email verify confirm request",
                value={"uid": "<uid>", "token": "<token>"},
                request_only=True,
            ),
            OpenApiExample(
                "Email verify confirm response",
                value={"message": "Email verified successfully."},
                response_only=True,
            ),
        ],
    )
    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]
        if not user.is_email_verified:
            user.is_email_verified = True
            user.save(update_fields=["is_email_verified", "updated_at"])

        return Response({"message": "Email verified successfully."}, status=status.HTTP_200_OK)
