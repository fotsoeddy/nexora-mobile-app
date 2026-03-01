from __future__ import annotations

from django.contrib.auth import authenticate, get_user_model, password_validation
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from .tokens import decode_uid, default_token_generator, email_verification_token_generator

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "first_name",
            "last_name",
            "phone",
            "is_email_verified",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "email", "is_email_verified", "created_at", "updated_at")


class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    first_name = serializers.CharField(max_length=150, required=False, allow_blank=True)
    last_name = serializers.CharField(max_length=150, required=False, allow_blank=True)
    phone = serializers.CharField(max_length=32, required=False, allow_blank=True)
    password1 = serializers.CharField(write_only=True, min_length=8)
    password2 = serializers.CharField(write_only=True, min_length=8)

    def validate_email(self, value: str) -> str:
        email = value.lower().strip()
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return email

    def validate(self, attrs):
        if attrs["password1"] != attrs["password2"]:
            raise serializers.ValidationError({"password2": ["Passwords do not match."]})

        user = User(email=attrs.get("email", ""))
        try:
            password_validation.validate_password(attrs["password1"], user=user)
        except DjangoValidationError as exc:
            raise serializers.ValidationError({"password1": list(exc.messages)})
        return attrs

    def create(self, validated_data):
        validated_data.pop("password2")
        password = validated_data.pop("password1")
        email = validated_data.pop("email").lower()
        user = User.objects.create_user(email=email, password=password, **validated_data)
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs.get("email", "").lower().strip()
        password = attrs.get("password")

        if not email or not password:
            raise serializers.ValidationError({"detail": "Email and password are required."})

        user = authenticate(
            request=self.context.get("request"),
            username=email,
            password=password,
        )

        if not user:
            raise serializers.ValidationError({"detail": "Invalid credentials."})
        if not user.is_active:
            raise serializers.ValidationError({"detail": "User account is disabled."})

        attrs["user"] = user
        return attrs


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()


class MeSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "first_name",
            "last_name",
            "phone",
            "is_email_verified",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "email", "is_email_verified", "created_at", "updated_at")


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password1 = serializers.CharField(write_only=True, min_length=8)
    new_password2 = serializers.CharField(write_only=True, min_length=8)

    def validate(self, attrs):
        request = self.context.get("request")
        user = getattr(request, "user", None)

        if not user or not user.is_authenticated:
            raise serializers.ValidationError({"detail": "Authentication required."})
        if not user.check_password(attrs["old_password"]):
            raise serializers.ValidationError({"old_password": ["Current password is incorrect."]})
        if attrs["new_password1"] != attrs["new_password2"]:
            raise serializers.ValidationError({"new_password2": ["Passwords do not match."]})

        try:
            password_validation.validate_password(attrs["new_password1"], user=user)
        except DjangoValidationError as exc:
            raise serializers.ValidationError({"new_password1": list(exc.messages)})

        return attrs


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value: str) -> str:
        return value.lower().strip()


class ResetPasswordSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password1 = serializers.CharField(write_only=True, min_length=8)
    new_password2 = serializers.CharField(write_only=True, min_length=8)

    def validate(self, attrs):
        if attrs["new_password1"] != attrs["new_password2"]:
            raise serializers.ValidationError({"new_password2": ["Passwords do not match."]})

        uid = attrs.get("uid")
        token = attrs.get("token")
        user_id = decode_uid(uid)
        if not user_id:
            raise serializers.ValidationError({"detail": "Invalid or expired token."})

        user = User.objects.filter(pk=user_id).first()
        if not user or not default_token_generator.check_token(user, token):
            raise serializers.ValidationError({"detail": "Invalid or expired token."})

        try:
            password_validation.validate_password(attrs["new_password1"], user=user)
        except DjangoValidationError as exc:
            raise serializers.ValidationError({"new_password1": list(exc.messages)})

        attrs["user"] = user
        return attrs


class EmailVerificationRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value: str) -> str:
        return value.lower().strip()


class EmailVerificationSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()

    def validate(self, attrs):
        uid = attrs.get("uid")
        token = attrs.get("token")
        user_id = decode_uid(uid)
        if not user_id:
            raise serializers.ValidationError({"detail": "Invalid or expired token."})

        user = User.objects.filter(pk=user_id).first()
        if not user or not email_verification_token_generator.check_token(user, token):
            raise serializers.ValidationError({"detail": "Invalid or expired token."})

        attrs["user"] = user
        return attrs


class MessageSerializer(serializers.Serializer):
    message = serializers.CharField()


class RegisterResponseSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    email = serializers.EmailField()
    message = serializers.CharField()


class LoginResponseSerializer(serializers.Serializer):
    access = serializers.CharField()
    refresh = serializers.CharField()
    user = UserSerializer()
