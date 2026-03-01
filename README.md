# Nexora Auth API (Django + DRF + JWT)

Implémentation d'une authentification API complète avec:
- Django + DRF
- JWT via `djangorestframework-simplejwt`
- Blacklist refresh token (logout)
- Vérification email
- Reset password par email
- Documentation OpenAPI/Swagger

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

## Lancer le projet

```bash
export DJANGO_SETTINGS_MODULE=config.settings.dev
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

## Variables d'environnement clés
- `DJANGO_SETTINGS_MODULE`: `config.settings.dev` ou `config.settings.prod`
- `DB_ENGINE`: `sqlite` (dev) ou `postgresql`
- `AUTH_REQUIRE_EMAIL_VERIFIED`: bloque/autorise login sans email vérifié
- `JWT_ACCESS_MINUTES`, `JWT_REFRESH_DAYS`
- `THROTTLE_LOGIN_RATE`, `THROTTLE_FORGOT_RATE`
- `PASSWORD_RESET_TIMEOUT_SECONDS`

## Endpoints
Base: `/api/auth/`

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `PATCH /api/auth/me`
- `POST /api/auth/password/change`
- `POST /api/auth/password/forgot`
- `POST /api/auth/password/reset`
- `POST /api/auth/email/verify/request`
- `POST /api/auth/email/verify/confirm`

OpenAPI:
- `GET /api/schema/`
- `GET /api/docs/`

## Exemples cURL

Register:
```bash
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"john@example.com","password1":"StrongPass123!","password2":"StrongPass123!"}'
```

Login:
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@example.com","password":"StrongPass123!"}'
```

Refresh:
```bash
curl -X POST http://localhost:8000/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh":"<refresh_token>"}'
```

Me:
```bash
curl http://localhost:8000/api/auth/me \
  -H "Authorization: Bearer <access_token>"
```

Forgot password:
```bash
curl -X POST http://localhost:8000/api/auth/password/forgot \
  -H "Content-Type: application/json" \
  -d '{"email":"john@example.com"}'
```

Reset password:
```bash
curl -X POST http://localhost:8000/api/auth/password/reset \
  -H "Content-Type: application/json" \
  -d '{"uid":"<uid>","token":"<token>","new_password1":"NewStrongPass123!","new_password2":"NewStrongPass123!"}'
```

## Notes sécurité
- Mots de passe validés via validateurs Django.
- Tokens JWT courts (access) + refresh blacklistable.
- Reset/verify via token signé et expiration (`PASSWORD_RESET_TIMEOUT`).
- Throttling minimal sur login/forgot.
- Aucun secret en dur: config via `.env`.
