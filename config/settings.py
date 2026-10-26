"""Environment-driven settings for the Module 1 Django service."""

import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured


BASE_DIR = Path(__file__).resolve().parent.parent


def env(name, default=None):
    value = os.environ.get(name, default)
    if value is None or value == "":
        raise ImproperlyConfigured(f"{name} must be set")
    return value


def env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    if value.lower() in {"1", "true", "yes", "on"}:
        return True
    if value.lower() in {"0", "false", "no", "off"}:
        return False
    raise ImproperlyConfigured(f"{name} must be a boolean")


SECRET_KEY = env("DJANGO_SECRET_KEY")
DEBUG = env_bool("DJANGO_DEBUG")
ALLOWED_HOSTS = [host.strip() for host in env("DJANGO_ALLOWED_HOSTS").split(",") if host.strip()]
if not ALLOWED_HOSTS:
    raise ImproperlyConfigured("DJANGO_ALLOWED_HOSTS cannot be empty")
CSRF_TRUSTED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("DJANGO_CSRF_TRUSTED_ORIGINS", "").split(",")
    if origin.strip()
]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "core",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env("DATABASE_NAME"),
        "USER": env("DATABASE_USER"),
        "PASSWORD": env("DATABASE_PASSWORD"),
        "HOST": env("DATABASE_HOST", "localhost"),
        "PORT": env("DATABASE_PORT", "5432"),
        "CONN_HEALTH_CHECKS": True,
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
PRIVATE_ARTIFACT_ROOT = Path(env("PRIVATE_ARTIFACT_ROOT", str(BASE_DIR / "private_artifacts"))).resolve()
GOOGLE_SERVICE_ACCOUNT_FILE = os.environ.get("GOOGLE_SERVICE_ACCOUNT_FILE", "")
GOOGLE_INGESTION_SERVICE_ACCOUNT_FILE = os.environ.get(
    "GOOGLE_INGESTION_SERVICE_ACCOUNT_FILE", GOOGLE_SERVICE_ACCOUNT_FILE,
)
GOOGLE_RESPONSE_SERVICE_ACCOUNT_FILE = os.environ.get("GOOGLE_RESPONSE_SERVICE_ACCOUNT_FILE", "")
CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", "amqp://guest:guest@localhost:5672//")
CELERY_TASK_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TIMEZONE = "UTC"
CELERY_TASK_ACKS_LATE = True
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
GMAIL_POLL_INTERVAL_SECONDS = max(10, int(os.environ.get("GMAIL_POLL_INTERVAL_SECONDS", "60")))
GMAIL_ANALYSIS_SWEEP_INTERVAL_SECONDS = max(10, int(os.environ.get("GMAIL_ANALYSIS_SWEEP_INTERVAL_SECONDS", "30")))
GMAIL_ANALYSIS_DISPATCH_BATCH_SIZE = max(1, int(os.environ.get("GMAIL_ANALYSIS_DISPATCH_BATCH_SIZE", "100")))
GMAIL_ANALYSIS_REDISPATCH_SECONDS = max(30, int(os.environ.get("GMAIL_ANALYSIS_REDISPATCH_SECONDS", "120")))
GMAIL_ANALYSIS_LEASE_SECONDS = max(30, int(os.environ.get("GMAIL_ANALYSIS_LEASE_SECONDS", "300")))
GMAIL_RETRY_BASE_SECONDS = max(1, int(os.environ.get("GMAIL_RETRY_BASE_SECONDS", "5")))
GMAIL_RETRY_MAX_SECONDS = max(GMAIL_RETRY_BASE_SECONDS, int(os.environ.get("GMAIL_RETRY_MAX_SECONDS", "3600")))
DETECTION_INDICATOR_MODE = os.environ.get("DETECTION_INDICATOR_MODE", "operational")
if DETECTION_INDICATOR_MODE not in {"operational", "synthetic"} or (DETECTION_INDICATOR_MODE == "synthetic" and not DEBUG):
    raise ImproperlyConfigured("DETECTION_INDICATOR_MODE must be operational, or synthetic with DJANGO_DEBUG=1")
DETECTION_AUTH_RESULTS_MODE = os.environ.get("DETECTION_AUTH_RESULTS_MODE", "untrusted_context")
if DETECTION_AUTH_RESULTS_MODE not in {"untrusted_context", "ignore"}:
    raise ImproperlyConfigured("DETECTION_AUTH_RESULTS_MODE must be untrusted_context or ignore")
CLASSIFIER_MODEL_ROOT = Path(env("CLASSIFIER_MODEL_ROOT", str(BASE_DIR / "model_artifacts"))).resolve()
CLASSIFIER_ACTIVE_VERSION = os.environ.get("CLASSIFIER_ACTIVE_VERSION", "")
CLASSIFIER_DATASET_SELECTION_FILE = os.environ.get("CLASSIFIER_DATASET_SELECTION_FILE", "")
CLASSIFIER_SIGNING_KEY = os.environ.get("CLASSIFIER_SIGNING_KEY", "")
CLASSIFIER_APPROVAL_KEY = os.environ.get("CLASSIFIER_APPROVAL_KEY", "")
CLASSIFIER_ALLOW_SYNTHETIC = env_bool("CLASSIFIER_ALLOW_SYNTHETIC", False) and DEBUG
CELERY_BEAT_SCHEDULE = {
    "gmail-incremental-poll": {
        "task": "core.tasks.poll_gmail",
        "schedule": float(GMAIL_POLL_INTERVAL_SECONDS),
    },
    "gmail-analysis-reconciliation": {
        "task": "core.tasks.dispatch_pending_analysis",
        "schedule": float(GMAIL_ANALYSIS_SWEEP_INTERVAL_SECONDS),
    },
}
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "private_artifacts": {
        "BACKEND": "core.storage.PrivateArtifactStorage",
    },
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
