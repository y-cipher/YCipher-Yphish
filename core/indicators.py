"""Local, timestamped exact-match indicators; no network lookups."""

import hashlib
import json
import re
from datetime import datetime
from urllib.parse import urlsplit, urlunsplit

from django.conf import settings
from django.db import connection, transaction
from django.utils import timezone

from .models import Indicator, IndicatorSnapshot


MAX_SNAPSHOT_BYTES = 5 * 1024 * 1024
MAX_INDICATORS = 50000


def normalize_indicator(indicator_type, value):
    if not isinstance(value, str) or not value or len(value) > 2048 or value != value.strip():
        raise ValueError("Indicator value is invalid")
    if indicator_type == Indicator.Type.DOMAIN:
        try:
            value = value.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise ValueError("Invalid indicator domain") from None
        if not value or any(not re.fullmatch(r"[a-z0-9-]{1,63}", label) for label in value.split(".")):
            raise ValueError("Invalid indicator domain")
        return value
    if indicator_type == Indicator.Type.EMAIL:
        if value.count("@") != 1:
            raise ValueError("Invalid indicator email")
        local, domain = value.rsplit("@", 1)
        if not local or any(char.isspace() for char in local):
            raise ValueError("Invalid indicator email")
        return f"{local.casefold()}@{normalize_indicator(Indicator.Type.DOMAIN, domain)}"
    if indicator_type == Indicator.Type.SHA256:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            raise ValueError("Invalid SHA-256 indicator")
        return value.lower()
    if indicator_type == Indicator.Type.URL:
        try:
            parsed = urlsplit(value)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                raise ValueError
            if parsed.username is not None or parsed.password is not None:
                raise ValueError
            host = normalize_indicator(Indicator.Type.DOMAIN, parsed.hostname)
            port = parsed.port
            netloc = host if port is None else f"{host}:{port}"
            return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))
        except (ValueError, UnicodeError):
            raise ValueError("Invalid URL indicator") from None
    raise ValueError("Unknown indicator type")


def _parse_timestamp(value):
    if not isinstance(value, str):
        raise ValueError("Indicator timestamp must be an ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("Invalid indicator timestamp") from None
    if timezone.is_naive(parsed):
        raise ValueError("Indicator timestamp must include a timezone")
    return parsed


def import_snapshot(raw, *, expected_kind):
    """Import a complete local snapshot atomically; old snapshots stay auditable."""
    if not isinstance(raw, bytes) or len(raw) > MAX_SNAPSHOT_BYTES:
        raise ValueError("Indicator snapshot exceeds the byte limit")
    if expected_kind not in IndicatorSnapshot.Kind.values:
        raise ValueError("Invalid indicator source kind")
    if expected_kind == IndicatorSnapshot.Kind.SYNTHETIC and not settings.DEBUG:
        raise ValueError("Synthetic indicator imports require DJANGO_DEBUG=1")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, ValueError):
        raise ValueError("Invalid indicator JSON") from None
    if not isinstance(payload, dict) or payload.get("kind") != expected_kind:
        raise ValueError("Indicator kind does not match the selected source")
    name = payload.get("source_name")
    if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,99}", name):
        raise ValueError("Invalid indicator source name")
    fetched_at = _parse_timestamp(payload.get("fetched_at"))
    expires_at = _parse_timestamp(payload.get("expires_at"))
    now = timezone.now()
    if fetched_at > now or expires_at <= now or expires_at <= fetched_at:
        raise ValueError("Indicator snapshot is future-dated or expired")
    entries = payload.get("indicators")
    if not isinstance(entries, list) or len(entries) > MAX_INDICATORS:
        raise ValueError("Invalid indicator list")
    normalized = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"type", "value"}:
            raise ValueError("Invalid indicator entry")
        normalized.add((entry["type"], normalize_indicator(entry["type"], entry["value"])))
    digest = hashlib.sha256(raw).hexdigest()
    with transaction.atomic():
        lock = hashlib.sha256(f"{expected_kind}:{name}".encode()).digest()
        keys = (int.from_bytes(lock[:4], "big", signed=True),
                int.from_bytes(lock[4:8], "big", signed=True))
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(%s, %s)", keys)
        existing = IndicatorSnapshot.objects.filter(
            source_name=name, kind=expected_kind, fetched_at=fetched_at,
        ).first()
        if existing:
            if existing.sha256 != digest:
                raise ValueError("A different snapshot already uses this source timestamp")
            return existing, False
        latest = IndicatorSnapshot.objects.filter(
            source_name=name, kind=expected_kind,
        ).order_by("-fetched_at").first()
        if latest and fetched_at < latest.fetched_at:
            raise ValueError("An older snapshot cannot replace a newer source timestamp")
        IndicatorSnapshot.objects.filter(source_name=name, kind=expected_kind, is_active=True).update(is_active=False)
        snapshot = IndicatorSnapshot.objects.create(
            source_name=name, kind=expected_kind, fetched_at=fetched_at,
            expires_at=expires_at, sha256=digest,
        )
        Indicator.objects.bulk_create([
            Indicator(snapshot=snapshot, indicator_type=kind, value=value)
            for kind, value in sorted(normalized)
        ])
        return snapshot, True


def active_snapshots(kind, at=None):
    at = at or timezone.now()
    return IndicatorSnapshot.objects.filter(
        kind=kind, is_active=True, fetched_at__lte=at, expires_at__gt=at,
    )
