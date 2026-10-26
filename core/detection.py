"""Deterministic MIME observations. No provider calls, scoring, or verdicts."""

import hashlib
import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .indicators import normalize_indicator
from .models import Indicator


RULE_VERSION = "1"
ENGINE_VERSION = "rules-v1"
TEXT_LIMIT = 500_000
URL_LIMIT = 500
OBSERVATION_LIMIT = 1000
FORWARD_MARKER = re.compile(r"(?im)^\s*(?:-{2,}\s*forwarded message\s*-{2,}|begin forwarded message:?|on .{4,160} wrote:)\s*$")
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[A-Z0-9-]+\.)+[A-Z]{2,}\b", re.IGNORECASE)
PAYMENT_RE = re.compile(r"\b(?:payment|invoice|bank|wire|transfer|remittance|iban|routing)\b", re.IGNORECASE)
CHANGE_RE = re.compile(
    r"\b(?:new|updated|changed|different|replace(?:d)?|switch(?:ed)?)\b.{0,45}"
    r"\b(?:bank|account|iban|routing|payment\s+(?:details|instructions)|wire\s+instructions)\b|"
    r"\b(?:bank|account|iban|routing|payment\s+(?:details|instructions)|wire\s+instructions)\b.{0,35}"
    r"\b(?:changed|updated|new|different)\b",
    re.IGNORECASE,
)
REDIRECT_RE = re.compile(r"\b(?:send|wire|transfer|remit|pay|deposit)\b.{0,70}\b(?:new|different|updated|account|iban|routing|bank)\b", re.IGNORECASE)
ACCOUNT_RE = re.compile(r"\b(?:account|iban|routing)\s*(?:number|no\.?|#|:)?\s*[A-Z0-9 -]{6,40}", re.IGNORECASE)
URGENCY_RE = re.compile(r"\b(?:urgent|immediately|today|before close of business|by end of day)\b", re.IGNORECASE)


@dataclass(frozen=True)
class Observation:
    rule_id: str
    label: str
    source_field: str
    source_span: dict = field(default_factory=dict)
    provenance: dict = field(default_factory=lambda: {"origin": "original_mime"})
    status: str = "observed"
    category: str = "signal"
    limitations: tuple = ()
    facts: dict = field(default_factory=dict)
    version: str = RULE_VERSION


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.visible_text = []
        self._anchor = None
        self._ignored_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() in {"script", "style"}:
            self._ignored_depth += 1
            return
        if self._ignored_depth:
            return
        if tag.lower() == "a":
            href = dict(attrs).get("href", "")
            self._anchor = {"href": href, "text": [], "line": self.getpos()[0], "column": self.getpos()[1]}

    def handle_data(self, data):
        if self._ignored_depth:
            return
        self.visible_text.append(data)
        if self._anchor is not None:
            self._anchor["text"].append(data)

    def handle_endtag(self, tag):
        if tag.lower() in {"script", "style"} and self._ignored_depth:
            self._ignored_depth -= 1
            return
        if self._ignored_depth:
            return
        if tag.lower() == "a" and self._anchor is not None:
            self.links.append(self._anchor)
            self._anchor = None


def _parts(message, prefix="mime"):
    if message.get_content_type() == "message/rfc822":
        return
    if message.is_multipart():
        for index, child in enumerate(message.iter_parts()):
            yield from _parts(child, f"{prefix}.part.{index}")
    else:
        yield prefix, message


def _host(value):
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        return normalize_indicator(Indicator.Type.DOMAIN, parsed.hostname)
    except (ValueError, UnicodeError):
        return ""


def _visible_host(text):
    text = text.strip().rstrip("/.,;:)")
    if text.lower().startswith(("http://", "https://")):
        return _host(text)
    if DOMAIN_RE.fullmatch(text):
        try:
            return normalize_indicator(Indicator.Type.DOMAIN, text)
        except ValueError:
            pass
    return ""


def _url_flags(value):
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        if parsed.scheme.lower() not in {"http", "https"} or not host:
            return ["malformed_url"]
        flags = []
        if parsed.username is not None or parsed.password is not None:
            flags.append("userinfo")
        try:
            ipaddress.ip_address(host)
            flags.append("ip_literal")
        except ValueError:
            pass
        if "xn--" in host.lower():
            flags.append("punycode_host")
        if len(host.split(".")) >= 6:
            flags.append("deep_subdomain")
        if parsed.port and parsed.port not in {80, 443}:
            flags.append("unusual_port")
        return flags
    except ValueError:
        return ["malformed_url"]


def _attachment_type(part):
    filename = part.get_filename() or ""
    extensions = [item.lower() for item in filename.split(".")[1:]]
    extension = extensions[-1] if extensions else ""
    declared = part.get_content_type().lower()
    known = {
        "pdf": ("application/pdf", b"%PDF-"),
        "png": ("image/png", b"\x89PNG\r\n\x1a\n"),
        "jpg": ("image/jpeg", b"\xff\xd8\xff"),
        "jpeg": ("image/jpeg", b"\xff\xd8\xff"),
        "zip": ("application/zip", b"PK\x03\x04"),
        "docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", b"PK\x03\x04"),
        "xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", b"PK\x03\x04"),
        "exe": ("application/vnd.microsoft.portable-executable", b"MZ"),
    }
    if extension not in known:
        return extension, declared, []
    expected_mime, signature = known[extension]
    flags = []
    if declared not in {expected_mime, "application/octet-stream"}:
        flags.append("declared_type_mismatch")
    payload = part.get_payload(decode=True) or b""
    if payload and not payload.startswith(signature):
        flags.append("signature_mismatch")
    if extension == "exe" and any(item in {"pdf", "doc", "docx", "xls", "xlsx"} for item in extensions[:-1]):
        flags.append("double_extension")
    return extension, declared, flags


def _candidate(kind, value, source_field, span=None):
    try:
        return kind, normalize_indicator(kind, value), source_field, span or {}
    except ValueError:
        return None


def detect(message, *, gmail_label_ids=(), indicator_matches=None, indicator_cache_available=False,
           auth_results_mode="untrusted_context"):
    """Return observations from one parsed original MIME and supplemental labels."""
    observations = []
    candidates = []
    from_name, from_address = parseaddr(str(message.get("From", "")))
    _, reply_address = parseaddr(str(message.get("Reply-To", "")))
    claimed_email = EMAIL_RE.search(from_name)
    claimed_domain = DOMAIN_RE.search(from_name) if not claimed_email else None
    if claimed_email and claimed_email.group().casefold() != from_address.casefold():
        observations.append(Observation(
            "IDENTITY_DISPLAY_FROM", "Display name claims a different email address", "mime.From",
            limitations=("Display names are sender-controlled; the claim is not a verified identity.",),
            facts={"claim_type": "email", "from_domain": from_address.rsplit("@", 1)[-1].lower()},
        ))
    elif claimed_domain and from_address and claimed_domain.group().casefold() != from_address.rsplit("@", 1)[-1].casefold():
        observations.append(Observation(
            "IDENTITY_DISPLAY_FROM", "Display name contains a domain different from From", "mime.From",
            limitations=("A display-name domain can be descriptive rather than an identity claim.",),
            facts={"claim_type": "domain", "from_domain": from_address.rsplit("@", 1)[-1].lower()},
        ))
    if reply_address and from_address and reply_address.rsplit("@", 1)[-1].casefold() != from_address.rsplit("@", 1)[-1].casefold():
        observations.append(Observation(
            "IDENTITY_REPLY_TO", "Reply-To domain differs from From domain", "mime.Reply-To",
            limitations=("Delegated senders, lists, and support systems can use a separate reply domain.",),
            facts={"from_domain": from_address.rsplit("@", 1)[-1].lower(),
                   "reply_domain": reply_address.rsplit("@", 1)[-1].lower()},
        ))
    elif reply_address and from_address and reply_address.casefold() != from_address.casefold():
        observations.append(Observation(
            "IDENTITY_REPLY_TO_ADDRESS", "Reply-To address differs from From within the same domain", "mime.Reply-To",
            category="context",
            limitations=("A separate reply mailbox within the same domain is common and is not an identity verdict.",),
            facts={"same_domain": True, "addresses_differ": True},
        ))
    for address, field_name in ((from_address, "mime.From"), (reply_address, "mime.Reply-To")):
        if address:
            candidates.append(_candidate(Indicator.Type.EMAIL, address, field_name))
            candidates.append(_candidate(Indicator.Type.DOMAIN, address.rsplit("@", 1)[-1], field_name))

    auth_headers = message.get_all("Authentication-Results", [])
    if auth_headers and auth_results_mode == "untrusted_context":
        observations.append(Observation(
            "AUTH_RESULTS_CONTEXT", "Authentication-Results header present", "mime.Authentication-Results",
            category="context", limitations=(
                "Retrieved MIME does not establish which authentication headers crossed a trusted ingress boundary.",
                "Authentication success or failure is not interpreted as a safety verdict.",
            ), facts={"header_count": len(auth_headers), "trust_configuration": "untrusted_context"},
        ))
    labels = sorted(set(gmail_label_ids))
    if labels:
        observations.append(Observation(
            "GMAIL_LABEL_CONTEXT", "Gmail labels captured as context", "gmail.labelIds",
            provenance={"origin": "gmail_metadata"}, category="context",
            limitations=("Mailbox placement and labels are not Yphish verdicts.",),
            facts={"label_ids": labels},
        ))

    body_chunks = []
    urls = []
    forwarded = False
    truncated = False
    for field_name, part in _parts(message):
        if part.get_content_disposition() == "attachment" or part.get_filename():
            extension, declared, flags = _attachment_type(part)
            if flags:
                observations.append(Observation(
                    "ATTACHMENT_TYPE", "Attachment type indicators disagree", field_name,
                    limitations=("Filename, declared type, and magic bytes can all be spoofed; no file execution occurred.",),
                    facts={"extension": extension, "declared_mime": declared, "flags": flags},
                ))
            payload = part.get_payload(decode=True) or b""
            if payload:
                candidates.append(_candidate(Indicator.Type.SHA256, hashlib.sha256(payload).hexdigest(), field_name))
            continue
        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
            if not isinstance(content, str):
                continue
        except (LookupError, UnicodeError, ValueError, TypeError):
            truncated = True
            continue
        if len(content) > TEXT_LIMIT:
            content = content[:TEXT_LIMIT]
            truncated = True
        marker = FORWARD_MARKER.search(content)
        if marker:
            content = content[:marker.start()]
            forwarded = True
        source = f"{field_name}.{content_type}"
        if content_type == "text/html":
            parser = _Links()
            parser.feed(content)
            scan_text = " ".join(parser.visible_text)
            scan_source = f"{source}.visible_text"
            body_chunks.append((scan_source, scan_text))
            for link in parser.links:
                href = link["href"]
                if not isinstance(href, str) or not href.lower().startswith(("http://", "https://")):
                    continue
                span = {"line": link["line"], "column": link["column"]}
                urls.append((href, f"{source}.anchor.href", span))
                visible_host, actual_host = _visible_host("".join(link["text"])), _host(href)
                if visible_host and actual_host and visible_host != actual_host:
                    observations.append(Observation(
                        "LINK_VISIBLE_DESTINATION", "Visible link domain differs from destination", f"{source}.anchor",
                        source_span=span,
                        limitations=("Anchor text and destination can differ legitimately; redirects and visual rendering were not checked.",),
                        facts={"visible_host": visible_host, "destination_host": actual_host},
                    ))
        else:
            scan_text = content
            scan_source = source
            body_chunks.append((source, content))
        for match in URL_RE.finditer(scan_text):
            url = match.group().rstrip(".,;:)")
            urls.append((url, scan_source, {"start": match.start(), "end": match.start() + len(url)}))
        if len(urls) > URL_LIMIT:
            urls = urls[:URL_LIMIT]
            truncated = True
            break

    if forwarded:
        observations.append(Observation(
            "FORWARDED_CONTEXT", "Forwarded or quoted content excluded", "mime.body",
            category="context", limitations=("Only text before a recognized forward marker was assessed as current-message text.",),
            facts={"quoted_content_excluded": True},
        ))
    if truncated:
        observations.append(Observation(
            "RULE_COVERAGE_LIMIT", "Some MIME text or links were not evaluated", "mime.body",
            status="unavailable", category="coverage",
            limitations=("Text decoding or bounded extraction prevented complete body assessment.",),
            facts={"text_limit_chars": TEXT_LIMIT, "url_limit": URL_LIMIT},
        ))
    for url, source, span in urls:
        flags = _url_flags(url)
        if flags:
            observations.append(Observation(
                "URL_STRUCTURE", "URL has structural features requiring review", source,
                source_span=span,
                limitations=("Structural features alone do not establish that a destination is malicious.",
                             "No URL was opened or redirected."),
                facts={"host": _host(url), "flags": flags},
            ))
        candidates.append(_candidate(Indicator.Type.URL, url, source, span))
        host = _host(url)
        if host:
            candidates.append(_candidate(Indicator.Type.DOMAIN, host, source, span))

    payment_match = None
    redirection_match = None
    for source, text in body_chunks:
        if payment_match is None and PAYMENT_RE.search(text):
            change = CHANGE_RE.search(text)
            if change:
                payment_match = (source, change.span())
        if redirection_match is None and PAYMENT_RE.search(text):
            redirect = REDIRECT_RE.search(text)
            if redirect and (CHANGE_RE.search(text) or (ACCOUNT_RE.search(text) and URGENCY_RE.search(text))):
                redirection_match = (source, redirect.span())
    if payment_match:
        source, (start, end) = payment_match
        observations.append(Observation(
            "PAYMENT_CHANGE_CLAIM", "Message claims changed payment instructions", source,
            source_span={"start": start, "end": end},
            limitations=("No verified prior payment instructions were available; an actual change or fraud is not established.",),
            facts={"claimed_change": True},
        ))
    if redirection_match and not urls and not truncated:
        source, (start, end) = redirection_match
        observations.append(Observation(
            "PAYMENT_REDIRECTION_NO_LINK", "Payment redirection language appears without an extracted HTTP(S) link", source,
            source_span={"start": start, "end": end},
            limitations=("Absence of links does not make a payment request safe or fraudulent.",
                         "No verified bank-account baseline or recipient action is known."),
            facts={"http_link_count": 0, "redirection_language": True},
        ))

    if indicator_matches is None or not indicator_cache_available:
        observations.append(Observation(
            "INDICATOR_CACHE", "Current indicator snapshot unavailable", "indicator.cache",
            provenance={"origin": "local_indicator_cache"}, status="unavailable", category="coverage",
            limitations=("No current local snapshot was available; absence of a match cannot be assessed.",),
            facts={"source_kind": "configured"},
        ))
    else:
        seen_candidates = set()
        for candidate in candidates:
            if candidate is None:
                continue
            kind, value, source, span = candidate
            identity = (kind, value, source, tuple(sorted(span.items())))
            if identity in seen_candidates:
                continue
            seen_candidates.add(identity)
            for snapshot in indicator_matches.get((kind, value), ()):
                observations.append(Observation(
                    "INDICATOR_EXACT", "Exact local indicator match", source,
                    source_span=span,
                    provenance={"origin": "local_indicator_cache", "snapshot_id": str(snapshot.id),
                                "source_name": snapshot.source_name, "source_kind": snapshot.kind,
                                "fetched_at": snapshot.fetched_at.isoformat(),
                                "expires_at": snapshot.expires_at.isoformat(), "sha256": snapshot.sha256},
                    limitations=("An exact indicator match is a lead, not proof of malicious activity.",
                                 "The feed's provenance and freshness depend on its local curator."),
                    facts={"indicator_type": kind, "exact_match": True},
                ))
    if len(observations) > OBSERVATION_LIMIT:
        observations = observations[:OBSERVATION_LIMIT - 1] + [Observation(
            "RULE_OBSERVATION_LIMIT", "Further rule observations omitted", "mime.message",
            status="unavailable", category="coverage",
            limitations=("The deterministic observation limit was reached; additional signals may exist.",),
            facts={"observation_limit": OBSERVATION_LIMIT},
        )]
    return observations


def summarize(observations):
    counts = Counter(item.rule_id for item in observations)
    categories = Counter(item.category for item in observations)
    statuses = Counter(item.status for item in observations)
    return {
        "engine_version": ENGINE_VERSION,
        "observation_count": len(observations),
        "rule_counts": dict(sorted(counts.items())),
        "category_counts": dict(sorted(categories.items())),
        "status_counts": dict(sorted(statuses.items())),
        "verdict": "not_assigned",
    }
