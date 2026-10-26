"""Provider-independent text feature boundary for training and inference."""

from dataclasses import dataclass
from email.message import EmailMessage
from html.parser import HTMLParser


FEATURE_SCHEMA_VERSION = "mime-content-v1"
MAX_TEXT_CHARS = 500_000


class _VisibleHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.fragments = []
        self.ignored = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() in {"script", "style"}:
            self.ignored += 1

    def handle_endtag(self, tag):
        if tag.lower() in {"script", "style"} and self.ignored:
            self.ignored -= 1

    def handle_data(self, data):
        if not self.ignored:
            self.fragments.append(data)


@dataclass(frozen=True)
class TextDocument:
    subject: str
    body_text: str

    def as_feature_text(self):
        """Only extracted message content enters TF-IDF."""
        return f"subject {self.subject.strip()}\nbody {self.body_text.strip()}".strip()

    def has_content(self):
        return bool(self.subject.strip() or self.body_text.strip())


def _text_parts(part):
    if part.get_content_type() == "message/rfc822":
        return
    if part.is_multipart():
        for child in part.iter_parts():
            yield from _text_parts(child)
    elif part.get_content_disposition() != "attachment" and not part.get_filename():
        yield part


def extract_document(message: EmailMessage):
    """Extract subject and body only; never use Gmail or organization metadata."""
    subject = str(message.get("Subject", ""))[:MAX_TEXT_CHARS]
    plain, html = [], []
    for part in _text_parts(message):
        kind = part.get_content_type()
        if kind not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError, ValueError, TypeError):
            continue
        if not isinstance(content, str):
            continue
        if kind == "text/plain":
            plain.append(content)
        else:
            parser = _VisibleHTML()
            parser.feed(content[:MAX_TEXT_CHARS])
            html.append(" ".join(parser.fragments))
    body = "\n".join(plain if plain else html)[:MAX_TEXT_CHARS]
    return TextDocument(subject=subject, body_text=body)
