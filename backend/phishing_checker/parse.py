"""MIME parsing. Quoted-printable, encoded-words, and both text and HTML are kept.

The HTML part is never trusted over the text part. Phishing mail often puts a
benign URL in one part and a different destination in the other.
"""

from __future__ import annotations

from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser

from phishing_checker.models import Address, Attachment, ParsedEmail

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\ufeff\u2060\u00ad"), None)


class _HTML(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[tuple[str, str]] = []
        self.text_parts: list[str] = []
        self.base_href = ""
        self.form_actions: list[str] = []
        self.meta_refresh: list[str] = []
        self.has_password_field = False
        self._capture: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k.lower(): (v or "") for k, v in attrs}
        if tag in {"p", "div", "tr", "li", "h1", "h2", "h3", "br", "table"}:
            self.text_parts.append("\n")
        if tag == "a":
            self._capture = [ad.get("href", ""), ""]
        elif tag == "base" and ad.get("href"):
            self.base_href = ad["href"]
        elif tag == "form" and ad.get("action"):
            self.form_actions.append(ad["action"])
        elif tag == "meta" and ad.get("http-equiv", "").lower() == "refresh":
            self.meta_refresh.append(ad.get("content", ""))
        elif tag == "input" and ad.get("type", "").lower() == "password":
            self.has_password_field = True
        elif tag == "img" and self._capture is not None and ad.get("alt"):
            self._capture[1] += ad["alt"]
        elif tag == "br":
            self.text_parts.append("\n")

    def handle_data(self, data: str) -> None:
        self.text_parts.append(data)
        if self._capture is not None:
            self._capture[1] += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._capture is not None:
            self.anchors.append((self._capture[0].strip(), " ".join(self._capture[1].split())))
            self._capture = None
        if tag in {"p", "div", "tr", "li", "h1", "h2", "h3", "td", "th", "a", "b", "strong"}:
            self.text_parts.append(" ")


def _clean(value: str | None) -> str:
    if not value:
        return ""
    return str(value).translate(_ZERO_WIDTH).strip()


def _address(display: str, email: str) -> Address | None:
    email = _clean(email).strip("<>").lower()
    if not email or email == "<>":
        return None
    local, _, domain = email.partition("@")
    return Address(display=_clean(display), email=email, domain=domain, local=local)


def _addresses(header: str | None) -> list[Address]:
    if not header:
        return []
    found = []
    for display, email in getaddresses([header]):
        addr = _address(display, email)
        if addr:
            found.append(addr)
    return found


def _decode_part(part) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _magic(payload: bytes) -> str:
    prefix = payload[:16]
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in prefix)
    return text


def parse_email(raw: bytes) -> ParsedEmail:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    body_text: list[str] = []
    body_html: list[str] = []
    attachments: list[Attachment] = []

    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        ctype = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        is_attachment = disposition == "attachment" or (
            filename and ctype not in {"text/plain", "text/html"}
        )
        if is_attachment or (filename and disposition == "attachment"):
            payload = part.get_payload(decode=True) or b""
            ext = ""
            if filename and "." in filename:
                ext = filename.rsplit(".", 1)[-1].lower()
            attachments.append(
                Attachment(
                    filename=filename or "",
                    content_type=ctype,
                    size=len(payload),
                    extension=ext,
                    magic=_magic(payload),
                )
            )
            if ctype not in {"text/plain", "text/html"} or disposition == "attachment":
                continue
        if ctype == "text/plain":
            body_text.append(_decode_part(part))
        elif ctype == "text/html":
            body_html.append(_decode_part(part))
        elif disposition == "attachment":
            continue

    html = "\n".join(body_html)
    parser = _HTML()
    if html:
        try:
            parser.feed(html)
        except Exception:
            parser = _HTML()

    from_addrs = _addresses(msg.get("from"))
    reply = _addresses(msg.get("reply-to"))
    return_path = ""
    rp = _addresses(str(msg.get("return-path") or ""))
    if rp:
        return_path = rp[0].email
    else:
        return_path = _clean(str(msg.get("return-path") or "")).strip("<>")

    return ParsedEmail(
        subject=_clean(str(msg.get("subject") or "")),
        from_=from_addrs[0] if from_addrs else None,
        from_all=from_addrs,
        to=_addresses(msg.get("to")),
        reply_to=reply,
        return_path=return_path,
        date=_clean(str(msg.get("date") or "")),
        message_id=_clean(str(msg.get("message-id") or "")),
        body_text="\n".join(body_text)[:500_000],
        body_html=html[:500_000],
        html_visible_text="".join(parser.text_parts)[:500_000],
        authentication_results=_clean(str(msg.get("authentication-results") or "")),
        list_unsubscribe=_clean(str(msg.get("list-unsubscribe") or "")),
        attachments=attachments,
        anchors=parser.anchors,
        base_href=parser.base_href,
        form_actions=parser.form_actions,
        meta_refresh=parser.meta_refresh,
        has_password_field=parser.has_password_field,
    )
