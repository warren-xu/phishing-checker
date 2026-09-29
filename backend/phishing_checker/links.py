"""Link extraction and the traps that hide in the difference between parts."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, unquote, urljoin, urlsplit

from phishing_checker.auth import AuthAssessment
from phishing_checker.context import OrgContext
from phishing_checker.domains import (
    TRACKER_DOMAINS,
    has_mixed_script,
    lookalike_of,
    nested_deception,
    protected_domains,
    registrable_domain,
    same_brand,
    skeleton,
    split_sld,
)
from phishing_checker.models import Finding, Link, ParsedEmail, add_finding

_URL_RE = re.compile(r"(?i)\b(?:(?:https?|hxxps?)://|www\.)[^\s<>'\"\)\]]+")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b", re.I)
_NOT_A_TLD = {
    "pdf",
    "xlsx",
    "xls",
    "docx",
    "doc",
    "pptx",
    "ppt",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "zip",
    "html",
    "htm",
    "csv",
    "txt",
    "json",
    "xml",
    "exe",
}
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b", re.I)
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_CREDENTIAL_PATH = re.compile(r"(validate|login|signin|sign-in|account|password|verify|auth|credential)", re.I)
_SHORTENERS = {
    "bit.ly",
    "bitly.com",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "buff.ly",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "tiny.cc",
}
_REDIRECT_PARAMS = {
    "url",
    "u",
    "redirect",
    "redir",
    "next",
    "dest",
    "destination",
    "goto",
    "target",
    "continue",
    "return",
    "rurl",
    "link",
    "redirect_url",
}


def clip(value: str, limit: int = 180) -> str:
    value = " ".join((value or "").split())
    if len(value) <= limit:
        return value
    return value[: limit - 1] + "…"


def refang(url: str) -> str:
    url = url.strip().strip("<>").rstrip(".,;>")
    lower = url.lower()
    if lower.startswith("hxxps://"):
        url = "https://" + url[8:]
    elif lower.startswith("hxxp://"):
        url = "http://" + url[7:]
    url = url.replace("[.]", ".").replace("(.)", ".")
    url = re.sub(r"\[:\]", ":", url)
    if url.lower().startswith("www."):
        url = "http://" + url
    return url


def urls_in(text: str) -> list[str]:
    return [refang(match) for match in _URL_RE.findall(text or "")]


def _record(url: str, source: str, visible: str) -> Link | None:
    cleaned = refang(url)
    if not cleaned:
        return None
    parts = urlsplit(cleaned)
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    return Link(
        url=cleaned,
        host=host,
        registrable_domain=registrable_domain(host) or "",
        scheme=scheme,
        source=source,
        visible_text=visible.strip(),
    )


def analyze_links(
    email: ParsedEmail,
    auth: AuthAssessment,
    ctx: OrgContext,
) -> tuple[list[Link], list[Finding]]:
    findings: list[Finding] = []
    protected = protected_domains(ctx.org_domains, ctx.vendor_domains)
    links: list[Link] = []

    for url in urls_in(email.body_text):
        rec = _record(url, "text", "")
        if rec:
            links.append(rec)

    base = refang(email.base_href) if email.base_href else ""
    for href, text in email.anchors:
        if not href or href.startswith("#") or href.lower().startswith("mailto:"):
            continue
        absolute = href
        if base and not urlsplit(href).scheme and not href.lower().startswith(("javascript:", "data:")):
            absolute = urljoin(base, href)
        rec = _record(absolute, "html", text)
        if rec:
            _compare_visible(rec, text)
            links.append(rec)

    if base:
        rec = _record(base, "base", "")
        if rec:
            links.append(rec)
            from_reg = registrable_domain(email.from_.domain) if email.from_ else ""
            if rec.registrable_domain and rec.registrable_domain != from_reg and not same_brand(rec.host, from_reg or ""):
                rec.issues.append("base href points off the sender domain")
                add_finding(
                    findings,
                    Finding(
                        id="link.base_hijack",
                        severity="high",
                        category="links",
                        title="HTML base href points somewhere else",
                        explanation=(
                            "A <base> tag rewrites every relative link in the message. "
                            f"This one points at {rec.url}."
                        ),
                        evidence=[clip(rec.url)],
                    ),
                )

    for action in email.form_actions:
        rec = _record(action, "form", "")
        if not rec:
            continue
        links.append(rec)
        add_finding(
            findings,
            Finding(
                id="link.form_action",
                severity="critical" if email.has_password_field else "high",
                category="links",
                title="The message contains an HTML form",
                explanation=(
                    f"The HTML posts a form to {rec.url}. Mail clients should not be collecting "
                    "credentials, and a password field inside the message is a phishing page."
                    if email.has_password_field
                    else f"The HTML posts a form to {rec.url}."
                ),
                evidence=[clip(rec.url)],
            ),
        )

    for content in email.meta_refresh:
        match = re.search(r"url\s*=\s*['\"]?([^'\"\s;]+)", content, re.I)
        if not match:
            continue
        rec = _record(unquote(match.group(1)), "meta", "")
        if not rec:
            continue
        links.append(rec)
        add_finding(
            findings,
            Finding(
                id="link.meta_refresh",
                severity="high",
                category="links",
                title="Meta refresh redirects the message",
                explanation=f"The HTML refresh header sends the reader to {rec.url}.",
                evidence=[clip(rec.url)],
            ),
        )

    for rec in links:
        _inspect(rec, protected, findings)

    _multipart_mismatch(email, links, findings)
    _mentioned_domains(email, links, findings)
    return links, findings


def _compare_visible(rec: Link, text: str) -> None:
    visible_urls = urls_in(text)
    if not visible_urls:
        return
    shown = urlsplit(visible_urls[0])
    shown_host = (shown.hostname or "").lower()
    shown_reg = registrable_domain(shown_host) or ""
    if shown_host and rec.host and shown_reg != rec.registrable_domain and not same_brand(shown_host, rec.host):
        rec.issues.append("visible URL does not match the href")
        rec.visible_text = text


def _inspect(rec: Link, protected: set[str], findings: list[Finding]) -> None:
    if rec.scheme in {"javascript", "data", "vbscript"}:
        rec.issues.append(f"{rec.scheme} URL")
        add_finding(
            findings,
            Finding(
                id="link.dangerous_scheme",
                severity="critical",
                category="links",
                title="Link uses a script or data URL",
                explanation=f"A {rec.scheme}: URL runs in the client instead of navigating to a site.",
                evidence=[clip(rec.url)],
            ),
        )
        return

    raw_lower = rec.url.lower()
    netloc = urlsplit(rec.url).netloc
    if "\\" in rec.url or "%5c" in raw_lower:
        rec.issues.append("backslash in URL")
        add_finding(
            findings,
            Finding(
                id="link.backslash_host",
                severity="high",
                category="links",
                title="URL uses a backslash to disguise the host",
                explanation="Browsers and mail clients disagree on backslashes in URLs, which is a classic host-confusion trick.",
                evidence=[clip(rec.url)],
            ),
        )
    if urlsplit(rec.url).username or urlsplit(rec.url).password or "@" in netloc:
        rec.issues.append("credentials embedded in the URL")
        real_host = rec.host or "the real host"
        add_finding(
            findings,
            Finding(
                id="link.userinfo_deception",
                severity="critical",
                category="links",
                title="URL hides the real host behind an @ sign",
                explanation=(
                    f"Text before @ in a URL is a username, not the site. This link actually goes to {real_host}."
                ),
                evidence=[clip(rec.url)],
            ),
        )

    if rec.host and (_IP_RE.match(rec.host) or ":" in rec.host):
        rec.issues.append("IP address host")
        add_finding(
            findings,
            Finding(
                id="link.ip_host",
                severity="high",
                category="links",
                title="Link goes to an IP address",
                explanation=f"The link host is {rec.host}. Organizations do not ask recipients to sign in on a raw IP.",
                evidence=[clip(rec.url)],
            ),
        )

    if rec.host:
        nested = nested_deception(rec.host, protected)
        if nested:
            rec.issues.append(f"nests the name {nested}")
            add_finding(
                findings,
                Finding(
                    id="link.nested_domain_deception",
                    severity="critical",
                    category="links",
                    title="Link disguises itself as a known domain",
                    explanation=(
                        f"The host {rec.host} contains {nested} as a label, but the registrable domain "
                        f"is {rec.registrable_domain}. The real site is the rightmost domain."
                    ),
                    evidence=[clip(rec.url), f"imitates {nested}"],
                ),
            )
        else:
            brand = lookalike_of(rec.host, protected)
            if brand:
                rec.issues.append(f"lookalike of {brand}")
                add_finding(
                    findings,
                    Finding(
                        id="brand.lookalike",
                        severity="critical",
                        category="brand",
                        title=f"Domain imitates {brand}",
                        explanation=(
                            f"{rec.host} is not {brand}. A hyphen, an extra word, or a swapped character "
                            "is there so it reads as that brand. The lookalike can still pass SPF and DKIM, "
                            "because the attacker controls that domain."
                        ),
                        evidence=[clip(rec.url), f"imitates {brand}"],
                    ),
                )
            skel = skeleton(rec.host)
            skel_reg = registrable_domain(skel)
            puny = "xn--" in rec.host or any(ord(ch) > 127 for ch in rec.host)
            if puny and skel_reg in protected and (rec.registrable_domain not in protected):
                rec.issues.append(f"homoglyph of {skel_reg}")
                add_finding(
                    findings,
                    Finding(
                        id="link.homoglyph",
                        severity="critical",
                        category="links",
                        title=f"Internationalized domain imitates {skel_reg}",
                        explanation=(
                            f"{rec.host} uses characters that look like {skel_reg}. "
                            "Mixed-script and punycode domains are a standard phishing disguise."
                        ),
                        evidence=[clip(rec.url), f"skeleton {skel}"],
                    ),
                )
            elif puny or has_mixed_script(rec.host):
                rec.issues.append("punycode or mixed script")
                add_finding(
                    findings,
                    Finding(
                        id="link.punycode",
                        severity="high",
                        category="links",
                        title="Link uses an internationalized domain",
                        explanation=(
                            f"{rec.host} is punycode or mixes scripts. That is unusual in ordinary business mail "
                            "and is worth confirming before use."
                        ),
                        evidence=[clip(rec.url)],
                    ),
                )

    if rec.scheme == "http" and _CREDENTIAL_PATH.search(rec.url):
        rec.issues.append("credential page over HTTP")
        add_finding(
            findings,
            Finding(
                id="link.cleartext_credential",
                severity="medium",
                category="links",
                title="Credential-looking page is served over HTTP",
                explanation=f"{rec.url} asks for a validation or sign-in step without TLS.",
                evidence=[clip(rec.url)],
            ),
        )

    if rec.registrable_domain in _SHORTENERS or rec.host in _SHORTENERS:
        rec.issues.append("shortener")
        add_finding(
            findings,
            Finding(
                id="link.shortener",
                severity="medium",
                category="links",
                title="Link is a URL shortener",
                explanation="The destination is hidden behind a shortener. Open it only after expanding the URL out of band.",
                evidence=[clip(rec.url)],
            ),
        )

    _redirect_params(rec, findings)

    if "visible URL does not match the href" in rec.issues:
        add_finding(
            findings,
            Finding(
                id="link.text_href_mismatch",
                severity="critical",
                category="links",
                title="The link text is a different URL than the destination",
                explanation=(
                    f"The message displays {clip(rec.visible_text, 120)} but the href goes to {rec.host}."
                ),
                evidence=[f"visible: {clip(rec.visible_text, 120)}", f"href: {clip(rec.url)}"],
            ),
        )


def _redirect_params(rec: Link, findings: list[Finding]) -> None:
    query = parse_qs(urlsplit(rec.url).query, keep_blank_values=False)
    for key, values in query.items():
        if key.lower() not in _REDIRECT_PARAMS:
            continue
        for value in values:
            candidate = unquote(value)
            if not candidate.lower().startswith(("http://", "https://", "hxxp")):
                continue
            dest = _record(candidate, "query", "")
            if not dest or not dest.registrable_domain:
                continue
            if dest.registrable_domain == rec.registrable_domain or same_brand(dest.host, rec.host):
                rec.issues.append("same-organization tracking redirect")
                add_finding(
                    findings,
                    Finding(
                        id="link.tracking_redirect",
                        severity="info",
                        category="links",
                        title="Marketing click-tracker stays on the sender's domain",
                        explanation=(
                            f"{rec.host} redirects to {dest.host}. Both are the same organization, "
                            "which is normal for a mailing-list tracker."
                        ),
                        evidence=[clip(rec.url)],
                    ),
                )
            else:
                rec.issues.append(f"redirects to {dest.host}")
                add_finding(
                    findings,
                    Finding(
                        id="link.open_redirect",
                        severity="high",
                        category="links",
                        title="Link parameter points at a different domain",
                        explanation=(
                            f"{rec.host} carries a redirect to {dest.host}. "
                            "The visible site and the eventual destination are not the same organization."
                        ),
                        evidence=[clip(rec.url), clip(dest.url)],
                    ),
                )


def _multipart_mismatch(email: ParsedEmail, links: list[Link], findings: list[Finding]) -> None:
    text_regs = {rec.registrable_domain for rec in links if rec.source == "text" and rec.registrable_domain}
    html_regs = {rec.registrable_domain for rec in links if rec.source == "html" and rec.registrable_domain}
    if not text_regs or not html_regs:
        return
    from_reg = registrable_domain(email.from_.domain) if email.from_ else ""
    safe = set(text_regs)
    safe.update(TRACKER_DOMAINS)
    if from_reg:
        safe.add(from_reg)
    unexpected = []
    for reg in sorted(html_regs):
        if reg in safe or any(same_brand(reg, item) for item in safe):
            continue
        unexpected.append(reg)
    if unexpected:
        add_finding(
            findings,
            Finding(
                id="link.html_introduces_domain",
                severity="high",
                category="links",
                title="HTML part links somewhere the text part does not",
                explanation=(
                    "The plain-text part and the HTML part advertise different destinations. "
                    f"Only the HTML goes to {', '.join(unexpected)}. Many clients show the HTML."
                ),
                evidence=[f"text domains: {', '.join(sorted(text_regs))}", f"html-only: {', '.join(unexpected)}"],
            ),
        )


def _mentioned_domains(email: ParsedEmail, links: list[Link], findings: list[Finding]) -> None:
    visible = f"{email.body_text}\n{email.html_visible_text}"
    visible = _EMAIL_RE.sub(" ", visible)
    visible = _URL_RE.sub(" ", visible)
    mentioned = set()
    for match in _DOMAIN_RE.findall(visible):
        cleaned = match.lower().strip(".")
        tld = cleaned.rsplit(".", 1)[-1]
        if tld in _NOT_A_TLD:
            continue
        reg = registrable_domain(cleaned)
        if reg and "." in reg:
            mentioned.add(reg)
    link_regs = {rec.registrable_domain for rec in links if rec.registrable_domain}
    evidence = []
    for name in sorted(mentioned):
        msld, _ = split_sld(name)
        if len(msld) < 4:
            continue
        for reg in link_regs:
            if reg == name or same_brand(name, reg):
                continue
            lsld, _ = split_sld(reg)
            if lsld.startswith(msld + "-") or msld.startswith(lsld + "-"):
                evidence.append(f"mentions {name}, links to {reg}")
    if evidence:
        add_finding(
            findings,
            Finding(
                id="link.mentioned_domain_mismatch",
                severity="high",
                category="links",
                title="The brand's domain and the link's domain disagree",
                explanation=(
                    "The message names one domain and sends the reader to a cousin domain that "
                    "starts with the same word. The cousin is a different site."
                ),
                evidence=evidence,
            ),
        )
