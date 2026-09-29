"""Registrable domains, brand groups, and lookalike checks.

Alignment uses the relaxed DMARC notion of an organizational domain: the
registrable domain (eTLD+1), not the full hostname. That is why a DKIM key on
microsoft.com covers accountprotection.microsoft.com, and why an ESP bounce
domain like em4225.rippling.com still aligns with rippling.com.
"""

from __future__ import annotations

import os
import re
import tempfile

import tldextract

# Public Suffix List lookup
_EXTRACT = tldextract.TLDExtract(
    cache_dir=os.environ.get("TLDEXTRACT_CACHE") or os.path.join(tempfile.gettempdir(), "tldextract"),
    include_psl_private_domains=True,
    cache_fetch_timeout=3,
)

# Domains that may legitimately send automated mail
WELL_KNOWN_SENDERS = {
    "google.com",
    "github.com",
    "microsoft.com",
    "docusign.net",
    "docusign.com",
    "apple.com",
    "amazon.com",
    "dropbox.com",
    "adobe.com",
    "okta.com",
    "slack.com",
    "zoom.us",
    "linkedin.com",
}

BRAND_GROUPS: list[set[str]] = [
    {"docusign.com", "docusign.net"},
    {
        "microsoft.com",
        "office.com",
        "office365.com",
        "microsoftonline.com",
        "sharepoint.com",
        "live.com",
        "outlook.com",
    },
    {"google.com", "gmail.com", "googleusercontent.com"},
    {"github.com"},
    {"adobe.com", "adobesign.com", "echosign.com"},
    {"dropbox.com", "dropboxsign.com", "hellosign.com"},
    {"apple.com", "icloud.com"},
    {"amazon.com"},
]

ESIGN_DOMAINS = {
    "docusign.com",
    "docusign.net",
    "adobesign.com",
    "adobe.com",
    "echosign.com",
    "hellosign.com",
    "dropboxsign.com",
    "dropbox.com",
    "pandadoc.com",
    "signnow.com",
}

# Third-party click domains used by real marketing platforms
TRACKER_DOMAINS = {
    "sendgrid.net",
    "mailchimp.com",
    "mandrillapp.com",
    "sparkpostmail.com",
    "exacttarget.com",
    "campaignmonitor.com",
    "list-manage.com",
    "hubspot.com",
    "mcsv.net",
    "cmail19.com",
}

NOTIFICATION_PLATFORMS = {
    "google.com",
    "github.com",
    "microsoft.com",
    "docusign.net",
    "docusign.com",
    "dropbox.com",
    "adobe.com",
}

FREEMAIL = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "ymail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "aol.com",
    "icloud.com",
    "me.com",
    "proton.me",
    "protonmail.com",
    "gmx.com",
    "mail.com",
    "pm.me",
    "zoho.com",
}

_SUSPICIOUS_TOKENS = {
    "login",
    "logon",
    "secure",
    "security",
    "account",
    "accounts",
    "verify",
    "verification",
    "update",
    "support",
    "alert",
    "alerts",
    "signin",
    "auth",
    "webmail",
    "mailbox",
    "password",
    "confirm",
    "confirmation",
    "billing",
    "payment",
    "wallet",
    "unlock",
    "notification",
    "notifications",
    "notify",
    "session",
    "recover",
    "recovery",
    "restore",
    "validate",
    "validation",
    "portal",
    "online",
    "service",
    "services",
    "helpdesk",
    "mail",
    "email",
    "team",
    "center",
    "centre",
    "app",
    "apps",
    "customer",
    "official",
    "notice",
    "sign",
    "document",
    "documents",
    "doc",
    "web",
}

# Cyrillic, Greek, and a few Latin lookalikes that show up in homograph domains.
_CONFUSABLES = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "i",
    "ї": "i",
    "ѕ": "s",
    "һ": "h",
    "ј": "j",
    "ɡ": "g",
    "ℓ": "l",
    "ι": "i",
    "ο": "o",
    "α": "a",
    "τ": "t",
    "ν": "v",
    "ε": "e",
    "ρ": "p",
    "κ": "k",
    "μ": "u",
    "υ": "u",
    "χ": "x",
    "０": "0",
    "Ｏ": "o",
    "ｌ": "l",
    "ⅰ": "i",
}

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def registrable_domain(host: str | None) -> str | None:
    if not host:
        return None
    host = host.lower().strip().rstrip(".").strip("[]")
    if not host or _IP_RE.match(host) or ":" in host:
        return host or None
    labels = [label for label in host.split(".") if label]
    if len(labels) < 2:
        return host
    parts = _EXTRACT(host)
    if parts.suffix and parts.domain:
        return f"{parts.domain}.{parts.suffix}"
    return ".".join(labels[-2:])


def split_sld(domain: str | None) -> tuple[str, str]:
    if not domain or "." not in domain:
        return domain or "", ""
    parts = _EXTRACT(domain)
    if parts.suffix and parts.domain:
        return parts.domain, parts.suffix
    sld, _, tld = domain.rpartition(".")
    return sld, tld


def same_brand(left: str | None, right: str | None) -> bool:
    a = registrable_domain(left)
    b = registrable_domain(right)
    if not a or not b:
        return False
    if a == b:
        return True
    return any(a in group and b in group for group in BRAND_GROUPS)


def decode_host(host: str) -> str:
    labels = []
    for label in host.split("."):
        if label.lower().startswith("xn--"):
            try:
                labels.append(label.encode("ascii").decode("idna"))
            except (UnicodeError, UnicodeDecodeError):
                labels.append(label)
        else:
            labels.append(label)
    return ".".join(labels)


def skeleton(host: str) -> str:
    decoded = decode_host(host.lower())
    return "".join(_CONFUSABLES.get(ch, ch) for ch in decoded)


def has_mixed_script(host: str) -> bool:
    decoded = decode_host(host)
    has_latin = any("a" <= ch.lower() <= "z" for ch in decoded)
    has_other = any(ord(ch) > 127 and ch.isalpha() for ch in decoded)
    return has_latin and has_other


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike_of(host: str, protected: set[str]) -> str | None:
    """Return the protected domain this host is imitating, if any."""
    reg = registrable_domain(host)
    if not reg or reg in protected or host.lower().rstrip(".") in protected:
        return None
    sld, tld = split_sld(reg)
    if not sld:
        return None
    folded = sld.replace("-", "")
    best: tuple[int, str] | None = None
    for prot in protected:
        psld, ptld = split_sld(prot)
        if len(psld) < 4:
            continue
        matched = False
        if folded == psld:
            matched = True
        elif folded.startswith(psld) and folded[len(psld) :] in _SUSPICIOUS_TOKENS:
            matched = True
        else:
            parts = [p for p in sld.split("-") if p]
            if parts and parts[0] == psld and any(p in _SUSPICIOUS_TOKENS for p in parts[1:]):
                matched = True
            elif sld == psld and tld != ptld:
                matched = True
            elif (
                len(psld) >= 6
                and abs(len(sld) - len(psld)) <= 2
                and 0 < levenshtein(sld, psld) <= 1
            ):
                matched = True
        if matched and (best is None or len(psld) > best[0]):
            best = (len(psld), prot)
    return best[1] if best else None


def nested_deception(host: str, protected: set[str]) -> str | None:
    """login.microsoft.com.evil.test contains microsoft.com but is not Microsoft."""
    labels = host.lower().rstrip(".").split(".")
    for prot in protected:
        plabels = prot.split(".")
        width = len(plabels)
        if width < 2 or len(labels) <= width:
            continue
        for i in range(len(labels) - width):
            if labels[i : i + width] == plabels:
                return prot
    return None


def protected_domains(org_domains: set[str], vendor_domains: set[str]) -> set[str]:
    domains = set(WELL_KNOWN_SENDERS)
    domains.update(ESIGN_DOMAINS)
    for group in BRAND_GROUPS:
        domains.update(group)
    domains.update(
        {
            "paypal.com",
            "okta.com",
            "slack.com",
            "zoom.us",
            "linkedin.com",
            "fedex.com",
            "ups.com",
            "dhl.com",
            "irs.gov",
        }
    )
    domains.update(org_domains)
    domains.update(vendor_domains)
    return domains
