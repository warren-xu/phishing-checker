"""What the message asks the recipient to do.

Urgency, typos, and the word "account" are notes. They become a verdict only
when the request is paired with an identity or link problem, or when the
sender is not a party this organization actually works with.
"""

from __future__ import annotations

import re

from phishing_checker.auth import AuthAssessment
from phishing_checker.context import OrgContext
from phishing_checker.domains import ESIGN_DOMAINS, WELL_KNOWN_SENDERS, registrable_domain, same_brand
from phishing_checker.identity import IdentityAssessment
from phishing_checker.models import Finding, Link, ParsedEmail, add_finding

_HARVEST = re.compile(
    r"(validate your account|verify your account|verify your password|"
    r"confirm your password|confirm your identity|"
    r"storage limit|mailbox.{0,40}full|"
    r"account (will be |has been |is )?suspend|"
    r"re-verify|unlock your account)",
    re.I,
)
_SIGN = re.compile(
    r"(review and sign|please sign|requires your signature|"
    r"document to sign|waiting for your signature|"
    r"sign this document|your signature is required|"
    r"sent you a document to review)",
    re.I,
)
_PAYMENT = re.compile(
    r"(remittance|routing number|wire transfer|bank account|\bbanking\b|"
    r"\biban\b|\bswift\b|direct deposit details|new account details)",
    re.I,
)
_SECRECY = re.compile(
    r"(keep (it|this) quiet|keep this between us|do not tell anyone|don't tell anyone)",
    re.I,
)
_GIFT = re.compile(r"\bgift cards?\b", re.I)
_DESK = re.compile(r"are you (at your desk|free right now|available)", re.I)
_FAVOR = re.compile(r"(quick favor|handle something for me|need you to .{0,60}quickly)", re.I)
_NOTIFY = re.compile(
    r"(password was changed|security info was added|ssh key was added|new ssh key|"
    r"if you did not|if this wasn.?t you|you can safely ignore|no action is needed)",
    re.I,
)
_TYPOS = (
    (re.compile(r"\brecieve", re.I), "recieve"),
    (re.compile(r"immediat", re.I), "immediatly"),
    (re.compile(r"\bsuspenson\b", re.I), "suspenson"),
    (re.compile(r"exceed it\b", re.I), "exceed it"),
)
_GOV_DISPLAY = re.compile(r"\b(dod|department of defense|u\.s\. government|us government)\b", re.I)
_GOV_BODY = re.compile(r"(department of defense|sprs program office)", re.I)


def _blob(email: ParsedEmail) -> str:
    display = email.from_.display if email.from_ else ""
    return "\n".join([email.subject, display, email.body_text, email.html_visible_text])


def _known_destination(reg: str, email: ParsedEmail, ctx: OrgContext, sender_trusted: bool) -> bool:
    if not reg:
        return False
    if reg in ESIGN_DOMAINS or reg in WELL_KNOWN_SENDERS:
        return True
    from_reg = registrable_domain(email.from_.domain) if email.from_ else ""
    if reg in ctx.org_domains:
        return True
    if reg in ctx.vendor_domains and sender_trusted and (reg == from_reg or same_brand(reg, from_reg or "")):
        return True
    if sender_trusted and from_reg and (reg == from_reg or same_brand(reg, from_reg)):
        return True
    return False


def analyze_content(
    email: ParsedEmail,
    auth: AuthAssessment,
    identity: IdentityAssessment,
    links: list[Link],
    ctx: OrgContext,
    link_findings: list[Finding] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    text = _blob(email)
    http_links = [link for link in links if link.scheme in {"http", "https"} and link.source != "base"]
    unsafe = [
        link
        for link in http_links
        if not _known_destination(link.registrable_domain, email, ctx, identity.sender_trusted)
    ]

    if email.has_password_field:
        add_finding(
            findings,
            Finding(
                id="content.embedded_password_form",
                severity="critical",
                category="content",
                title="Password field embedded in the message",
                explanation="The HTML includes a password input. Legitimate services do not collect passwords inside an email.",
                evidence=["<input type=password>"],
            ),
        )

    if _HARVEST.search(text) and unsafe:
        sample = unsafe[0]
        sender_domain = email.from_.domain if email.from_ else ""
        same_site = bool(sender_domain) and sample.registrable_domain == registrable_domain(sender_domain)
        if same_site:
            where = (
                f"{sample.host}. {sender_domain} is not {ctx.org_name} or one of its vendors"
            )
        else:
            where = f"{sample.host}, which is not the sender ({sender_domain or 'unknown'})"
        add_finding(
            findings,
            Finding(
                id="content.credential_harvest",
                severity="high",
                category="content",
                title="Asks the recipient to validate an account on an untrusted site",
                explanation=(
                    "The message tells the recipient to verify or restore an account, and a link goes to "
                    f"{where}. Mailbox-quota and account-suspension notices are a standard lure."
                ),
                evidence=[clip_phrase(text, _HARVEST), sample.url[:180]],
            ),
        )

    # Handle unfamiliar sender requests
    from_reg = registrable_domain(email.from_.domain) if email.from_ else ""
    links_deceive = any(f.severity in {"high", "critical"} for f in link_findings or [])
    own_site = [
        link
        for link in unsafe
        if auth.aligned
        and not links_deceive
        and from_reg
        and (link.registrable_domain == from_reg or same_brand(link.registrable_domain, from_reg))
    ]
    foreign = [link for link in unsafe if link not in own_site]

    if _SIGN.search(text) and not foreign and own_site:
        add_finding(
            findings,
            Finding(
                id="content.signature_request_new_sender",
                severity="info",
                category="content",
                title="Signature request from a sender this organization has not dealt with",
                explanation=(
                    f"{from_reg} authenticated and the signing link stays on its own domain, so nothing hides "
                    f"where the link goes. It is not a known vendor of {ctx.org_name}; confirm the agreement is expected."
                ),
                evidence=[clip_phrase(text, _SIGN), own_site[0].url[:180]],
            ),
        )

    if _SIGN.search(text) and foreign:
        sample = foreign[0]
        add_finding(
            findings,
            Finding(
                id="content.untrusted_signature_request",
                severity="high",
                category="content",
                title="Signature request points at an unknown signing site",
                explanation=(
                    f"The message asks for a signature and links to {sample.host}. "
                    "That domain is not a known e-sign provider and is not an authenticated vendor "
                    f"of {ctx.org_name}. Owning a domain that SPF-passes does not make it DocuSign."
                ),
                evidence=[clip_phrase(text, _SIGN), sample.url[:180]],
            ),
        )

    if _PAYMENT.search(text):
        reply = email.reply_to[0].email if email.reply_to else ""
        why = _payment_deception(email, auth, identity)
        if why:
            add_finding(
                findings,
                Finding(
                    id="bec.payment_diversion",
                    severity="critical",
                    category="content",
                    title="Payment details change on an untrusted path",
                    explanation=(
                        "The message asks to change banking or remittance details. "
                        f"{why} Confirm any account change by phone, using a number you already have."
                    ),
                    evidence=[clip_phrase(text, _PAYMENT)] + ([f"Reply-To: {reply}"] if reply else []),
                ),
            )
        elif identity.sender_trusted:
            add_finding(
                findings,
                Finding(
                    id="bec.payment_change_request",
                    severity="high",
                    category="content",
                    title="Authenticated sender is asking to change payment details",
                    explanation=(
                        "The sender authenticated, and the request is still the highest-risk thing in "
                        "business email. Compromised vendor mailboxes send exactly this. "
                        "Pay only after confirming through a known phone number."
                    ),
                    evidence=[clip_phrase(text, _PAYMENT)],
                ),
            )
        else:
            from_domain = email.from_.domain if email.from_ else "the sender's domain"
            who = (
                f"{from_domain} authenticated, but it is not a known vendor of {ctx.org_name}."
                if auth.aligned
                else "The sender's identity could not be verified from this copy."
            )
            add_finding(
                findings,
                Finding(
                    id="bec.new_payee_request",
                    severity="high",
                    category="content",
                    title="Payment request from a sender this organization has not dealt with",
                    explanation=(
                        f"The message asks for payment to bank details. {who} Nothing in it is deceptive, "
                        "but a new payee is how invoice fraud starts. Confirm by phone, using a number "
                        "you find independently, before paying."
                    ),
                    evidence=[clip_phrase(text, _PAYMENT)],
                ),
            )

    if not identity.sender_trusted and (_SECRECY.search(text) or _GIFT.search(text) or (_DESK.search(text) and _FAVOR.search(text))):
        evidence = []
        for pattern in (_SECRECY, _GIFT, _DESK, _FAVOR):
            phrase = clip_phrase(text, pattern)
            if phrase:
                evidence.append(phrase)
        add_finding(
            findings,
            Finding(
                id="bec.pretext",
                severity="critical",
                category="content",
                title="Business-email-compromise pretext",
                explanation=(
                    "The message presses for a quiet, urgent favor and the sender is not an "
                    f"authenticated party of {ctx.org_name}. This is the opening move of a "
                    "gift-card or payment scam, often before any link appears."
                ),
                evidence=evidence,
            ),
        )

    from_domain = email.from_.domain if email.from_ else ""
    gov_suffix = from_domain.endswith(".mil") or from_domain.endswith(".gov")
    display = email.from_.display if email.from_ else ""
    claims_gov = bool(_GOV_DISPLAY.search(display) or _GOV_BODY.search(text))
    if claims_gov and not gov_suffix and not (identity.sender_trusted and ctx.allows_sender(from_domain)):
        add_finding(
            findings,
            Finding(
                id="brand.government_impersonation",
                severity="critical",
                category="brand",
                title="Claims to be a government office from a non-government domain",
                explanation=(
                    f"The message presents itself as a Department of Defense or SPRS notice, but it was sent from "
                    f"{from_domain or 'an unknown domain'} rather than a .mil or .gov address. "
                    "SPF can pass for any domain an attacker registers."
                ),
                evidence=[f"From: {display} <{email.from_.email if email.from_ else ''}>"],
            ),
        )

    if _NOTIFY.search(text) and not unsafe:
        add_finding(
            findings,
            Finding(
                id="content.security_notification",
                severity="info",
                category="content",
                title="Security notification with first-party destinations",
                explanation=(
                    "The message reports an account change and, if it links anywhere, links to the "
                    "sender's own domain. If the change was unexpected, review it by navigating to "
                    "the service directly rather than assuming the notice is a lure."
                ),
                evidence=[clip_phrase(text, _NOTIFY)],
            ),
        )

    typos = [label for pattern, label in _TYPOS if pattern.search(text)]
    if typos:
        add_finding(
            findings,
            Finding(
                id="content.language_errors",
                severity="info",
                category="content",
                title="Unusual spelling in a sensitive request",
                explanation="Spelling errors support a verdict that already has stronger evidence. They are not a verdict by themselves.",
                evidence=typos,
            ),
        )

    if identity.sender_trusted and (
        email.list_unsubscribe or re.search(r"unsubscribe", text, re.I)
    ) and re.search(r"(\d+\s*%\s*off|unsubscribe|\bsale\b|shop now)", text, re.I):
        add_finding(
            findings,
            Finding(
                id="content.marketing",
                severity="info",
                category="content",
                title="Authenticated marketing mail",
                explanation=(
                    "The message is promotional, authenticates as the sending brand, offers an "
                    "unsubscribe path, and keeps links on that brand's domain. Sale urgency is not "
                    "the same thing as an account-takeover lure."
                ),
                evidence=[email.list_unsubscribe[:180]] if email.list_unsubscribe else ["unsubscribe link in the body"],
            ),
        )

    return findings


_IMPERSONATION = {
    "bec.executive_impersonation",
    "bec.contact_impersonation",
    "brand.lookalike",
    "identity.multiple_from",
    "identity.missing_from",
}


def _payment_deception(email: ParsedEmail, auth: AuthAssessment, identity: IdentityAssessment) -> str:
    """Why a payment request is on a deceptive path, or "" when nothing is deceptive.

    Being unknown to the organization is not deception. A failed authentication
    check, a diverted reply, or an impersonated identity is.
    """
    sender = email.from_.email if email.from_ else "The sender"
    reply = email.reply_to[0].email if email.reply_to else ""
    if identity.reply_to_mismatch and reply:
        return f"Replies from {sender} are diverted to {reply}."
    failed = [f for f in auth.findings if f.severity != "info"]
    if failed:
        return f"{sender} did not authenticate: {failed[0].title.lower()}."
    impersonation = [f for f in identity.findings if f.id in _IMPERSONATION]
    if impersonation:
        return f"The sender identity is deceptive: {impersonation[0].title}."
    return ""


def clip_phrase(text: str, pattern: re.Pattern) -> str:
    match = pattern.search(text or "")
    if not match:
        return ""
    start = max(0, match.start() - 40)
    end = min(len(text), match.end() + 40)
    return " ".join(text[start:end].split())
