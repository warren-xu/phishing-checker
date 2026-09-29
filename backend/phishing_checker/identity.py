"""From, Reply-To, and display-name checks.

Authentication passing does not end the analysis. A mailbox the attacker owns
will SPF-pass and DKIM-sign. What matters is whether the identity matches a
person your organization actually corresponds with.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from phishing_checker.auth import AuthAssessment
from phishing_checker.context import OrgContext
from phishing_checker.domains import (
    FREEMAIL,
    NOTIFICATION_PLATFORMS,
    WELL_KNOWN_SENDERS,
    lookalike_of,
    protected_domains,
    registrable_domain,
    same_brand,
)
from phishing_checker.models import Address, Finding, ParsedEmail, add_finding


@dataclass
class IdentityAssessment:
    sender_trusted: bool = False
    reply_to_mismatch: bool = False
    findings: list[Finding] = field(default_factory=list)


def sender_is_trusted(email: ParsedEmail, auth: AuthAssessment, ctx: OrgContext) -> bool:
    if email.from_ is None:
        return False
    reg = registrable_domain(email.from_.domain)
    allowlisted = bool(
        reg and (reg in ctx.org_domains or reg in ctx.vendor_domains or reg in WELL_KNOWN_SENDERS)
    )
    if not allowlisted or not auth.present or not auth.header_trusted:
        return False
    return auth.aligned


def _name_in_display(name: str, display: str) -> bool:
    if not display or len(name.split()) < 2:
        return False
    folded = re.sub(r"[^a-z\s]", " ", display.lower())
    folded = re.sub(r"\s+", " ", folded).strip()
    return name.lower() in folded


def _platform_notification(addr: Address) -> bool:
    reg = registrable_domain(addr.domain)
    if reg not in NOTIFICATION_PLATFORMS:
        return False
    local = addr.local.lower()
    return any(token in local for token in ("noreply", "no-reply", "notification", "notify", "drive-shares"))


def _differs(left: str, right: str) -> bool:
    if not left or not right:
        return False
    return registrable_domain(left) != registrable_domain(right) and not same_brand(left, right)


def analyze_identity(email: ParsedEmail, auth: AuthAssessment, ctx: OrgContext) -> IdentityAssessment:
    result = IdentityAssessment(sender_trusted=sender_is_trusted(email, auth, ctx))
    if len(email.from_all) > 1:
        add_finding(
            result.findings,
            Finding(
                id="identity.multiple_from",
                severity="medium",
                category="identity",
                title="Multiple From addresses",
                explanation="The From header lists more than one address. Mail clients hide all but the first, which is a spoofing trick.",
                evidence=[addr.email for addr in email.from_all],
            ),
        )
    if email.from_ is None:
        add_finding(
            result.findings,
            Finding(
                id="identity.missing_from",
                severity="high",
                category="identity",
                title="Missing From address",
                explanation="The message has no usable From address. There is no sender identity to authenticate.",
                evidence=[],
            ),
        )

    covered_reply = False
    for field_name, addresses in (("from", email.from_all), ("reply-to", email.reply_to)):
        for addr in addresses:
            covered_reply = _check_person(email, auth, ctx, result, field_name, addr) or covered_reply

    from_domain = email.from_.domain if email.from_ else ""
    for addr in email.reply_to:
        if _differs(addr.domain, from_domain) and not covered_reply:
            result.reply_to_mismatch = True
            add_finding(
                result.findings,
                Finding(
                    id="identity.reply_to_mismatch",
                    severity="high",
                    category="identity",
                    title="Reply-To uses a different domain",
                    explanation=(
                        f"From is {email.from_.email if email.from_ else 'missing'}, but replies go to "
                        f"{addr.email}. A mailbox compromise often keeps the real From domain and "
                        "diverts the conversation to an attacker address."
                    ),
                    evidence=[f"From: {email.from_.email if email.from_ else ''}", f"Reply-To: {addr.email}"],
                ),
            )
        elif _differs(addr.domain, from_domain):
            result.reply_to_mismatch = True

    if (
        email.return_path
        and from_domain
        and not auth.aligned
        and _differs(email.return_path.split("@")[-1], from_domain)
    ):
        add_finding(
            result.findings,
            Finding(
                id="identity.return_path_mismatch",
                severity="medium",
                category="identity",
                title="Return-Path does not match From",
                explanation=(
                    f"Bounces go to {email.return_path}, which is a different organization than "
                    f"{from_domain}, and the message did not authenticate."
                ),
                evidence=[f"Return-Path: {email.return_path}", f"From domain: {from_domain}"],
            ),
        )

    if email.from_ and email.from_.domain:
        imitated = lookalike_of(email.from_.domain, protected_domains(ctx.org_domains, ctx.vendor_domains))
        if imitated:
            add_finding(
                result.findings,
                Finding(
                    id="brand.lookalike",
                    severity="critical",
                    category="brand",
                    title=f"From domain imitates {imitated}",
                    explanation=(
                        f"{email.from_.domain} is not {imitated}. The lookalike can still pass SPF and "
                        "DKIM, because the attacker controls that domain."
                    ),
                    evidence=[f"From: {email.from_.email}", f"imitates {imitated}"],
                ),
            )
    return result


def _check_person(
    email: ParsedEmail,
    auth: AuthAssessment,
    ctx: OrgContext,
    result: IdentityAssessment,
    field_name: str,
    addr: Address,
) -> bool:
    """Return True when a Reply-To impersonation finding already covers this address."""
    matched = False
    for person in ctx.people:
        if not _name_in_display(person.name, addr.display):
            continue
        reg = registrable_domain(addr.domain)
        if reg and reg in person.domains:
            continue
        if _platform_notification(addr) and auth.aligned:
            add_finding(
                result.findings,
                Finding(
                    id="identity.platform_notification",
                    severity="info",
                    category="identity",
                    title="Known person named in a platform notification",
                    explanation=(
                        f"{person.name} appears in the {field_name} display name, and the message "
                        f"was sent by {addr.domain}, a notification platform. That is normal for "
                        "file-share and e-sign mail. Open the document from the platform itself "
                        "if the share was unexpected."
                    ),
                    evidence=[f"{field_name}: {addr.display} <{addr.email}>"],
                ),
            )
            continue
        freemail = reg in FREEMAIL
        serious = person.role == "executive" or field_name == "reply-to" or freemail
        where = "From" if field_name == "from" else "Reply-To"
        add_finding(
            result.findings,
            Finding(
                id="bec.executive_impersonation" if person.role == "executive" else "bec.contact_impersonation",
                severity="critical" if serious else "high",
                category="identity",
                title=f"{person.name} is not writing from their own domain",
                explanation=(
                    f"The {where} display name matches {person.name} ({person.role.replace('_', ' ')}), "
                    f"but the address is {addr.email}. Their known domains are "
                    f"{', '.join(sorted(person.domains)) or 'the organization domain'}."
                ),
                evidence=[f"{where}: {addr.display} <{addr.email}>"],
            ),
        )
        matched = field_name == "reply-to"
    return matched
