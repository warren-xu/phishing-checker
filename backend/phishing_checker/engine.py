"""Turn a mailbox copy into a verdict, a score, and the evidence behind both."""

from __future__ import annotations

import re

from phishing_checker.attachments import analyze_attachments
from phishing_checker.auth import analyze_auth
from phishing_checker.content import analyze_content
from phishing_checker.context import OrgContext, load_context
from phishing_checker.identity import analyze_identity
from phishing_checker.links import analyze_links
from phishing_checker.models import (
    PHISHING_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    SEVERITY_WEIGHT,
    Finding,
    add_finding,
)
from phishing_checker.parse import parse_email

_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_ACTIONS = {
    "phishing": (
        "Do not click links, open attachments, reply, or send payment. "
        "Report the message to security. If it requests a payment or account change, "
        "confirm with the sender through a phone number or portal you already use."
    ),
    "suspicious": (
        "Do not complete the request through links in this message. "
        "Confirm it through a channel you already trust."
    ),
    "legitimate": (
        "No material phishing indicators in this copy. "
        "If the message was unexpected, confirm it through a channel you already trust."
    ),
}


def analyze_message(raw: bytes | str, ctx: OrgContext | None = None) -> dict:
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    context = ctx or load_context()
    try:
        email = parse_email(raw)
    except Exception as exc:
        return _report(
            verdict="suspicious",
            score=SUSPICIOUS_THRESHOLD,
            summary=f"The message could not be parsed as mail ({exc}). Treat it as untrusted.",
            auth={},
            identity={"sender_trusted": False, "reply_to_mismatch": False},
            message={},
            links=[],
            attachments=[],
            findings=[
                Finding(
                    id="parse.malformed",
                    severity="medium",
                    category="parse",
                    title="Message could not be parsed",
                    explanation=f"The parser raised {type(exc).__name__}: {exc}.",
                    evidence=[],
                )
            ],
        )

    auth = analyze_auth(email, context)
    identity = analyze_identity(email, auth, context)
    links, link_findings = analyze_links(email, auth, context)
    content_findings = analyze_content(email, auth, identity, links, context, link_findings)
    attachment_findings = analyze_attachments(email)

    findings: list[Finding] = []
    for group in (auth.findings, identity.findings, link_findings, content_findings, attachment_findings):
        for finding in group:
            add_finding(findings, finding)
    findings.sort(key=lambda item: (-_RANK[item.severity], item.id))

    score = sum(SEVERITY_WEIGHT[item.severity] for item in findings)
    material = [item for item in findings if item.severity != "info"]
    if any(item.severity == "critical" for item in material) or score >= PHISHING_THRESHOLD:
        verdict = "phishing"
    elif score >= SUSPICIOUS_THRESHOLD:
        verdict = "suspicious"
    else:
        verdict = "legitimate"

    if material:
        summary = " ".join(item.explanation for item in material[:2])
    elif findings:
        summary = findings[0].explanation
    elif auth.aligned:
        summary = (
            f"DMARC aligned for {email.from_.domain if email.from_ else 'the sender'}. "
            "Links, reply path, and attachments do not add a phishing indicator."
        )
    else:
        summary = (
            "No material phishing indicators. There is also no trusted authentication result, "
            "so this is not a positive identification of the sender."
        )

    return _report(
        verdict=verdict,
        score=score,
        summary=summary,
        auth=auth.to_dict(),
        identity={
            "sender_trusted": identity.sender_trusted,
            "reply_to_mismatch": identity.reply_to_mismatch,
        },
        message={
            "subject": email.subject,
            "date": email.date,
            "message_id": email.message_id,
            "from": email.from_.to_dict() if email.from_ else None,
            "to": [addr.to_dict() for addr in email.to],
            "reply_to": [addr.to_dict() for addr in email.reply_to],
            "return_path": email.return_path,
            **_body(email),
        },
        links=[item.to_dict() for item in links],
        attachments=[item.to_dict() for item in email.attachments],
        findings=findings,
    )


_BODY_LIMIT = 50_000


def _body(email) -> dict:
    """Readable body for display. HTML is reduced to its visible text, never returned as markup."""
    text = email.body_text.strip()
    source = "text"
    if not text:
        text = email.html_visible_text
        source = "html" if text.strip() else ""
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n[ \t]*(\n[ \t]*)+", "\n\n", text).strip()
    return {"body": text[:_BODY_LIMIT], "body_source": source}


def _report(
    verdict: str,
    score: int,
    summary: str,
    auth: dict,
    identity: dict,
    message: dict,
    links: list,
    attachments: list,
    findings: list[Finding],
) -> dict:
    notes = [item.to_dict() for item in findings if item.severity == "info"]
    material = [item.to_dict() for item in findings if item.severity != "info"]
    return {
        "verdict": verdict,
        "score": score,
        "thresholds": {"suspicious": SUSPICIOUS_THRESHOLD, "phishing": PHISHING_THRESHOLD},
        "summary": summary,
        "recommended_action": _ACTIONS[verdict],
        "message": message,
        "authentication": auth,
        "identity": identity,
        "links": links,
        "attachments": attachments,
        "findings": material,
        "notes": notes,
    }
