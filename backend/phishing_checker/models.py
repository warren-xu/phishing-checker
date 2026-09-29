"""Shared records. Scoring lives in the engine so weights stay in one place."""

from __future__ import annotations

from dataclasses import dataclass, field


SEVERITY_WEIGHT = {
    "info": 0,
    "low": 5,
    "medium": 15,
    "high": 30,
    "critical": 50,
}

PHISHING_THRESHOLD = 45
SUSPICIOUS_THRESHOLD = 15


@dataclass
class Finding:
    id: str
    severity: str
    category: str
    title: str
    explanation: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "explanation": self.explanation,
            "evidence": self.evidence,
            "weight": SEVERITY_WEIGHT[self.severity],
        }


@dataclass
class Address:
    display: str
    email: str
    domain: str
    local: str

    def to_dict(self) -> dict:
        return {
            "display": self.display,
            "email": self.email,
            "domain": self.domain,
            "local": self.local,
        }


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    extension: str
    magic: str

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size": self.size,
            "extension": self.extension,
            "magic": self.magic,
        }


@dataclass
class Link:
    url: str
    host: str
    registrable_domain: str
    scheme: str
    source: str
    visible_text: str
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "host": self.host,
            "registrable_domain": self.registrable_domain,
            "scheme": self.scheme,
            "source": self.source,
            "visible_text": self.visible_text,
            "issues": self.issues,
        }


@dataclass
class ParsedEmail:
    subject: str
    from_: Address | None
    from_all: list[Address]
    to: list[Address]
    reply_to: list[Address]
    return_path: str
    date: str
    message_id: str
    body_text: str
    body_html: str
    html_visible_text: str
    authentication_results: str
    list_unsubscribe: str
    attachments: list[Attachment]
    anchors: list[tuple[str, str]]
    base_href: str
    form_actions: list[str]
    meta_refresh: list[str]
    has_password_field: bool


def add_finding(findings: list[Finding], finding: Finding) -> None:
    for existing in findings:
        if existing.id == finding.id:
            for item in finding.evidence:
                if item not in existing.evidence:
                    existing.evidence.append(item)
            rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            if rank[finding.severity] > rank[existing.severity]:
                existing.severity = finding.severity
                existing.title = finding.title
                existing.explanation = finding.explanation
            return
    findings.append(finding)
