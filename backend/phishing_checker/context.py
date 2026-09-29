"""Organization context. BEC checks are only as good as this directory."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from phishing_checker.domains import registrable_domain

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTEXT = ROOT / "context" / "organization.json"


@dataclass
class Person:
    name: str
    role: str
    domains: set[str]


@dataclass
class OrgContext:
    org_name: str
    org_domains: set[str]
    people: list[Person] = field(default_factory=list)
    vendor_domains: set[str] = field(default_factory=set)
    vendor_names: dict[str, str] = field(default_factory=dict)
    trusted_authserv_ids: set[str] = field(default_factory=set)
    trust_unnamed_authserv: bool = False

    def allows_sender(self, domain: str | None) -> bool:
        reg = registrable_domain(domain)
        if not reg:
            return False
        return reg in self.org_domains or reg in self.vendor_domains


def load_context(path: Path | None = None) -> OrgContext:
    raw = json.loads((path or DEFAULT_CONTEXT).read_text())
    org = raw.get("organization") or {}
    org_domains = {d.lower() for d in org.get("domains") or []}
    people = []
    for item in raw.get("people") or []:
        domains = {d.lower() for d in item.get("domains") or []}
        if item.get("role") in {"executive", "employee"}:
            domains.update(org_domains)
        people.append(
            Person(
                name=item["name"],
                role=item.get("role") or "employee",
                domains=domains,
            )
        )
    vendor_domains: set[str] = set()
    vendor_names: dict[str, str] = {}
    for vendor in raw.get("vendors") or []:
        for domain in vendor.get("domains") or []:
            vendor_domains.add(domain.lower())
            vendor_names[domain.lower()] = vendor.get("name") or domain
    return OrgContext(
        org_name=org.get("name") or "the organization",
        org_domains=org_domains,
        people=people,
        vendor_domains=vendor_domains,
        vendor_names=vendor_names,
        trusted_authserv_ids={d.lower() for d in raw.get("trusted_authserv_ids") or []},
        trust_unnamed_authserv=bool(raw.get("trust_unnamed_authserv")),
    )
