"""Authentication-Results, trusted only when this organization's gateway stamped it."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from phishing_checker.context import OrgContext
from phishing_checker.domains import registrable_domain
from phishing_checker.models import Finding, ParsedEmail, add_finding

_COMMENT = re.compile(r"\([^()]*\)")
_RESULT = re.compile(r"^\s*([a-z][a-z0-9-]*)\s*=\s*([a-z]+)", re.I)
_PROP = re.compile(
    r"\b(smtp\.mailfrom|header\.from|header\.d|header\.i)\s*=\s*(\"[^\"]*\"|[^\s;]+)",
    re.I,
)


@dataclass
class MethodResult:
    method: str
    result: str
    props: dict[str, str]


def parse_authentication_results(raw: str) -> tuple[str, list[MethodResult]]:
    """Split the header into its authserv-id and one record per method result.

    Properties stay with the result they belong to, so a passing DKIM signature
    for one domain is never credited to another signature's header.d. Exchange
    Online omits the authserv-id and starts directly with spf=...; that case
    returns an empty id instead of treating the first result as the id.
    """
    text = raw
    while True:
        stripped = _COMMENT.sub(" ", text)
        if stripped == text:
            break
        text = stripped
    segments = text.split(";")
    head = segments[0].strip()
    if _RESULT.match(head):
        authserv, resinfo = "", segments
    else:
        authserv, resinfo = (head.split()[0] if head else ""), segments[1:]
    results = []
    for segment in resinfo:
        match = _RESULT.match(segment)
        if not match:
            continue
        props = {}
        for name, value in _PROP.findall(segment[match.end() :]):
            props.setdefault(name.lower(), value.strip('"'))
        results.append(MethodResult(match.group(1).lower(), match.group(2).lower(), props))
    return authserv, results


@dataclass
class AuthAssessment:
    present: bool = False
    header_trusted: bool = False
    authserv_id: str = ""
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    mailfrom_domain: str = ""
    dkim_domains: list[str] = field(default_factory=list)
    dkim_signatures: list[dict] = field(default_factory=list)
    aligned: bool = False
    spf_aligned: bool = False
    dkim_aligned: bool = False
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "present": self.present,
            "header_trusted": self.header_trusted,
            "authserv_id": self.authserv_id,
            "spf": self.spf,
            "dkim": self.dkim,
            "dmarc": self.dmarc,
            "mailfrom_domain": self.mailfrom_domain,
            "dkim_domains": self.dkim_domains,
            "dkim_signatures": self.dkim_signatures,
            "aligned": self.aligned,
            "spf_aligned": self.spf_aligned,
            "dkim_aligned": self.dkim_aligned,
        }


def _domain_of(value: str) -> str:
    value = value.strip().strip("<>").lower()
    if "@" in value:
        value = value.rsplit("@", 1)[-1]
    return value.rstrip(".")


def _trusted_authserv(authserv: str, ctx: OrgContext) -> bool:
    if not authserv:
        return ctx.trust_unnamed_authserv
    host = authserv.split("@")[-1].lower().rstrip(".")
    if host in ctx.trusted_authserv_ids:
        return True
    reg = registrable_domain(host)
    if reg in ctx.org_domains:
        return True
    return any(host == domain or host.endswith("." + domain) for domain in ctx.org_domains)


def _aligns(candidate: str, from_domain: str) -> bool:
    return bool(candidate) and registrable_domain(candidate) == registrable_domain(from_domain)


def analyze_auth(email: ParsedEmail, ctx: OrgContext) -> AuthAssessment:
    result = AuthAssessment()
    raw = email.authentication_results
    if not raw:
        add_finding(
            result.findings,
            Finding(
                id="auth.missing",
                severity="info",
                category="authentication",
                title="No Authentication-Results header",
                explanation=(
                    "This copy has no Authentication-Results header, so SPF, DKIM, "
                    "and DMARC were not available to the checker. Missing authentication "
                    "is not itself phishing, but a sensitive request cannot be cleared on identity."
                ),
                evidence=[],
            ),
        )
        return result

    result.present = True
    result.authserv_id, results = parse_authentication_results(raw)
    result.header_trusted = _trusted_authserv(result.authserv_id, ctx)

    def of(method: str) -> list[MethodResult]:
        return [item for item in results if item.method == method]

    def summary(items: list[MethodResult]) -> str | None:
        values = [item.result for item in items]
        if "pass" in values:
            return "pass"
        return values[0] if values else None

    from_domain = email.from_.domain if email.from_ else ""
    spf = of("spf")
    dkim = of("dkim")
    result.spf = summary(spf)
    result.dkim = summary(dkim)
    result.dmarc = summary(of("dmarc"))

    spf_passing = [item for item in spf if item.result == "pass"]
    mailfrom = next(
        (item.props["smtp.mailfrom"] for item in spf_passing + spf if item.props.get("smtp.mailfrom")),
        "",
    )
    result.mailfrom_domain = _domain_of(mailfrom) if mailfrom else ""
    result.spf_aligned = any(
        _aligns(_domain_of(item.props.get("smtp.mailfrom", "")), from_domain) for item in spf_passing
    )

    for item in dkim:
        signer = item.props.get("header.d") or item.props.get("header.i") or ""
        domain = _domain_of(signer) if signer else ""
        result.dkim_signatures.append({"result": item.result, "domain": domain})
        if domain:
            result.dkim_domains.append(domain)
    result.dkim_aligned = any(
        sig["result"] == "pass" and _aligns(sig["domain"], from_domain) for sig in result.dkim_signatures
    )
    if result.header_trusted and result.dmarc == "pass":
        result.aligned = True
    elif result.header_trusted and result.dmarc != "fail" and (result.spf_aligned or result.dkim_aligned):
        result.aligned = True

    if not result.header_trusted:
        add_finding(
            result.findings,
            Finding(
                id="auth.untrusted_results",
                # Leave as unverified, would be the same as having no header at all
                severity="info",
                category="authentication",
                title="Authentication-Results is not from your gateway",
                explanation=(
                    (
                        f"Authentication-Results was stamped by {result.authserv_id}, "
                        f"which is not a mail host for {ctx.org_name}. "
                    )
                    if result.authserv_id
                    else (
                        "Authentication-Results names no server. Exchange Online stamps it this way; "
                        "set trust_unnamed_authserv in the organization context if the mailbox is hosted there. "
                    )
                )
                + "Pass results in this header are ignored. A sender can prepend a forged "
                "authentication header if the receiving gateway does not strip it.",
                evidence=[raw[:300]],
            ),
        )
        result.aligned = False
        return result

    if result.dmarc == "fail":
        add_finding(
            result.findings,
            Finding(
                id="auth.dmarc_fail",
                severity="high",
                category="authentication",
                title="DMARC failed",
                explanation=(
                    f"{result.authserv_id or 'Your mail gateway'} reported dmarc=fail for {from_domain or 'the From domain'}. "
                    "The domain in the From header did not authenticate this message, so the "
                    "display name and address are not reliable."
                ),
                evidence=[
                    f"dmarc={result.dmarc}",
                    f"spf={result.spf or 'absent'}",
                    f"dkim={result.dkim or 'absent'}",
                    f"smtp.mailfrom={result.mailfrom_domain or 'absent'}",
                    f"header.d={', '.join(result.dkim_domains) or 'absent'}",
                ],
            ),
        )
    elif result.spf == "fail" and not result.dkim_aligned:
        add_finding(
            result.findings,
            Finding(
                id="auth.not_authenticated",
                severity="high",
                category="authentication",
                title="Neither SPF nor DKIM authenticated the sender",
                explanation=(
                    f"SPF failed for {from_domain}, and no passing DKIM signature is from {from_domain}. "
                    "A signature from another domain proves only that that domain sent it. "
                    "Nothing ties this message to the domain it claims."
                ),
                evidence=[f"spf={result.spf}"]
                + [f"dkim={sig['result']} header.d={sig['domain'] or 'absent'}" for sig in result.dkim_signatures],
            ),
        )
    elif result.spf == "softfail" and not result.dkim_aligned and result.dmarc != "pass":
        add_finding(
            result.findings,
            Finding(
                id="auth.spf_softfail",
                severity="medium",
                category="authentication",
                title="SPF softfail without an aligned DKIM signature",
                explanation=(
                    f"SPF softfailed for {result.mailfrom_domain or from_domain} and no DKIM signature from {from_domain} passed. "
                    "Treat the From address as unverified."
                ),
                evidence=["spf=softfail", f"dkim={result.dkim or 'absent'}"],
            ),
        )
    elif result.dkim == "fail" and not result.spf_aligned:
        add_finding(
            result.findings,
            Finding(
                id="auth.dkim_fail",
                severity="medium",
                category="authentication",
                title="DKIM failed",
                explanation=(
                    "A DKIM signature failed and SPF is not aligned with the From domain. "
                    "The message may have been altered or signed by a different domain."
                ),
                evidence=["dkim=fail", f"header.d={', '.join(result.dkim_domains) or 'absent'}"],
            ),
        )
    return result
