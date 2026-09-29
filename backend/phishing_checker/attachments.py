"""Attachment classification by name, declared type, and a short magic prefix.

Bytes are not executed and are not returned to the client.
"""

from __future__ import annotations

import re

from phishing_checker.models import Finding, ParsedEmail, add_finding

_CRITICAL_EXT = {
    "exe",
    "scr",
    "js",
    "jse",
    "vbs",
    "vbe",
    "wsf",
    "hta",
    "msi",
    "msp",
    "bat",
    "cmd",
    "ps1",
    "dll",
    "com",
    "pif",
    "lnk",
    "iso",
    "img",
    "vhd",
    "vhdx",
    "html",
    "htm",
    "svg",
    "docm",
    "xlsm",
    "pptm",
    "jar",
    "apk",
    "reg",
    "msc",
    "application",
    "gadget",
    "cpl",
    "scf",
}
_ARCHIVE_EXT = {"zip", "rar", "7z"}
_BENIGN_LOOKING = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "jpg", "jpeg", "png", "gif"}

""" Analyze attachments for dangerous filetypes, passworded archives, and MIME type mismatches. """
def analyze_attachments(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    body = f"{email.subject}\n{email.body_text}\n{email.html_visible_text}"
    mentions_password = bool(re.search(r"\bpassword\b", body, re.I))

    for item in email.attachments:
        name = item.filename or "(unnamed)"
        parts = [part for part in name.lower().rsplit(".", 5) if part]
        ext = item.extension.lower()
        if len(parts) >= 3 and parts[-2] in _BENIGN_LOOKING and (parts[-1] in _CRITICAL_EXT or parts[-1] in _ARCHIVE_EXT):
            add_finding(
                findings,
                Finding(
                    id="attachment.double_extension",
                    severity="critical",
                    category="attachments",
                    title="Attachment hides one extension behind another",
                    explanation=f"{name} ends in .{parts[-2]}.{parts[-1]}. The last extension is the one the operating system executes.",
                    evidence=[name, item.content_type],
                ),
            )
        if ext in _CRITICAL_EXT or item.content_type in {"text/html", "image/svg+xml"} and item.filename:
            if ext in _CRITICAL_EXT or (item.content_type in {"text/html", "image/svg+xml"} and ext in {"html", "htm", "svg"}):
                add_finding(
                    findings,
                    Finding(
                        id="attachment.dangerous_type",
                        severity="critical",
                        category="attachments",
                        title="Attachment is a dangerous file type",
                        explanation=(
                            f"{name} is a {ext or item.content_type} file. Executables, script, disk images, "
                            "macro documents, and HTML attachments are common malware and credential-harvest containers."
                        ),
                        evidence=[name, item.content_type or ext],
                    ),
                )
        if ext == "pdf" and item.size and not item.magic.startswith("%PDF"):
            add_finding(
                findings,
                Finding(
                    id="attachment.mime_mismatch",
                    severity="high",
                    category="attachments",
                    title="File named as a PDF does not start like a PDF",
                    explanation=f"{name} claims to be a PDF, but its first bytes are {item.magic!r} rather than %PDF.",
                    evidence=[name, item.magic, item.content_type],
                ),
            )
        elif ext == "pdf" and item.content_type.startswith("text/"):
            add_finding(
                findings,
                Finding(
                    id="attachment.mime_mismatch",
                    severity="high",
                    category="attachments",
                    title="PDF filename is served as text",
                    explanation=f"{name} is declared as {item.content_type}.",
                    evidence=[name, item.content_type],
                ),
            )
        if ext in _ARCHIVE_EXT and mentions_password:
            add_finding(
                findings,
                Finding(
                    id="attachment.passworded_archive",
                    severity="high",
                    category="attachments",
                    title="Password and an archive are in the same message",
                    explanation=(
                        f"The body mentions a password and attaches {name}. "
                        "Password-protected archives are used to slip malware past scanners. Confirm the file with the sender."
                    ),
                    evidence=[name],
                ),
            )
    return findings
