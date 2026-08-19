#!/usr/bin/env python3
"""Fail closed when a public repository contains private or non-portable material."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


REQUIRED_FILES = ("README.md", "AGENTS.md", "SECURITY.md", "LICENSE")
IGNORED_PARTS = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "node_modules"}
BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf"}
APACHE_2_LICENSE_MARKERS = (
    "Apache License",
    "Version 2.0, January 2004",
)
FORBIDDEN_LITERALS = (
    "ix-" + "agy",
    "ix" + "security",
    "True" + "Me",
    "fizi" + "ico",
    "skill-" + "bettor",
    "/Users" + "/",
)
SECRET_PATTERNS = {
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github-token": re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    "aws-access-key": re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    "generic-secret-assignment": re.compile(
        r"(?i)\b(?:api[_-]?key|client[_-]?secret|password|access[_-]?token)\s*[:=]\s*['\"][^'\"]{8,}"
    ),
}
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
MARKDOWN_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+['\"][^)]*['\"])?\)")


def _iter_paths(root: Path):
    for path in sorted(root.rglob("*")):
        if any(part in IGNORED_PARTS for part in path.relative_to(root).parts):
            continue
        yield path


def check(root: Path) -> list[str]:
    root = root.resolve()
    failures: list[str] = []
    for name in REQUIRED_FILES:
        path = root / name
        if path.is_symlink() or not path.is_file():
            failures.append(f"required regular file missing: {name}")
    license_path = root / "LICENSE"
    if license_path.is_file():
        license_text = license_path.read_text(encoding="utf-8", errors="replace")
        if not all(marker in license_text for marker in APACHE_2_LICENSE_MARKERS):
            failures.append("LICENSE is not recognized as Apache-2.0")

    for path in _iter_paths(root):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            failures.append(f"symlink forbidden: {rel}")
            continue
        if not path.is_file() or path.suffix.lower() in BINARY_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            failures.append(f"non-UTF-8 file is not allowlisted as binary: {rel}")
            continue
        for literal in FORBIDDEN_LITERALS:
            if literal in text:
                failures.append(f"private literal in {rel}: {literal}")
        for name, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                failures.append(f"credential pattern in {rel}: {name}")
        for domain in EMAIL_RE.findall(text):
            lowered = domain.lower()
            if lowered not in {
                "example.com",
                "example.org",
                "example.invalid",
                "users.noreply.github.com",
            }:
                failures.append(f"non-example email in {rel}: *@{domain}")
        if path.suffix.lower() == ".md":
            for raw_link in MARKDOWN_LINK_RE.findall(text):
                link = raw_link.strip("<>")
                if link.startswith("#") or urlsplit(link).scheme or link.startswith("//"):
                    continue
                relative = unquote(link.split("#", 1)[0])
                target = (path.parent / relative).resolve()
                try:
                    target.relative_to(root)
                except ValueError:
                    failures.append(f"unsafe local Markdown link: {rel} -> {link}")
                    continue
                if not target.exists():
                    failures.append(f"broken local Markdown link: {rel} -> {relative}")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", type=Path)
    args = parser.parse_args(argv)
    failures = check(args.root)
    if failures:
        for failure in failures:
            print(f"PUBLIC-SURFACE FAIL: {failure}", file=sys.stderr)
        return 2
    print("PUBLIC-SURFACE PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
