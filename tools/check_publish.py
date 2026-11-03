#!/usr/bin/env python3
"""Check versioned files without echoing potentially sensitive matches."""
import ipaddress
import re
import subprocess
import sys
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    listing = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True)
    paths = [name for name in listing.stdout.decode("utf-8").split("\0") if name]
    failures = []
    for name in paths:
        path = root / name
        basename = path.name.lower()
        if (basename.startswith(("credentials", "server")) and basename != "credentials.example.json"
                or basename in {"latest.json", "known_hosts"}
                or basename.startswith(("verification", "manifest"))
                or path.suffix.lower() in {".pem", ".key", ".zip", ".log"}
                or any(part in {"private", "work", "logs", "backups"} for part in Path(name).parts)):
            failures.append((name, "private file path"))
            continue
        content = path.read_text(encoding="utf-8-sig")
        patterns = {
            "JWT": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            "GitHub credential": r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})",
            "private key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            "local personal path": r"[A-Za-z]:[\\/](?:Users|Documents and Settings)[\\/](?!private(?:[\\/]|$))",
            "numeric device identifier": r"(?i)device_id[\"']?\s*:\s*[\"']\d{12,}[\"']",
        }
        for label, pattern in patterns.items():
            if re.search(pattern, content):
                failures.append((name, label))
        for address in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content):
            try:
                if ipaddress.ip_address(address).is_global:
                    failures.append((name, "public IPv4 address"))
                    break
            except ValueError:
                pass
    for name, category in failures:
        sys.stderr.write(f"FAIL: {name}: {category}\n")
    if failures:
        return 1
    sys.stdout.write(f"Checked {len(paths)} tracked files; no matching sensitive patterns.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
