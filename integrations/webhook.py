#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations

import argparse
import sys
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser(
        description="POST approvewarden JSON findings to a webhook URL."
    )
    ap.add_argument("--url", required=True, help="Destination URL (https://...)")
    ap.add_argument("--header", action="append", default=[], help="Key: Value")
    args = ap.parse_args()

    # Basic URL sanity check before reading stdin.
    if not args.url.startswith(("http://", "https://")):
        print(
            f"error: --url must start with http:// or https://, got: {args.url!r}",
            file=sys.stderr,
        )
        return 1

    payload = sys.stdin.read().encode("utf-8")
    if not payload.strip():
        print("error: stdin is empty — nothing to forward", file=sys.stderr)
        return 1

    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        k, _, v = h.partition(":")
        if not k.strip():
            print(f"error: malformed --header value: {h!r}", file=sys.stderr)
            return 1
        req.add_header(k.strip(), v.strip())

    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except Exception as e:
        print(f"webhook error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
