#!/usr/bin/env python3
"""
One-off importer: copy the allowed users (username + SHA-256 ``pass_hash``)
from the shared credential store (``iimt-block/data/db.json``) into this
project's local ``users.json``.

The Log Parser reads only the local ``users.json`` at runtime — it never opens
the shared ``db.json``. Re-run this script whenever the shared store changes to
refresh the local copy. Keep ``users.json`` out of version control (.gitignore).

Usage:
    python import_users.py [SOURCE_DB_JSON] [-o users.json]

If SOURCE_DB_JSON is omitted, uses $LOG_PARSER_SOURCE_DB or the default
relative path ``../iimt-block/data/db.json``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

DEFAULT_SOURCE = os.path.join("..", "iimt-block", "data", "db.json")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import allowed users into users.json")
    parser.add_argument(
        "source", nargs="?",
        default=os.environ.get("LOG_PARSER_SOURCE_DB", DEFAULT_SOURCE),
        help="Path to the shared db.json (default: ../iimt-block/data/db.json)")
    parser.add_argument("-o", "--out", default="users.json", help="Output path")
    args = parser.parse_args(argv)

    try:
        with open(args.source, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: could not read {args.source}: {exc}", file=sys.stderr)
        return 1

    raw = data.get("users") if isinstance(data, dict) else None
    if not isinstance(raw, list):
        print("error: source has no 'users' array", file=sys.stderr)
        return 1

    users = []
    for entry in raw:
        if (isinstance(entry, dict)
                and isinstance(entry.get("username"), str)
                and isinstance(entry.get("pass_hash"), str)
                and entry["username"] and entry["pass_hash"]):
            users.append({"username": entry["username"], "pass_hash": entry["pass_hash"]})

    if not users:
        print("error: no valid users found in source", file=sys.stderr)
        return 1

    out = {
        "_comment": ("Local copy of allowed users imported from the shared "
                     "credential store. username + SHA-256 pass_hash only. "
                     "Do not commit real hashes."),
        "imported_from": args.source.replace(os.sep, "/"),
        "users": users,
    }
    try:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
    except OSError as exc:
        print(f"error: could not write {args.out}: {exc}", file=sys.stderr)
        return 1

    print(f"wrote {len(users)} users to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
