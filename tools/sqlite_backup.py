#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from tracehawk_api.services.database_backup import create_backup, restore_backup, verify_backup


def main() -> int:
    parser = argparse.ArgumentParser(description="Create, verify, or restore a TraceHawk SQLite backup.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    backup_parser = subparsers.add_parser("backup")
    backup_parser.add_argument("--source", type=Path, required=True)
    backup_parser.add_argument("--destination", type=Path, required=True)
    backup_parser.add_argument("--force", action="store_true")

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--backup", type=Path, required=True)

    restore_parser = subparsers.add_parser("restore")
    restore_parser.add_argument("--backup", type=Path, required=True)
    restore_parser.add_argument("--destination", type=Path, required=True)
    restore_parser.add_argument("--offline-confirmed", action="store_true")

    args = parser.parse_args()
    if args.command == "backup":
        result = create_backup(args.source, args.destination, force=args.force)
    elif args.command == "verify":
        result = verify_backup(args.backup)
    else:
        result = restore_backup(
            args.backup,
            args.destination,
            offline_confirmed=args.offline_confirmed,
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
