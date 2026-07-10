#!/usr/bin/env python3
from __future__ import annotations

import argparse
import time
from pathlib import Path

SCENARIOS = {
    "ssh-compromise": [
        "Jul 05 10:02:11 lab sshd[1201]: Failed password for admin from 198.51.100.10 port 49210 ssh2",
        "Jul 05 10:02:32 lab sshd[1205]: Failed password for admin from 198.51.100.10 port 49212 ssh2",
        "Jul 05 10:02:51 lab sshd[1211]: Failed password for admin from 198.51.100.10 port 49214 ssh2",
        "Jul 05 10:03:07 lab sshd[1216]: Failed password for admin from 198.51.100.10 port 49216 ssh2",
        "Jul 05 10:03:19 lab sshd[1221]: Failed password for admin from 198.51.100.10 port 49218 ssh2",
        "Jul 05 10:03:42 lab sshd[1228]: Failed password for admin from 198.51.100.10 port 49220 ssh2",
        "Jul 05 10:04:01 lab sshd[1233]: Failed password for admin from 198.51.100.10 port 49222 ssh2",
        "Jul 05 10:04:16 lab sshd[1239]: Failed password for admin from 198.51.100.10 port 49224 ssh2",
        "Jul 05 10:04:34 lab sshd[1244]: Failed password for admin from 198.51.100.10 port 49226 ssh2",
        "Jul 05 10:04:55 lab sshd[1250]: Failed password for admin from 198.51.100.10 port 49228 ssh2",
        "Jul 05 10:05:21 lab sshd[1261]: Accepted password for admin from 198.51.100.10 port 49230 ssh2",
        "Jul 05 10:12:20 lab sudo:   admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/sbin/useradd backupadm",
    ],
    "benign": [
        "Jul 05 14:00:00 lab sshd[2001]: Accepted password for alice from 10.0.0.10 port 51222 ssh2",
        "Jul 05 14:02:00 lab sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl status nginx",
    ],
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="ssh-compromise")
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--truncate", action="store_true")
    args = parser.parse_args()

    args.path.parent.mkdir(parents=True, exist_ok=True)
    mode = "w" if args.truncate else "a"
    with args.path.open(mode) as handle:
        for line in SCENARIOS[args.scenario]:
            handle.write(line + "\n")
            handle.flush()
            if args.delay:
                time.sleep(args.delay)

    print(f"wrote={len(SCENARIOS[args.scenario])}")
    print(f"path={args.path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
