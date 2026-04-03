from __future__ import annotations

import argparse

from .monitor import enable


def main() -> int:
    parser = argparse.ArgumentParser(description="GuardianAI Python SDK CLI")
    parser.add_argument("--service-name", default="guardian-cli-py")
    parser.add_argument("--log-path", default="security.log")
    parser.add_argument("--mode", default="monitor", choices=["monitor", "block"])
    args = parser.parse_args()

    enable(service_name=args.service_name, log_path=args.log_path, mode=args.mode)
    print(f"GuardianAI Python SDK initialized in {args.mode} mode.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
