#!/usr/bin/env python3
"""Convert Shadowrocket .list rules to QuantumultX .list format.

Shadowrocket rule lines look like:
    DOMAIN-SUFFIX,futu.com
    DOMAIN,api.futunn.com
    DOMAIN-KEYWORD,openaicom
    IP-CIDR,1.14.242.0/23,no-resolve

QuantumultX expects an explicit policy name appended to each rule:
    HOST-SUFFIX,futu.com,Broker
    HOST,api.futunn.com,Broker
    HOST-KEYWORD,openaicom,Broker
    IP-CIDR,1.14.242.0/23,Broker,no-resolve

The rule-type keyword mapping below was verified against the QuantumultX
official filter documentation (wiki.repcz.link/quantumultx/filter).

Usage:
    python3 convert_to_quantumultx.py                          # convert all *.list, policy = Broker
    python3 convert_to_quantumultx.py HK_Broker.list --stdout  # preview one file
    python3 convert_to_quantumultx.py HK_Broker.list --policy Broker
"""

import argparse
import sys
from pathlib import Path

# Shadowrocket rule type -> QuantumultX rule type.
# Only mappings confirmed in the QuantumultX official docs are listed here.
# Any type not in this map is passed through unchanged (see convert_line).
TYPE_MAP = {
    "DOMAIN-SUFFIX": "HOST-SUFFIX",
    "DOMAIN-KEYWORD": "HOST-KEYWORD",
    "DOMAIN": "HOST",
    "IP-CIDR": "IP-CIDR",
    "IP-CIDR6": "IP6-CIDR",  # QuantumultX uses IP6-CIDR for IPv6.
    "IP6-CIDR": "IP6-CIDR",
    "USER-AGENT": "USER-AGENT",
    "GEOIP": "GEOIP",
    "IP-ASN": "IP-ASN",
}

# Trailing options that must stay at the very end of a QuantumultX rule,
# after the policy name (e.g. no-resolve).
TRAILING_OPTIONS = {"no-resolve", "force-remote-dns", "pre-matching"}


def convert_line(line: str, policy: str) -> str:
    """Convert a single rule line. Comments and blank lines pass through unchanged."""
    stripped = line.strip()
    if not stripped or stripped.startswith(("#", ";", "//")):
        return line.rstrip("\n")

    parts = [p.strip() for p in stripped.split(",")]
    rule_type = parts[0].upper()

    if rule_type not in TYPE_MAP:
        # Unknown/unverified rule type (e.g. URL-REGEX): keep as-is so nothing
        # is silently dropped or mistranslated.
        return stripped

    qx_type = TYPE_MAP[rule_type]

    # Separate the trailing options (like no-resolve) from the rule value,
    # so the policy name can be inserted before them.
    value_parts = parts[1:]
    trailing = []
    while value_parts and value_parts[-1].lower() in TRAILING_OPTIONS:
        trailing.insert(0, value_parts.pop())

    value = ",".join(value_parts)

    result = [qx_type, value, policy]
    result.extend(trailing)
    return ",".join(result)


def convert_content(text: str, policy: str) -> str:
    lines = text.splitlines()
    converted = [convert_line(line, policy) for line in lines]
    return "\n".join(converted) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert Shadowrocket .list rules to QuantumultX format.")
    parser.add_argument("files", nargs="*", help="Specific .list files to convert. Defaults to all *.list in the current directory.")
    parser.add_argument("--policy", default="Broker", help="Policy name appended to each rule (default: Broker).")
    parser.add_argument("--stdout", action="store_true", help="Print result to stdout instead of writing an output file.")
    parser.add_argument("--out-dir", default="QuantumultX", help="Directory to write converted files into (default: QuantumultX).")
    args = parser.parse_args()

    root = Path.cwd()
    if args.files:
        targets = [Path(f) for f in args.files]
    else:
        targets = sorted(root.glob("*.list"))

    if not targets:
        print("No .list files found.", file=sys.stderr)
        return 1

    for path in targets:
        if not path.exists():
            print(f"Skip (not found): {path}", file=sys.stderr)
            continue

        text = path.read_text(encoding="utf-8")
        result = convert_content(text, args.policy)

        if args.stdout:
            print(f"===== {path.name} (policy={args.policy}) =====")
            print(result, end="")
            continue

        out_dir = root / args.out_dir
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / path.name
        out_path.write_text(result, encoding="utf-8")
        print(f"Converted {path.name} -> {out_path.relative_to(root)} (policy={args.policy})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
