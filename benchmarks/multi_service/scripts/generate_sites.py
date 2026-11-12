#!/usr/bin/env python3
"""Generate 1/100/1000 virtual-host site files from the committed template.

Standalone use:
  python3 scripts/generate_sites.py --count 1000 --out /tmp/sites \
    --dynamic-upstream-port 18100 --static-upstream-port 18101

The driver uses the same substitution rules in-process.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re


def domain_for(index: int) -> str:
    return f"bench-{index:04d}.local"


def render(
    template: str,
    *,
    index: int,
    count: int,
    dynamic_port: int,
    static_port: int,
    attack_enabled: bool,
    attack_action: str,
    paranoia_level: int,
) -> str:
    replacements = {
        "@@SITE_COUNT@@": str(count),
        "@@DOMAIN@@": domain_for(index),
        "@@DYNAMIC_UPSTREAM_PORT@@": str(dynamic_port),
        "@@STATIC_UPSTREAM_PORT@@": str(static_port),
        "@@ATTACK_ENABLED@@": "true" if attack_enabled else "false",
        "@@ATTACK_ACTION@@": attack_action,
        "@@PARANOIA_LEVEL@@": str(paranoia_level),
    }
    text = template
    for key, value in replacements.items():
        text = text.replace(key, value)
    leftovers = sorted(set(re.findall(r"@@[A-Z0-9_]+@@", text)))
    if leftovers:
        raise SystemExit(f"unsubstituted placeholders: {leftovers}")
    return text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument(
        "--template",
        default=str(
            pathlib.Path(__file__).resolve().parent.parent
            / "config"
            / "templates"
            / "site.toml.tpl"
        ),
    )
    parser.add_argument("--dynamic-upstream-port", type=int, required=True)
    parser.add_argument("--static-upstream-port", type=int, required=True)
    parser.add_argument("--attack-enabled", choices=("on", "off"), default="on")
    parser.add_argument("--attack-action", default="log")
    parser.add_argument("--paranoia-level", type=int, default=2)
    parser.add_argument("--manifest", action="store_true")
    args = parser.parse_args()

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    template = pathlib.Path(args.template).read_text()

    domains: list[str] = []
    for index in range(args.count):
        domain = domain_for(index)
        text = render(
            template,
            index=index,
            count=args.count,
            dynamic_port=args.dynamic_upstream_port,
            static_port=args.static_upstream_port,
            attack_enabled=args.attack_enabled == "on",
            attack_action=args.attack_action,
            paranoia_level=args.paranoia_level,
        )
        path = out / f"site-{index:05d}-{domain}.toml"
        path.write_text(text)
        domains.append(domain)

    if args.manifest:
        print(json.dumps({"count": args.count, "domains": domains}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
