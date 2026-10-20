#!/usr/bin/env python3
"""
Infer scannable subnets from a list of observed IP addresses.

Reads a file of IP addresses (one per line, whitespace-tolerant, dupes OK),
groups them into /24 boundaries, merges adjacent /24s into /23s where both
halves are populated, and optionally excludes subnets that overlap with
forbidden CIDR ranges.

Usage:
    python3 infer_subnets.py hosts.txt
    python3 infer_subnets.py hosts.txt -e exclusions.txt
    python3 infer_subnets.py hosts.txt -e exclusions.txt -o targets.txt
    python3 infer_subnets.py hosts.txt --min-merge 1 --format nmap

Exclusion file format (one per line, CIDR or "subnet CIDR" columns):
    10.7.0.0/16
    10.10.8.0    /24
    10.164.0.0/24
"""

import argparse
import ipaddress
import sys
from collections import defaultdict


def parse_ips(filepath: str) -> set[ipaddress.IPv4Address]:
    """Extract valid IPv4 addresses from a file, one per line."""
    ips = set()
    with open(filepath) as f:
        for lineno, line in enumerate(f, 1):
            token = line.strip()
            if not token or token.startswith("#"):
                continue
            try:
                ips.add(ipaddress.IPv4Address(token))
            except ValueError:
                print(f"[warn] line {lineno}: skipping invalid IP '{token}'", file=sys.stderr)
    return ips


def parse_exclusions(filepath: str) -> list[ipaddress.IPv4Network]:
    """Parse exclusion CIDRs. Accepts 'x.x.x.x/nn' or 'x.x.x.x  /nn' (split columns)."""
    nets = []
    with open(filepath) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Handle tab/space-separated "10.0.0.0  /24" format
            parts = line.split()
            if len(parts) == 2 and parts[1].startswith("/"):
                cidr = parts[0] + parts[1]
            elif len(parts) == 1:
                cidr = parts[0]
            else:
                print(f"[warn] exclusions line {lineno}: skipping '{line}'", file=sys.stderr)
                continue
            try:
                nets.append(ipaddress.IPv4Network(cidr, strict=False))
            except ValueError:
                print(f"[warn] exclusions line {lineno}: invalid CIDR '{cidr}'", file=sys.stderr)
    return nets


def group_by_24(ips: set[ipaddress.IPv4Address]) -> dict[ipaddress.IPv4Network, list[ipaddress.IPv4Address]]:
    """Group IPs into their containing /24 networks."""
    groups = defaultdict(list)
    for ip in ips:
        net24 = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        groups[net24].append(ip)
    for v in groups.values():
        v.sort()
    return dict(groups)


def merge_adjacent(
    groups: dict[ipaddress.IPv4Network, list[ipaddress.IPv4Address]],
    min_merge: int = 1,
) -> dict[ipaddress.IPv4Network, list[ipaddress.IPv4Address]]:
    """
    Merge adjacent /24 pairs into /23s when both halves have >= min_merge hosts.
    Returns a dict of subnet -> observed IPs.
    """
    merged = {}
    consumed = set()
    sorted_nets = sorted(groups.keys(), key=lambda n: int(n.network_address))

    for net in sorted_nets:
        if net in consumed:
            continue

        # Compute the /23 supernet and find the sibling /24
        net23 = ipaddress.IPv4Network(f"{net.network_address}/23", strict=False)
        sibling_addr = (
            net23.network_address + 256
            if net.network_address == net23.network_address
            else net23.network_address
        )
        sibling = ipaddress.IPv4Network(f"{ipaddress.IPv4Address(sibling_addr)}/24")

        if sibling in groups and len(groups[net]) >= min_merge and len(groups[sibling]) >= min_merge:
            merged[net23] = sorted(groups[net] + groups[sibling])
            consumed.add(net)
            consumed.add(sibling)
        else:
            merged[net] = groups[net]
            consumed.add(net)

    return merged


def filter_excluded(
    subnets: dict[ipaddress.IPv4Network, list[ipaddress.IPv4Address]],
    exclusions: list[ipaddress.IPv4Network],
) -> tuple[dict, dict]:
    """Split subnets into safe and excluded based on CIDR overlap."""
    safe = {}
    excluded = {}
    for net, ips in subnets.items():
        overlapping = [e for e in exclusions if net.overlaps(e)]
        if overlapping:
            excluded[net] = (ips, overlapping)
        else:
            safe[net] = ips
    return safe, excluded


def print_report(
    safe: dict[ipaddress.IPv4Network, list[ipaddress.IPv4Address]],
    excluded: dict,
    fmt: str = "full",
    outfile=None,
):
    """Print results to stdout and optionally write plain list to outfile."""
    out = sys.stdout

    sorted_safe = sorted(safe.keys(), key=lambda n: int(n.network_address))
    sorted_excl = sorted(excluded.keys(), key=lambda n: int(n.network_address))

    if fmt == "full":
        total_hosts = sum(n.num_addresses - 2 for n in sorted_safe if n.prefixlen <= 30)
        print("=" * 70, file=out)
        print("INFERRED SUBNETS FOR SCANNING", file=out)
        print("=" * 70, file=out)
        print(f"\nSafe to scan:  {len(sorted_safe)} subnets, {total_hosts} host addresses", file=out)
        print(f"Excluded:      {len(sorted_excl)} subnets (overlap with forbidden CIDRs)", file=out)

        if sorted_excl:
            print(f"\n--- EXCLUDED ---", file=out)
            for net in sorted_excl:
                ips, overlaps = excluded[net]
                for o in overlaps:
                    print(f"  {str(net):<24s} overlaps {o}", file=out)

        print(f"\n--- SAFE SUBNETS ({len(sorted_safe)}) ---", file=out)
        print(f"  {'Subnet':<24s} {'Usable hosts':<14s} {'Observed'}", file=out)
        print(f"  {'-'*54}", file=out)
        for net in sorted_safe:
            usable = net.num_addresses - 2 if net.prefixlen <= 30 else net.num_addresses
            observed = len(safe[net])
            print(f"  {str(net):<24s} {usable:<14d} {observed}", file=out)

        print(f"\n  Total scannable: {total_hosts} addresses across {len(sorted_safe)} subnets", file=out)

    # Plain list (always printed for 'plain' format, or as a second section for 'full')
    if fmt == "plain":
        for net in sorted_safe:
            print(net, file=out)
    elif fmt == "full":
        print(f"\n--- PLAIN LIST ---", file=out)
        for net in sorted_safe:
            print(f"  {net}", file=out)

    # Write to file if requested
    if outfile:
        with open(outfile, "w") as f:
            for net in sorted_safe:
                f.write(f"{net}\n")
        print(f"\n[+] Wrote {len(sorted_safe)} subnets to {outfile}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Infer scannable subnets from observed IP addresses.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("ipfile", help="File containing IP addresses (one per line)")
    parser.add_argument(
        "-e", "--exclusions",
        help="File containing CIDR ranges to exclude (one per line, supports 'addr /mask' columns)",
    )
    parser.add_argument("-o", "--output", help="Write plain subnet list to this file")
    parser.add_argument(
        "--min-merge", type=int, default=1, metavar="N",
        help="Minimum hosts in each /24 half to merge into a /23 (default: 1)",
    )
    parser.add_argument(
        "--format", choices=["full", "plain"], default="full",
        help="Output format: 'full' report or 'plain' CIDR list (default: full)",
    )
    args = parser.parse_args()

    # Parse inputs
    ips = parse_ips(args.ipfile)
    if not ips:
        print("[!] No valid IPs found.", file=sys.stderr)
        sys.exit(1)
    print(f"[+] Parsed {len(ips)} unique IPs", file=sys.stderr)

    exclusions = []
    if args.exclusions:
        exclusions = parse_exclusions(args.exclusions)
        print(f"[+] Loaded {len(exclusions)} exclusion CIDRs", file=sys.stderr)

    # Process
    groups = group_by_24(ips)
    merged = merge_adjacent(groups, min_merge=args.min_merge)
    safe, excluded = filter_excluded(merged, exclusions)

    # Output
    print_report(safe, excluded, fmt=args.format, outfile=args.output)


if __name__ == "__main__":
    main()
