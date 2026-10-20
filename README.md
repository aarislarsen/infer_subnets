# infer_subnets.py

Infer scannable subnets from a list of observed host IP addresses. Designed for pentest scoping — takes raw IPs from reconnaissance output and produces CIDR ranges suitable for broader host discovery, while respecting exclusion lists.

## How it works

1. Parses and deduplicates IPv4 addresses from input
2. Groups hosts into /24 boundaries
3. Merges adjacent /24 pairs into /23s when both halves contain observed hosts
4. Filters out any subnets overlapping with excluded CIDR ranges
5. Outputs a report or plain target list

## Usage

```bash
# Full report with subnet table
python3 infer_subnets.py hosts.txt

# Apply exclusions
python3 infer_subnets.py hosts.txt -e exclusions.txt

# Plain CIDR list (nmap -iL / masscan compatible)
python3 infer_subnets.py hosts.txt -e exclusions.txt --format plain

# Write targets to file
python3 infer_subnets.py hosts.txt -e exclusions.txt -o targets.txt

# Require 3+ hosts per /24 half before merging into /23
python3 infer_subnets.py hosts.txt --min-merge 3
```

## Input formats

**IP list** — one address per line, whitespace-tolerant. Duplicates and blank lines are ignored. Lines starting with `#` are skipped.

```
10.0.70.11
10.0.70.15
10.0.34.192
```

**Exclusion file** — one CIDR per line. Supports both joined and column-separated formats:

```
10.7.0.0/16
10.10.8.0    /24
10.164.0.0/24
```

## Options

| Flag | Description |
|---|---|
| `-e`, `--exclusions` | File of CIDR ranges to exclude |
| `-o`, `--output` | Write plain subnet list to file |
| `--min-merge N` | Minimum hosts in each /24 half to allow merging into /23 (default: 1) |
| `--format` | `full` (default) for report table, `plain` for bare CIDR list |

## Requirements

Python 3.9+ (stdlib only, no dependencies).
