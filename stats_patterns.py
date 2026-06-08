#!/usr/bin/env python3
"""Stats on all 34 vulnerability patterns across verified contracts.

Usage:
    python stats_patterns.py [--limit 500] [--chain 56]
"""

import os
import sys
import asyncio
import json
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sqlite3
import yaml
from analysis.vulnerability_scanner import analyze_contract
from verify import SourceCodeVerifier

DB_PATH = "guardian_data.db"
CONFIG_PATH = "config.yaml"


def get_explorer_api_key():
    """Read Etherscan API key from config.yaml."""
    try:
        with open(CONFIG_PATH) as f:
            cfg = yaml.safe_load(f)
        return cfg.get("global", {}).get("explorer_api_key", "")
    except Exception:
        return ""

def get_contracts(limit=500, chain_id=None):
    """Get verified contracts from DB."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    query = """
        SELECT address, chain_id, chain_name, name, bnb_balance
        FROM contracts
        WHERE verified = 1
    """
    params = []
    if chain_id:
        query += " AND chain_id = ?"
        params.append(chain_id)

    query += " ORDER BY bnb_balance DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


async def run_stats(limit=500, chain_id=None):
    print(f"Scanning up to {limit} verified contracts...")
    print()

    contracts = get_contracts(limit, chain_id)
    print(f"Found {len(contracts)} verified contracts in DB")
    print()

    api_key = get_explorer_api_key()
    if not api_key:
        print("  [WARN] No explorer_api_key in config.yaml — source fetch will fail")
    verifier = SourceCodeVerifier(api_key=api_key)

    # Per-pattern stats
    pattern_counts = Counter()          # pattern id -> count
    pattern_severity = {}               # pattern id -> severity
    pattern_names = {}                  # pattern id -> name
    per_contract_counts = []            # number of findings per contract
    errors = 0
    no_source = 0
    skips = 0

    # All 34 pattern IDs and their expected severities
    all_pattern_ids = [
        "reentrancy", "reentrancy-no-cei", "selfdestruct", "tx-origin",
        "delegatecall", "unprotected-withdraw", "unprotected-init",
        "unchecked-call", "integer-overflow", "gas-loop", "arbitrary-from",
        "flash-loan", "oracle-manipulation", "missing-deadline",
        "zero-slippage", "force-feed-eth", "erc20-return-unchecked",
        "signature-replay", "rounding-error", "storage-collision",
        "timestamp-manipulation", "ownership-renounce",
        "uups-unprotected", "missing-disable-init", "single-step-ownership",
        "flash-loan-no-fee", "missing-pause",
        "upgradeable-field-init", "custom-auth", "missing-reinitializer",
        "unsafe-immutable-upgradeable",
        "arbitrary-jump", "arbitrary-storage-write", "multiple-external-calls",
        "transaction-order-dep", "predictable-var", "strict-balance-equality",
    ]

    pad = max(len(c["address"]) for c in contracts) if contracts else 42
    pad = min(pad, 42)

    for idx, c in enumerate(contracts):
        addr = c["address"]
        cid = c["chain_id"]
        name = c["name"] or "?"
        bal = c["bnb_balance"] or 0

        print(f"  [{idx+1}/{len(contracts)}] {addr[:42]:{pad}s} chain={cid} bal={bal:.4f}", end="")

        try:
            source = await verifier.get_source_code(addr, cid)
        except Exception as e:
            print(f"  [ERR] {e}")
            errors += 1
            continue

        if not source:
            print(f"  [NO SOURCE]")
            no_source += 1
            continue

        findings = analyze_contract(source)
        per_contract_counts.append(len(findings))

        # Track per-pattern
        for f in findings:
            pattern_counts[f.id] += 1
            if f.id not in pattern_severity:
                pattern_severity[f.id] = f.severity
            if f.id not in pattern_names:
                pattern_names[f.id] = f.name

        print(f"  {len(findings)} findings")

    await verifier.close()

    # --- REPORT ---
    print()
    print("=" * 80)
    print("  PATTERN STATISTICS REPORT — 34 Vulnerability Patterns")
    print("=" * 80)
    print()

    # Summary
    total_contracts = len(contracts)
    scanned = total_contracts - errors - no_source
    print(f"  Contracts requested : {total_contracts}")
    print(f"  Source fetched      : {scanned}")
    print(f"  No source available : {no_source}")
    print(f"  Errors              : {errors}")
    print(f"  Total findings      : {sum(per_contract_counts)}")
    print(f"  Avg findings/contract: {sum(per_contract_counts)/max(scanned,1):.2f}")
    print(f"  Contracts with 0 findings: {per_contract_counts.count(0)}")
    print()

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    # Per-pattern table
    print(f"  {'ID':<34s} {'Severity':<10s} {'Count':<7s} {'% of contracts':<15s} {'New Mythril':<12s}")
    print(f"  {'-'*34} {'-'*10} {'-'*7} {'-'*15} {'-'*12}")

    # Sort: by severity then count desc
    sorted_patterns = sorted(pattern_counts.items(),
        key=lambda x: (severity_order.get(pattern_severity.get(x[0], "INFO"), 99), -x[1]))

    is_mythril = {"arbitrary-jump", "arbitrary-storage-write", "multiple-external-calls",
                  "transaction-order-dep", "predictable-var", "strict-balance-equality"}

    for pid, cnt in sorted_patterns:
        sev = pattern_severity.get(pid, "?")
        name = pattern_names.get(pid, pid)[:32]
        pct = f"{cnt/scanned*100:.1f}%" if scanned > 0 else "N/A"
        mythril_flag = "  [NEW]" if pid in is_mythril else ""
        print(f"  {name:<34s} {sev:<10s} {cnt:<7d} {pct:<15s} {mythril_flag:<12s}")

    print()

    # Missing patterns (not found in any contract)
    found_ids = set(pattern_counts.keys())
    missing = [pid for pid in all_pattern_ids if pid not in found_ids]
    if missing:
        print(f"  Patterns with 0 findings (not detected in any contract):")
        for pid in missing:
            is_new = "  [NEW]" if pid in is_mythril else ""
            print(f"    - {pid}{is_new}")

    print()
    print("=" * 80)

    # Save to JSON for reference
    report = {
        "total_contracts": total_contracts,
        "scanned": scanned,
        "no_source": no_source,
        "errors": errors,
        "total_findings": sum(per_contract_counts),
        "avg_findings_per_contract": round(sum(per_contract_counts)/max(scanned,1), 2),
        "contracts_with_zero_findings": per_contract_counts.count(0),
        "patterns": {pid: {"count": cnt, "severity": pattern_severity.get(pid, "?"),
                          "name": pattern_names.get(pid, pid),
                          "pct": round(cnt/scanned*100, 1) if scanned > 0 else 0}
                    for pid, cnt in sorted_patterns},
        "missing_patterns": missing,
    }

    json_path = "findings/pattern_stats.json"
    os.makedirs(os.path.dirname(json_path), exist_ok=True)
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"  Report saved to: {json_path}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=500, help="Number of contracts to scan")
    parser.add_argument("--chain", type=int, default=None, help="Filter by chain ID")
    args = parser.parse_args()

    asyncio.run(run_stats(limit=args.limit, chain_id=args.chain))
