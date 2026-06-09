#!/usr/bin/env python3
"""
mine_abi_functions.py — Mine toutes les fonctions ABI des contrats vérifiés
===========================================================================
Lit les contrats vérifiés depuis guardian_data.db, fetch leur ABI via Etherscan V2,
extrait toutes les signatures de fonctions non-view/non-pure, et les classe
par fréquence. Génère un JSON exploitable pour l'exploit generator.

Usage:
    python mine_abi_functions.py                    # Tous les contrats vérifiés
    python mine_abi_functions.py --limit 50          # Limiter à 50 contrats
    python mine_abi_functions.py --min-count 5       # Filtrer par fréquence minimale
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify import SourceCodeVerifier

DB_PATH = "guardian_data.db"
OUTPUT_PATH = "findings/abi_functions_mined.json"
ETHERSCAN_V2_API = "https://api.etherscan.io/v2/api"


async def main():
    import argparse
    parser = argparse.ArgumentParser(description="Mine ABI functions from verified contracts")
    parser.add_argument("--limit", type=int, default=0, help="Max contracts to process (0 = all)")
    parser.add_argument("--min-count", type=int, default=1, help="Minimum frequency to include")
    parser.add_argument("--api-key", default=os.environ.get("ETHERSCAN_API_KEY", ""))
    args = parser.parse_args()

    # Read API key from config if not provided
    api_key = args.api_key
    if not api_key:
        try:
            import yaml
            with open("config.yaml") as f:
                cfg = yaml.safe_load(f)
            api_key = cfg.get("global", {}).get("explorer_api_key", "")
        except Exception:
            pass

    if not api_key:
        print("[ERROR] No API key. Set ETHERSCAN_API_KEY env var or add to config.yaml")
        sys.exit(1)

    # Load contracts from DB
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), DB_PATH)
    if not os.path.exists(db_path):
        print(f"[ERROR] Database not found: {db_path}")
        sys.exit(1)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.execute(
        "SELECT address, chain_id, chain_name, name, bnb_balance "
        "FROM contracts WHERE verified = 1 ORDER BY bnb_balance DESC"
    )
    contracts = cur.fetchall()
    conn.close()

    if args.limit > 0:
        contracts = contracts[:args.limit]

    total = len(contracts)
    print(f"[MINE] {total} verified contracts to process")
    print(f"[MINE] API key: {api_key[:12]}...")
    print()

    verifier = SourceCodeVerifier(api_key=api_key)

    # Collect all function signatures
    all_functions: Counter = Counter()
    skipped_no_abi = 0
    skipped_no_contract = 0
    processed = 0

    for idx, row in enumerate(contracts):
        addr = row["address"]
        cid = row["chain_id"]
        name = row["name"] or "Unknown"
        bal = row["bnb_balance"] or 0

        print(f"  [{idx+1}/{total}] {addr[:14]}.. {name[:25]:25s} bal={bal:.4f}", end="")

        try:
            info = await verifier.get_contract_info(addr, cid)
            if not info:
                print("  [NO CONTRACT]")
                skipped_no_contract += 1
                continue

            abi_raw = info.get("ABI", "")
            if not abi_raw or abi_raw == "Contract source code not verified":
                print("  [NO ABI]")
                skipped_no_abi += 1
                continue

            abi = json.loads(abi_raw) if isinstance(abi_raw, str) else abi_raw
            func_count = 0
            for entry in abi:
                if entry.get("type") != "function":
                    continue
                fname = entry.get("name", "")
                if not fname:
                    continue
                state_mut = entry.get("stateMutability", "nonpayable")
                # Skip view/pure — can't drain funds
                if state_mut in ("view", "pure"):
                    continue
                # Build normalized signature: name(paramType1,paramType2,...)
                inputs = entry.get("inputs", [])
                param_types = [inp.get("type", "uint256") for inp in inputs]
                sig = f"{fname}({','.join(param_types)})"
                all_functions[sig] += 1
                func_count += 1

            print(f"  {func_count} functions")
            processed += 1

        except Exception as e:
            print(f"  [ERROR] {e}")
            continue

    await verifier.close()

    # Filter by minimum count
    filtered = [(sig, cnt) for sig, cnt in all_functions.most_common() if cnt >= args.min_count]

    # Stats
    total_unique = len(all_functions)
    total_filtered = len(filtered)

    # Categorize: fund-draining vs other
    drain_keywords = [
        "withdraw", "claim", "transfer", "sweep", "collect", "redeem",
        "unstake", "harvest", "emergency", "recover", "release", "drain",
        "burn", "skim", "sync", "remove", "liquidate", "repay", "borrow",
    ]
    own_keywords = [
        "initialize", "setup", "renounce", "grant", "setowner", "setadmin",
        "owner", "admin", "role",
    ]

    drain_funcs = []
    own_funcs = []
    other_funcs = []

    for sig, cnt in filtered:
        name = sig.split("(")[0].lower()
        if any(kw in name for kw in drain_keywords):
            drain_funcs.append((sig, cnt))
        elif any(kw in name for kw in own_keywords):
            own_funcs.append((sig, cnt))
        else:
            other_funcs.append((sig, cnt))

    # Build report
    report = {
        "mined_at": datetime.now(timezone.utc).isoformat(),
        "stats": {
            "contracts_total": total,
            "contracts_processed": processed,
            "skipped_no_abi": skipped_no_abi,
            "skipped_no_contract": skipped_no_contract,
            "total_unique_functions": total_unique,
            "filtered_by_min_count": total_filtered,
        },
        "drain_functions": [{"signature": sig, "count": cnt} for sig, cnt in drain_funcs],
        "ownership_functions": [{"signature": sig, "count": cnt} for sig, cnt in own_funcs],
        "other_functions": [{"signature": sig, "count": cnt} for sig, cnt in other_funcs],
        # The full ranked list (for the exploit generator)
        "ranked_functions": [{"signature": sig, "count": cnt} for sig, cnt in filtered],
    }

    # Save
    os.makedirs(os.path.dirname(os.path.join(os.path.dirname(os.path.abspath(__file__)), OUTPUT_PATH)), exist_ok=True)
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), OUTPUT_PATH)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    # Print summary
    print()
    print("=" * 60)
    print("  ABI FUNCTION MINING — RESULTS")
    print("=" * 60)
    print(f"  Contracts processed : {processed}/{total}")
    print(f"  Skipped (no ABI)    : {skipped_no_abi}")
    print(f"  Skipped (no contract): {skipped_no_contract}")
    print(f"  Total unique funcs  : {total_unique}")
    print(f"  After min_count={args.min_count} : {total_filtered}")
    print()
    print(f"  Fund-draining funcs : {len(drain_funcs)}")
    print(f"  Ownership funcs     : {len(own_funcs)}")
    print(f"  Other funcs         : {len(other_funcs)}")
    print()
    print("  Top 30 fund-draining functions:")
    for sig, cnt in drain_funcs[:30]:
        print(f"    {cnt:4d}x  {sig}")
    print()
    print(f"  Report saved: {output_path}")


if __name__ == "__main__":
    asyncio.run(main())
