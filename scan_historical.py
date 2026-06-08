"""
Historical BSC scanner — Phase 1: DB-first, Phase 2: concurrent block scan.

Strategy:
  Phase 1 — Re-check verification status of all UNVERIFIED contracts in the DB
             that have BNB balance. Some may have been verified since our last scan.
  Phase 2 — Concurrent block scanning for contract deployments in extended
             historical ranges (much further back than 500 blocks).
  Phase 3 — Run exploit pipeline on newly discovered verified contracts.

Usage:
  # Phase 1: Re-check all unverified BSC contracts with balance
  python scan_historical.py --reverify

  # Phase 2: Scan 500,000 blocks (~1 month) concurrently
  python scan_historical.py --blocks 500000

  # Phase 3: Full pipeline (reverify + scan + exploit)
  python scan_historical.py --reverify --blocks 500000 --exploit

  # Scan specific block range
  python scan_historical.py --from-block 5000000 --to-block 20000000 --exploit
"""

import asyncio
import httpx
import json
import os
import sqlite3
import sys
import subprocess
import time
import argparse
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
BSC_RPC = "https://bsc-dataseed1.binance.org"
ETHERSCAN_V2 = "https://api.etherscan.io/v2/api"
API_KEY = "47JTF3MC7RJ24NSZGTIXNT84KFBQDHWY8E"
CHECKPOINT_FILE = "scan_historical_checkpoint.json"
DB_PATH = "guardian_data.db"
BLOCK_CONCURRENCY = 20  # Parallel block fetching
VERIFY_CONCURRENCY = 10  # Parallel verification checks
MIN_BALANCE_BNB = 0.001  # Minimum balance to care about
_CREATION_FLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0


def _s(text: str) -> str:
    return text.encode('ascii', errors='replace').decode('ascii')


def _log(msg: str):
    ts = datetime.now().strftime('%H:%M:%S')
    print(f"{ts}  {_s(msg)}")


def _db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


# ---------------------------------------------------------------------------
# RPC helpers
# ---------------------------------------------------------------------------

async def rpc_call(client: httpx.AsyncClient, method: str, params: list,
                   timeout: float = 30, retries: int = 2) -> dict:
    payload = {
        "jsonrpc": "2.0", "method": method, "params": params,
        "id": int(time.time() * 1000) & 0xFFFF,
    }
    for attempt in range(retries + 1):
        try:
            resp = await client.post(BSC_RPC, json=payload, timeout=timeout)
            data = resp.json()
            if data.get("error"):
                if attempt < retries:
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue
            return data
        except Exception as e:
            if attempt < retries:
                await asyncio.sleep(0.5 * (attempt + 1))
                continue
            return {"error": str(e)}
    return {"error": "Max retries exceeded"}


# ---------------------------------------------------------------------------
# Phase 1: Re-verify existing DB contracts
# ---------------------------------------------------------------------------

async def phase1_reverify(exploit: bool = False):
    """Check DB contracts with BNB balance but unverified status.
    Some may have been verified since we last checked."""
    _log("=" * 50)
    _log("Phase 1: Re-verifying unverified BSC contracts with balance")
    _log("=" * 50)

    conn = _db_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT address, printf('%.4f', bnb_balance) as balance, name
        FROM contracts
        WHERE chain_name = 'Binance Smart Chain'
          AND verified = 0
          AND bnb_balance > 0.001
        ORDER BY bnb_balance DESC
        LIMIT 200
    """)
    candidates = cur.fetchall()
    conn.close()

    _log(f"Found {len(candidates)} unverified contracts with BNB balance")

    if not candidates:
        _log("No candidates for re-verification.")
        return []

    sem = asyncio.Semaphore(VERIFY_CONCURRENCY)
    new_verified = []

    async def check_one(row) -> dict | None:
        async with sem:
            async with httpx.AsyncClient(timeout=15) as c:
                params = {
                    "chainid": "56", "module": "contract",
                    "action": "getsourcecode",
                    "address": row["address"], "apikey": API_KEY,
                }
                try:
                    resp = await c.get(ETHERSCAN_V2, params=params)
                    data = resp.json()
                    if data.get("status") == "1" and data.get("result"):
                        result = data["result"][0]
                        name = result.get("ContractName", "")
                        src = result.get("SourceCode", "")
                        if name and src and src != "0x" and src != "":
                            bal = float(row["balance"])
                            _log(f"  [NEW] {row['address'][:14]}.. "
                                 f"{name} ({bal:.2f} BNB) — NOW VERIFIED!")
                            return {
                                "address": row["address"],
                                "name": name,
                                "balance": bal,
                                "src_len": len(src),
                            }
                except Exception:
                    pass
            return None

    tasks = [check_one(row) for row in candidates]
    for i, future in enumerate(asyncio.as_completed(tasks)):
        result = await future
        if result:
            new_verified.append(result)
            # Update DB
            conn = _db_conn()
            conn.execute(
                "UPDATE contracts SET verified=1, name=?, source_length=? "
                "WHERE address=? AND chain_name='Binance Smart Chain'",
                (result["name"], result["src_len"], result["address"])
            )
            conn.commit()
            conn.close()
        if (i + 1) % 20 == 0:
            _log(f"  Progress: {i+1}/{len(candidates)} checked")

    _log(f"\nPhase 1 complete: {len(new_verified)} newly verified contracts")
    if new_verified:
        _log("New verified contracts:")
        for c in new_verified:
            _log(f"  {c['address']} {c['name']:25s} {c['balance']:.2f} BNB")

    return new_verified


# ---------------------------------------------------------------------------
# Phase 2: Concurrent historical block scanning
# ---------------------------------------------------------------------------

async def phase2_scan_blocks(from_block: int, to_block: int, exploit: bool = False) -> list[dict]:
    """Scan a range of blocks for contract deployments using CONCURRENT
    RPC calls. Much faster than sequential scanning.

    Returns list of newly discovered verified contracts with balance.
    """
    _log("=" * 50)
    total_blocks = to_block - from_block + 1
    _log(f"Phase 2: Scanning {total_blocks:,} blocks (#{from_block:,} -> #{to_block:,})")
    _log(f"  Concurrency: {BLOCK_CONCURRENCY} parallel requests")
    _log("=" * 50)

    sem_blocks = asyncio.Semaphore(BLOCK_CONCURRENCY)
    sem_verify = asyncio.Semaphore(VERIFY_CONCURRENCY)
    block_queue = list(range(from_block, to_block + 1))
    new_discovered = []
    stats = {"scanned": 0, "deployments": 0, "checked": 0}

    async def check_block(client: httpx.AsyncClient, block_num: int):
        async with sem_blocks:
            data = await rpc_call(
                client, "eth_getBlockByNumber", [hex(block_num), True]
            )
        if data.get("error") or "result" not in data or data["result"] is None:
            return None

        block = data["result"]
        txs = block.get("transactions", [])
        stats["scanned"] += 1

        # Find contract creation txs
        deploy_txs = [tx for tx in txs if tx.get("to") is None]
        if not deploy_txs:
            return None

        results = []
        for tx in deploy_txs:
            receipt_data = await rpc_call(
                client, "eth_getTransactionReceipt", [tx["hash"]]
            )
            if receipt_data.get("error") or "result" not in receipt_data:
                continue
            receipt = receipt_data["result"]
            contract_addr = receipt.get("contractAddress")
            if not contract_addr or contract_addr == "0x":
                continue
            stats["deployments"] += 1
            results.append({
                "address": contract_addr,
                "block": block_num,
                "deployer": tx.get("from", "?"),
                "timestamp": block.get("timestamp", "0"),
            })

        return results

    async def verify_and_record(contract: dict):
        async with sem_verify:
            # Check if already in DB
            conn = _db_conn()
            cur = conn.cursor()
            cur.execute(
                "SELECT address, verified FROM contracts WHERE address=? "
                "AND chain_name='Binance Smart Chain'",
                (contract["address"],)
            )
            existing = cur.fetchone()
            conn.close()

            if existing:
                return None  # Already known

            async with httpx.AsyncClient(timeout=15) as c:
                # Check balance
                bal_data = await rpc_call(c, "eth_getBalance",
                                          [contract["address"], "latest"])
                if bal_data.get("error") or "result" not in bal_data:
                    return None
                try:
                    bal = int(bal_data["result"], 16) / 1e18
                except (ValueError, TypeError):
                    return None

                if bal < MIN_BALANCE_BNB:
                    return None

                # Check verification
                params = {
                    "chainid": "56", "module": "contract",
                    "action": "getsourcecode",
                    "address": contract["address"], "apikey": API_KEY,
                }
                try:
                    resp = await c.get(ETHERSCAN_V2, params=params)
                    data = resp.json()
                    if data.get("status") == "1" and data.get("result"):
                        result = data["result"][0]
                        name = result.get("ContractName", "")
                        src = result.get("SourceCode", "")
                        if name and src and src != "0x" and src != "":
                            stats["checked"] += 1
                            return {
                                "address": contract["address"],
                                "name": name,
                                "balance": bal,
                                "src_len": len(src),
                                "block": contract["block"],
                            }
                except Exception:
                    pass
            return None

    # Process blocks concurrently
    async with httpx.AsyncClient(timeout=30) as client:
        # Split into batches of 1000 for progress reporting
        batch_size = 1000
        for batch_start in range(0, len(block_queue), batch_size):
            batch = block_queue[batch_start:batch_start + batch_size]

            # Fetch blocks concurrently
            block_tasks = [check_block(client, bn) for bn in batch]
            block_results = await asyncio.gather(*block_tasks)

            # Collect all contract deployments
            all_deployments = []
            for result in block_results:
                if result:
                    all_deployments.extend(result)

            if all_deployments:
                _log(f"  Found {len(all_deployments)} contract(s) in batch, "
                     f"checking balances + verification...")

                # Verify concurrently
                verify_tasks = [verify_and_record(c) for c in all_deployments]
                verify_results = await asyncio.gather(*verify_tasks)

                for c in verify_results:
                    if c:
                        new_discovered.append(c)
                        _log(f"  [RICH] {c['address'][:14]}.. {c['name']:25s} "
                             f"{c['balance']:.2f} BNB (block #{c['block']:,})")

            # Progress
            pct = min(100, (batch_start + batch_size) * 100 // len(block_queue))
            scanned = stats["scanned"]
            _log(f"  Progress: {scanned:,}/{total_blocks:,} blocks "
                 f"({pct}%) — {len(new_discovered)} new rich contracts")

    _log(f"\nPhase 2 complete:")
    _log(f"  Blocks scanned: {stats['scanned']:,}")
    _log(f"  Deployments found: {stats['deployments']}")
    _log(f"  New verified + balance: {len(new_discovered)}")

    if new_discovered:
        _log(f"\nNew contracts to exploit:")
        for c in new_discovered:
            _log(f"  {c['address']} {c['name']:25s} {c['balance']:.2f} BNB")

    return new_discovered


# ---------------------------------------------------------------------------
# Phase 3: Run exploit pipeline
# ---------------------------------------------------------------------------

async def phase3_exploit(contracts: list[dict]):
    """Run exploit pipeline on discovered contracts."""
    if not contracts:
        _log("Phase 3: No contracts to exploit.")
        return

    _log("=" * 50)
    _log("Phase 3: Running exploit pipeline")
    _log("=" * 50)

    for c in contracts:
        _log(f"\n  [{c['name']}] {c['address'][:14]}.. ({c['balance']:.2f} BNB)")
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "exploit_pipeline.py",
                "--address", c["address"],
                "--chain", "bsc",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                creationflags=_CREATION_FLAGS,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=120
            )
            # Print last few lines of output
            out = stdout.decode(errors='replace')
            for line in out.split('\n')[-5:]:
                if line.strip():
                    _log(f"    {line.strip()}")
        except asyncio.TimeoutError:
            _log(f"    TIMEOUT (120s)")
        except Exception as e:
            _log(f"    ERROR: {e}")


# ---------------------------------------------------------------------------
# DB insertion
# ---------------------------------------------------------------------------

def insert_to_db(contracts: list[dict], chain_name: str = "Binance Smart Chain",
                 chain_id: int = 56):
    """Insert discovered contracts into guardian_data.db."""
    if not contracts:
        return

    conn = _db_conn()
    inserted = 0
    for c in contracts:
        try:
            conn.execute("""
                INSERT OR IGNORE INTO contracts
                (address, chain_id, chain_name, name, verified, source_length,
                 bnb_balance, scanned_at)
                VALUES (?, ?, ?, ?, 1, ?, ?, ?)
            """, (
                c["address"], chain_id, chain_name,
                c.get("name", "Unknown"), c.get("src_len", 0),
                c["balance"],
                datetime.now(timezone.utc).isoformat(),
            ))
            inserted += 1
        except Exception as e:
            _log(f"  DB error for {c['address'][:14]}..: {e}")

    conn.commit()
    conn.close()
    _log(f"Inserted {inserted}/{len(contracts)} contracts into DB")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main():
    parser = argparse.ArgumentParser(
        description="Historical BSC scanner — finds verified contracts we missed"
    )
    parser.add_argument("--reverify", action="store_true",
                        help="Phase 1: Re-check unverified contracts in DB")
    parser.add_argument("--blocks", type=int, default=None,
                        help="Phase 2: Number of recent blocks to scan (e.g., 500000)")
    parser.add_argument("--from-block", type=int, default=None,
                        help="Phase 2: Starting block (overrides --blocks)")
    parser.add_argument("--to-block", type=int, default=None,
                        help="Phase 2: Ending block")
    parser.add_argument("--exploit", action="store_true",
                        help="Phase 3: Run exploit pipeline on discovered contracts")
    args = parser.parse_args()

    _log("Historical BSC Scanner")
    _log(f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    _log("")

    all_new = []

    # Phase 1: Re-verify existing DB contracts
    if args.reverify:
        new_verified = await phase1_reverify(exploit=args.exploit)
        all_new.extend(new_verified)
        if args.exploit:
            await phase3_exploit(new_verified)

    # Phase 2: Historical block scanning
    if args.from_block is not None or args.blocks is not None:
        # Get latest block
        async with httpx.AsyncClient(timeout=15) as c:
            data = await rpc_call(c, "eth_blockNumber", [])
            if data.get("error"):
                _log(f"ERROR: Cannot get latest block: {data['error']}")
                sys.exit(1)
            latest = int(data["result"], 16)

        if args.from_block is not None:
            from_block = args.from_block
            to_block = args.to_block or latest
        else:
            n = args.blocks or 100_000
            from_block = max(latest - n, 0)
            to_block = latest

        _log(f"Latest BSC block: #{latest:,}")
        new_contracts = await phase2_scan_blocks(from_block, to_block, args.exploit)
        all_new.extend(new_contracts)

        # Insert into DB
        if new_contracts:
            insert_to_db(new_contracts)

        # Phase 3: Exploit
        if args.exploit and new_contracts:
            await phase3_exploit(new_contracts)

    # Summary
    _log("")
    _log("=" * 50)
    _log("SUMMARY")
    _log("=" * 50)
    _log(f"Total new contracts: {len(all_new)}")
    if all_new:
        total_balance = sum(c["balance"] for c in all_new)
        _log(f"Total BNB: {total_balance:.2f}")
        _log("")
        _log("Quick exploit command:")
        _log("  python hardhat_fork_tester.py --batch")

    if not args.reverify and args.from_block is None and args.blocks is None:
        _log("No mode selected. Use --reverify and/or --blocks.")
        parser.print_help()


if __name__ == "__main__":
    asyncio.run(main())
