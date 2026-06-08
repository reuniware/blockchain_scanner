#!/usr/bin/env python3
"""
Hardhat Fork Tester — Standalone exploit validation framework
=============================================================
Fetches contract source, generates and runs Hardhat fork tests
to validate whether detected vulnerabilities are actually exploitable.

Usage:
    python hardhat_fork_tester.py --address 0x... --chain ethereum
    python hardhat_fork_tester.py --address 0x... --chain bsc --rpc <URL>
    python hardhat_fork_tester.py --batch  # Test all contracts with balance > 0
"""
from __future__ import annotations

import asyncio
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from verify import SourceCodeVerifier
from analysis.vulnerability_scanner import analyze_contract, VulnerabilityFinding

# RPC URLs for forking
RPC_URLS = {
    1: "https://eth.llamarpc.com",
    56: "https://bsc-dataseed1.binance.org",
    137: "https://polygon-bor-rpc.publicnode.com",
    42161: "https://arb1.arbitrum.io/rpc",
    10: "https://mainnet.optimism.io",
    43114: "https://api.avax.network/ext/bc/C/rpc",
    8453: "https://mainnet.base.org",
    250: "https://rpc.ftm.tools",
}

# Cross-platform npx command
_NPX = "npx.cmd" if platform.system() == "Windows" else "npx"

# Prevent console windows from popping up on Windows during subprocess calls
_CREATION_FLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

CHAIN_NAMES = {
    1: "ethereum", 56: "bsc", 137: "polygon", 42161: "arbitrum",
    10: "optimism", 43114: "avalanche", 8453: "base", 250: "fantom",
}

@dataclass
class TestResult:
    address: str
    chain: str
    chain_id: int
    balance_before: float
    balance_after: float
    drained: float
    confirmed: bool
    evidence: str
    timestamp: str


class HardhatForkTester:
    """Orchestrates Hardhat fork tests for a target contract."""

    def __init__(self, api_key: str = ""):
        self.verifier = SourceCodeVerifier(api_key=api_key)
        self.exploit_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "exploit"
        )

    async def test_contract(
        self,
        address: str,
        chain_id: int = 1,
    ) -> TestResult:
        """Run full exploit test suite against a contract on a forked chain.

        Args:
            address: Contract address to test
            chain_id: EVM chain ID

        Returns:
            TestResult with balance deltas and confirmation status
        """
        chain_name = CHAIN_NAMES.get(chain_id, f"chain-{chain_id}")
        rpc_url = RPC_URLS.get(chain_id)

        print(f"\n{'=' * 60}")
        print(f"  FORK TESTER — {address[:14]}.. on {chain_name}")
        print(f"{'=' * 60}")

        if not rpc_url:
            print(f"  [FAIL] No RPC URL for chain {chain_id}")
            return TestResult(
                address=address, chain=chain_name, chain_id=chain_id,
                balance_before=0, balance_after=0, drained=0,
                confirmed=False, evidence=f"No RPC for chain {chain_id}",
                timestamp=datetime.utcnow().isoformat(),
            )

        # Step 1: Check Hardhat availability
        if not await self._check_hardhat():
            print("  [FAIL] Hardhat not available")
            return TestResult(
                address=address, chain=chain_name, chain_id=chain_id,
                balance_before=0, balance_after=0, drained=0,
                confirmed=False, evidence="Hardhat not installed",
                timestamp=datetime.utcnow().isoformat(),
            )

        # Step 2: Get current balance via RPC
        print(f"  [1/4] Checking target balance...")
        balance_before = await self._get_balance(address, rpc_url)
        print(f"        Balance: {balance_before:.6f} native tokens")

        if balance_before < 0.0001:
            print(f"  [SKIP] Balance too low ({balance_before:.6f})")
            return TestResult(
                address=address, chain=chain_name, chain_id=chain_id,
                balance_before=balance_before, balance_after=balance_before,
                drained=0, confirmed=False,
                evidence=f"Balance too low ({balance_before:.6f})",
                timestamp=datetime.utcnow().isoformat(),
            )

        # Step 3: Compile contracts
        print(f"  [2/4] Compiling exploit contracts...")
        if not await self._compile_contracts():
            print("  [FAIL] Compilation failed")
            return TestResult(
                address=address, chain=chain_name, chain_id=chain_id,
                balance_before=balance_before, balance_after=balance_before,
                drained=0, confirmed=False,
                evidence="Solidity compilation failed",
                timestamp=datetime.utcnow().isoformat(),
            )

        # Step 4: Run Hardhat fork test
        print(f"  [3/4] Running fork exploit test...")
        env = os.environ.copy()
        env["TARGET_ADDRESS"] = address
        env["CHAIN_RPC"] = rpc_url

        try:
            proc = await asyncio.create_subprocess_exec(
                _NPX, "hardhat", "run", "scripts/test_fork_exploit.js",
                "--network", "hardhat",
                cwd=self.exploit_dir,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                creationflags=_CREATION_FLAGS,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
            output = stdout.decode("utf-8", errors="replace")
        except asyncio.TimeoutError:
            output = "TIMEOUT after 180s"
            print(f"  [TIMEOUT]")

        # Step 5: Parse results
        print(f"  [4/4] Parsing results...")
        drained = 0.0
        confirmed = False
        evidence = output[-1000:] if len(output) > 1000 else output

        # Look for DRAINED indicator
        drained_match = re.search(r"DRAINED:\s*([\d.]+)\s*ETH", output)
        if drained_match:
            drained = float(drained_match.group(1))
            confirmed = True
            print(f"  [!!!] CONFIRMED: {drained} ETH drained!")
        else:
            drained_match = re.search(r"No ETH drained", output)
            if drained_match:
                print(f"  [NO] No ETH drained")
            else:
                print(f"  [UNKNOWN] See output for details")
                # Print last 20 lines
                for line in output.strip().split("\n")[-20:]:
                    if line.strip():
                        print(f"     {line.strip()[:120]}")

        # Get final balance
        balance_after = await self._get_balance(address, rpc_url)

        return TestResult(
            address=address, chain=chain_name, chain_id=chain_id,
            balance_before=balance_before,
            balance_after=balance_after or (balance_before - drained),
            drained=drained,
            confirmed=confirmed,
            evidence=evidence[:2000],
            timestamp=datetime.utcnow().isoformat(),
        )

    async def _check_hardhat(self) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                _NPX, "hardhat", "--version",
                cwd=self.exploit_dir,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                creationflags=_CREATION_FLAGS,
            )
            code = await proc.wait()
            return code == 0
        except FileNotFoundError:
            return False

    async def _get_balance(self, address: str, rpc_url: str) -> float:
        import httpx
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.post(rpc_url, json={
                    "jsonrpc": "2.0",
                    "method": "eth_getBalance",
                    "params": [address, "latest"],
                    "id": 1
                })
                result = r.json().get("result", "0x0")
                return int(result, 16) / 1e18
        except Exception:
            return 0.0

    async def _compile_contracts(self) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                _NPX, "hardhat", "compile",
                cwd=self.exploit_dir,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
                creationflags=_CREATION_FLAGS,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            return proc.returncode == 0
        except Exception:
            return False

    async def close(self):
        await self.verifier.close()


async def main():
    import argparse
    parser = argparse.ArgumentParser(description="Hardhat Fork Tester")
    parser.add_argument("--address", "-a", help="Contract address to test")
    parser.add_argument("--chain", "-c", default="ethereum",
                        help="Chain: ethereum, bsc, polygon, arbitrum")
    parser.add_argument("--batch", action="store_true",
                        help="Test all contracts with balance > 0 from DB")
    parser.add_argument("--api-key", "-k",
                        default="47JTF3MC7RJ24NSZGTIXNT84KFBQDHWY8E")
    args = parser.parse_args()

    chain_ids = {"ethereum": 1, "bsc": 56, "polygon": 137,
                 "arbitrum": 42161, "optimism": 10,
                 "avalanche": 43114, "base": 8453, "fantom": 250}

    tester = HardhatForkTester(api_key=args.api_key)

    try:
        if args.address:
            cid = chain_ids.get(args.chain, 1)
            result = await tester.test_contract(args.address, cid)
            print(f"\n{'=' * 60}")
            print(f"  RESULT: {'CONFIRMED' if result.confirmed else 'NOT EXPLOITABLE'}")
            print(f"  Drained: {result.drained:.6f} ETH")
            print(f"{'=' * 60}")
        elif args.batch:
            # Import DB and test all contracts with balance
            import sqlite3
            db_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "guardian_data.db"
            )
            if not os.path.exists(db_path):
                print("[FAIL] No guardian_data.db found")
                return

            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                "SELECT address, chain_id FROM contracts "
                "WHERE bnb_balance > 0.001 AND exploitable_count > 0 "
                "ORDER BY bnb_balance DESC"
            )
            contracts = cur.fetchall()
            conn.close()

            print(f"Testing {len(contracts)} contracts...")
            results = []
            for row in contracts:
                cid = row["chain_id"]
                if cid not in RPC_URLS:
                    continue
                result = await tester.test_contract(row["address"], cid)
                results.append(result)
                if result.confirmed:
                    print(f"\n[!!!] EXPLOIT CONFIRMED on {result.address[:14]}.. !!!")
                    break  # Stop on first confirmed exploit

            # Summary
            confirmed_count = sum(1 for r in results if r.confirmed)
            print(f"\n{'=' * 60}")
            print(f"  BATCH RESULTS: {len(results)} tested, {confirmed_count} confirmed")
            print(f"{'=' * 60}")
        else:
            parser.print_help()
    finally:
        await tester.close()


if __name__ == "__main__":
    asyncio.run(main())
