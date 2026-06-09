#!/usr/bin/env python3
"""
Mythril Confirmator — External symbolic execution validation
=============================================================
Calls the Mythril CLI (`myth` or `python -m mythril`) as an external subprocess
to confirm whether detected vulnerabilities are actually exploitable.

Key design:
  - ZERO import dependency on Mythril's Python libraries
  - Communicates via subprocess + JSON pipe (standard Unix philosophy)
  - Falls back gracefully if Mythril is not installed
  - Results stored in the same DB as Hardhat tests

Usage:
    from confirmators.mythril_confirmator import MythrilConfirmator

    confirmator = MythrilConfirmator()
    if confirmator.is_available():
        results = await confirmator.analyze_address("0x...", rpc_url="https://...")
        for r in results:
            print(f"[{r['severity']}] {r['title']} — SWC-{r['swc_id']}")
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime
from typing import Optional

logger = logging.getLogger("mythril-confirmator")

# Prevent console windows on Windows
_CREATION_FLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

# Default paths to try for finding mythril CLI
_MYTH_COMMANDS = ["myth", "mythril"]
_NPX_CMD = "npx.cmd" if platform.system() == "Windows" else "npx"

# Mapping Mythril severity to our severity scale
_SEVERITY_MAP = {
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
    "Critical": "CRITICAL",
    "Informational": "INFO",
    "Warning": "MEDIUM",
}

# SWC ID to our finding name mapping (enrichment)
_SWC_KNOWN_NAMES = {
    "101": "Integer Overflow",
    "102": "Outdated Compiler",
    "103": "Floating Pragma",
    "104": "Unchecked Call Return Value",
    "105": "Ether Theft",
    "106": "Unprotected SELFDESTRUCT",
    "107": "Reentrancy",
    "108": "State Variable Default Visibility",
    "109": "Uninitialized Storage Pointer",
    "110": "Assert Violation",
    "111": "Use of Deprecated Solidity Functions",
    "112": "Delegatecall to Untrusted Callee",
    "113": "DoS with Failed Call",
    "114": "Transaction Order Dependence",
    "115": "Authorization through tx.origin",
    "116": "Timestamp Dependence",
    "117": "Uninitialized State Variable",
    "118": "Constructor Mismatch",
    "119": "Shadowing State Variables",
    "120": "Weak Sources of Randomness",
    "121": "Unprotected Initializer",
    "122": "Missing Protection against Signature Replay Attacks",
    "123": "Requirement Violation",
    "124": "Arbitrary Storage Write",
    "125": "Incorrect Inheritance Order",
    "126": "Insufficient Gas Griefing",
    "127": "Arbitrary Jump",
    "128": "DoS With Block Gas Limit",
    "129": "Typographical Error",
    "130": "Unchecked Return Value",
    "131": "Exposed Internal Function",
}


class MythrilConfirmator:
    """Calls Mythril CLI as an external subprocess (0 import dependency).

    Architecture:
      - Finds the `myth` command (or `python -m mythril`) on the system
      - Calls `myth analyze -a <addr> -o jsonv2` with optional RPC
      - Parses the JSON output into MythrilIssue objects
      - Stores results in the Guardian DB (optional)

    The confirmator is **optional** — if Mythril is not installed,
    `is_available()` returns False and all calls gracefully return [].
    """

    def __init__(self, mythril_dir: str = "", db=None):
        """
        Args:
            mythril_dir: Optional path to Mythril repository root.
                         Used for `python -m mythril` fallback.
            db: Optional FindingsDB instance to store results.
        """
        self.mythril_dir = mythril_dir
        self.db = db
        self._command: Optional[list[str]] = None

        # RPC URLs per chain (fallback — user can override)
        self.rpc_urls = {
            1: "https://eth.llamarpc.com",
            56: "https://bsc-dataseed1.binance.org",
            137: "https://polygon-bor-rpc.publicnode.com",
            42161: "https://arb1.arbitrum.io/rpc",
            10: "https://mainnet.optimism.io",
            43114: "https://api.avax.network/ext/bc/C/rpc",
            8453: "https://mainnet.base.org",
            250: "https://rpc.ftm.tools",
        }

    def is_available(self) -> bool:
        """Check if Mythril CLI is reachable (cached after first check)."""
        if self._command is not None:
            return True

        # 1. Try system `myth` command
        myth_path = shutil.which("myth")
        if myth_path:
            try:
                result = subprocess.run(
                    [myth_path, "--version"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=_CREATION_FLAGS,
                )
                if result.returncode == 0:
                    self._command = [myth_path]
                    logger.info(f"[MYTHRIL] Found system command: {myth_path}")
                    return True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # 2. Try system `mythril` command
        mythril_path = shutil.which("mythril")
        if mythril_path:
            try:
                result = subprocess.run(
                    [mythril_path, "--version"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=_CREATION_FLAGS,
                )
                if result.returncode == 0:
                    self._command = [mythril_path]
                    logger.info(f"[MYTHRIL] Found system command: {mythril_path}")
                    return True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # 3. Try `python -m mythril` from mythril_dir
        if self.mythril_dir and os.path.isdir(self.mythril_dir):
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "mythril", "--version"],
                    cwd=self.mythril_dir,
                    capture_output=True, text=True, timeout=10,
                    creationflags=_CREATION_FLAGS,
                )
                if result.returncode == 0:
                    self._command = [sys.executable, "-m", "mythril"]
                    logger.info(f"[MYTHRIL] Found via python -m mythril in {self.mythril_dir}")
                    return True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        logger.warning("[MYTHRIL] Mythril not available. Install: pip install mythril")
        return False

    async def analyze_address(self, address: str, chain_id: int = 1,
                               rpc_url: str = "", timeout: int = 180) -> list[dict]:
        """Run Mythril analysis on a contract address.

        Args:
            address: Contract address to analyze (0x-prefixed hex).
            chain_id: EVM chain ID (for RPC fallback).
            rpc_url: Custom RPC URL (defaults to self.rpc_urls[chain_id]).
            timeout: Analysis timeout in seconds (Mythril can be slow).

        Returns:
            List of issue dicts with title, severity, swc_id, description.
        """
        if not self.is_available():
            logger.warning("[MYTHRIL] Skipping: Mythril not available")
            return []

        rpc = rpc_url or self.rpc_urls.get(chain_id, "https://eth.llamarpc.com")
        addr_short = address[:14]

        logger.info(f"[MYTHRIL] Analyzing {addr_short}.. on chain {chain_id} (rpc={rpc[:40]}..)")

        try:
            proc = await asyncio.create_subprocess_exec(
                *self._command,
                "analyze",
                "-a", address,
                "--rpc", rpc,
                "-o", "jsonv2",
                cwd=self.mythril_dir or None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                creationflags=_CREATION_FLAGS,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

            output = stdout.decode("utf-8", errors="replace")
            err_output = stderr.decode("utf-8", errors="replace")[:500]

            if proc.returncode != 0:
                logger.warning(f"[MYTHRIL] Process exited with code {proc.returncode}: {err_output}")
                # Mythril returns non-zero even on success sometimes — try to parse anyway

            issues = self._parse_jsonv2_output(output)
            logger.info(f"[MYTHRIL] {addr_short}..: {len(issues)} issue(s) found")
            return issues

        except asyncio.TimeoutError:
            logger.warning(f"[MYTHRIL] Timed out after {timeout}s for {addr_short}..")
            return [{
                "title": "Analysis Timeout",
                "severity": "INFO",
                "swc_id": "N/A",
                "description": f"Mythril analysis timed out after {timeout}s",
                "contract": "",
                "function": "",
                "has_tx_sequence": False,
                "source": "Mythril",
            }]
        except Exception as e:
            logger.error(f"[MYTHRIL] Error analyzing {addr_short}..: {e}")
            return []

    async def analyze_bytecode(self, bytecode_path: str,
                                timeout: int = 120) -> list[dict]:
        """Run Mythril analysis on a local bytecode binary file.

        Args:
            bytecode_path: Path to file containing raw EVM bytecode (hex).
            timeout: Analysis timeout in seconds.

        Returns:
            List of issue dicts.
        """
        if not self.is_available():
            return []

        logger.info(f"[MYTHRIL] Analyzing bytecode file: {bytecode_path}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *self._command,
                "analyze",
                "--bin", bytecode_path,
                "-o", "jsonv2",
                cwd=self.mythril_dir or None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                creationflags=_CREATION_FLAGS,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = stdout.decode("utf-8", errors="replace")

            issues = self._parse_jsonv2_output(output)
            logger.info(f"[MYTHRIL] Bytecode: {len(issues)} issue(s) found")
            return issues

        except asyncio.TimeoutError:
            logger.warning(f"[MYTHRIL] Timed out after {timeout}s for bytecode")
            return []
        except Exception as e:
            logger.error(f"[MYTHRIL] Error analyzing bytecode: {e}")
            return []

    def _parse_jsonv2_output(self, stdout: str) -> list[dict]:
        """Parse Mythril JSONv2 output into a list of issue dicts.

        Handles both:
          - JSONv2 format: {"success": true, "issues": [...]}
          - Plain JSON:    {"issues": [...]}
          - Multiple JSON objects (myth sometimes outputs progress + result)
        """
        issues = []

        # Try to find and parse JSON in the output
        # Mythril sometimes outputs progress lines before the JSON
        json_start = stdout.find("{")
        if json_start < 0:
            logger.warning("[MYTHRIL] No JSON found in output")
            return issues

        json_str = stdout[json_start:]

        # Try to extract the last complete JSON object (Mythril may output multiple)
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            # Try to find a complete JSON object by brace matching
            brace_count = 0
            for i, ch in enumerate(json_str):
                if ch == "{":
                    brace_count += 1
                elif ch == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        try:
                            data = json.loads(json_str[:i + 1])
                            break
                        except json.JSONDecodeError:
                            continue
            else:
                logger.warning("[MYTHRIL] Could not parse JSON output")
                return issues

        if not data:
            return issues

        if data.get("success") is False:
            error = data.get("error", "Unknown error")
            logger.warning(f"[MYTHRIL] Analysis reported error: {error}")
            return []

        raw_issues = data.get("issues", [])
        for issue in raw_issues:
            mapped = self._map_issue(issue)
            if mapped:
                issues.append(mapped)

        return issues

    def _map_issue(self, issue: dict) -> Optional[dict]:
        """Map a Mythril issue dict to our standardized format."""
        try:
            title = issue.get("title", "Unknown")
            swc_id = str(issue.get("swc-id", issue.get("swcID", "")))
            severity_raw = issue.get("severity", "Medium")
            if isinstance(severity_raw, dict):
                severity_raw = severity_raw.get("level", "Medium")

            # Map severity to our scale
            severity = _SEVERITY_MAP.get(severity_raw, "MEDIUM")

            description = issue.get("description", "") or ""
            # Clean description (remove excessive whitespace)
            description = re.sub(r"\\s+", " ", description).strip()

            # Get SWC title from known names if available
            swc_title = _SWC_KNOWN_NAMES.get(swc_id, "")

            # Build a rich title
            if swc_title and swc_title not in title:
                display_title = f"{title} (SWC-{swc_id}: {swc_title})"
            else:
                display_title = f"{title} (SWC-{swc_id})"

            # Check if this finding includes a concrete tx sequence (proof)
            tx_sequence = issue.get("tx_sequence", issue.get("transaction_sequence"))
            has_proof = tx_sequence is not None

            return {
                "title": display_title,
                "swc_id": swc_id,
                "severity": severity,
                "description": description[:500],
                "contract": issue.get("contract", ""),
                "function": issue.get("function", ""),
                "address": issue.get("address", 0),
                "lineno": issue.get("lineno", 0),
                "has_tx_sequence": has_proof,
                "has_proof": has_proof,
                "source": f"Mythril SWC-{swc_id}",
                "raw": {
                    "title": title,
                    "swc_id": swc_id,
                    "severity": severity_raw,
                    "source_map": issue.get("sourceMap", ""),
                },
            }
        except Exception as e:
            logger.debug(f"[MYTHRIL] Failed to map issue: {e}")
            return None


# ---------------------------------------------------------------------------
# Standalone CLI test
# ---------------------------------------------------------------------------

async def _main():
    """Quick test: run Mythril on a known contract."""
    import argparse
    parser = argparse.ArgumentParser(description="Mythril Confirmator — standalone test")
    parser.add_argument("--address", "-a", required=True, help="Contract address")
    parser.add_argument("--chain", "-c", type=int, default=1, help="Chain ID")
    parser.add_argument("--rpc", "-r", default="", help="RPC URL")
    parser.add_argument("--mythril-dir", "-d",
                        default=os.path.join(os.path.dirname(__file__), "..", "..", "mythril"),
                        help="Path to mythril repo (for python -m mythril)")
    args = parser.parse_args()

    confirmator = MythrilConfirmator(mythril_dir=args.mythril_dir)

    if not confirmator.is_available():
        print("[FAIL] Mythril not available")
        # Print discovery paths for debugging
        print(f"  Checked: myth, mythril, python -m mythril in {args.mythril_dir}")
        return

    print(f"[OK] Mythril available via: {' '.join(confirmator._command)}")
    print(f"[ANALYZING] {args.address[:14]}.. on chain {args.chain}...")

    issues = await confirmator.analyze_address(args.address, args.chain, args.rpc)

    print(f"\\n{'=' * 60}")
    print(f"  RESULTS: {len(issues)} issue(s)")
    print(f"{'=' * 60}")

    for idx, issue in enumerate(issues, 1):
        proof = " [PROOF]" if issue.get("has_tx_sequence") else ""
        print(f"\\n  [{idx}] [{issue['severity']}] {issue['title']}{proof}")
        print(f"       Contract: {issue['contract']}  Function: {issue['function']}")
        print(f"       {issue['description'][:200]}")


if __name__ == "__main__":
    asyncio.run(_main())
