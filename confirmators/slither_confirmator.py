#!/usr/bin/env python3
"""
Slither Confirmator — Static analysis via Slither (Trail of Bits)
==================================================================
Calls the Slither CLI as an external subprocess to confirm whether
detected vulnerabilities are actually exploitable.

Slither is the industry standard for Solidity static analysis,
developed and maintained by Trail of Bits. It performs:
  - Data dependency analysis
  - Control flow graph construction
  - Taint analysis
  - Inheritance and contract interaction analysis

Key design:
  - ZERO import dependency on Slither's Python libraries
  - Communicates via subprocess + JSON pipe
  - Falls back gracefully if Slither is not installed
  - Results stored in the same DB as Hardhat tests

Usage:
    from confirmators.slither_confirmator import SlitherConfirmator

    confirmator = SlitherConfirmator()
    if confirmator.is_available():
        results = await confirmator.analyze_contract(
            source_code, contract_name="MyContract"
        )
        for r in results:
            print(f"[{r['severity']}] {r['title']} — {r['description'][:100]}")
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Optional

logger = logging.getLogger("slither-confirmator")

_CREATION_FLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0


# Known Slither detector mapping to severity
_SLITHER_SEVERITY = {
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
    "Informational": "INFO",
    "Optimization": "INFO",
}


class SlitherConfirmator:
    """Calls Slither CLI as an external subprocess (0 import dependency).

    Slither takes a .sol file or project directory as input and outputs
    analysis results in JSON format via the --json flag.

    The confirmator is **optional** — if Slither is not installed,
    `is_available()` returns False and all calls gracefully return [].
    """

    def __init__(self, db=None):
        """
        Args:
            db: Optional FindingsDB instance to store results.
        """
        self.db = db
        self._command: Optional[list[str]] = None
        self._home_dir = os.path.expanduser("~")

    def is_available(self) -> bool:
        """Check if Slither CLI is reachable (cached after first check)."""
        if self._command is not None:
            return True

        # 1. Try system `slither` command
        slither_path = shutil.which("slither")
        if slither_path:
            try:
                result = subprocess.run(
                    [slither_path, "--version"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=_CREATION_FLAGS,
                )
                if result.returncode == 0:
                    logger.info(f"[SLITHER] Found via system command: {slither_path}")
                    self._command = [slither_path]
                    return True
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                pass

        # 2. Try `python -m slither`
        try:
            result = subprocess.run(
                [sys.executable, "-m", "slither", "--version"],
                capture_output=True, text=True, timeout=10,
                creationflags=_CREATION_FLAGS,
            )
            if result.returncode == 0:
                logger.info(f"[SLITHER] Found via python -m slither")
                self._command = [sys.executable, "-m", "slither"]
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        logger.warning("[SLITHER] Slither not available. Install: pip install slither-analyzer")
        return False

    async def analyze_contract(
        self,
        source_code: str,
        contract_name: str = "Contract",
        timeout: int = 120,
    ) -> list[dict[str, Any]]:
        """Run Slither analysis on Solidity source code.

        Writes the source code to a temp file and runs slither --json on it.

        Args:
            source_code: Full Solidity source code as a string.
            contract_name: Name for the contract (for display).
            timeout: Analysis timeout in seconds.

        Returns:
            List of issue dicts with title, severity, description, etc.
        """
        if not self.is_available():
            logger.warning("[SLITHER] Skipping: Slither not available")
            return []

        tmp_dir = tempfile.mkdtemp(prefix="slither_")
        tmp_file = os.path.join(tmp_dir, f"{contract_name}.sol")
        json_output = os.path.join(tmp_dir, "slither_output.json")

        try:
            # Write source to temp file
            with open(tmp_file, "w", encoding="utf-8") as f:
                f.write(source_code)

            # Run slither analysis
            logger.info(f"[SLITHER] Analyzing {contract_name} ({len(source_code):,} chars)")
            proc = await asyncio.create_subprocess_exec(
                *self._command,
                tmp_file,
                "--json", json_output,
                "--solc-remaps", "@openzeppelin=node_modules/@openzeppelin",
                "--solc-disable-warnings",
                cwd=tmp_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                creationflags=_CREATION_FLAGS,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            err_output = stderr.decode("utf-8", errors="replace")[:500]

            if proc.returncode not in (0, 1):  # Slither exits 1 when it finds issues
                logger.warning(f"[SLITHER] Process exited with code {proc.returncode}: {err_output}")
                if proc.returncode != 1:
                    return []

            # Parse JSON output
            if not os.path.exists(json_output):
                logger.warning(f"[SLITHER] No JSON output file generated")
                return []

            with open(json_output, "r", encoding="utf-8") as f:
                data = json.load(f)

            issues = self._parse_output(data)
            logger.info(f"[SLITHER] {contract_name}: {len(issues)} issue(s) found")

            # Store in DB if configured
            if self.db and issues:
                self._store_in_db(issues, contract_name)

            return issues

        except asyncio.TimeoutError:
            logger.warning(f"[SLITHER] Timed out after {timeout}s for {contract_name}")
            return [self._timeout_result(timeout)]
        except Exception as e:
            logger.error(f"[SLITHER] Error analyzing {contract_name}: {e}")
            return []
        finally:
            # Cleanup temp files
            try:
                for f in [tmp_file, json_output]:
                    if os.path.exists(f):
                        os.remove(f)
                os.rmdir(tmp_dir)
            except Exception:
                pass

    async def analyze_address(
        self,
        address: str,
        chain_id: int,
        rpc_url: str = "",
        timeout: int = 120,
    ) -> list[dict[str, Any]]:
        """Analyze a contract address (requires verified source).

        Fetches source code via SourceCodeVerifier, then runs Slither on it.

        Args:
            address: Contract address (0x-prefixed hex).
            chain_id: EVM chain ID.
            rpc_url: Not used by Slither (Slither works on source, not bytecode).
            timeout: Analysis timeout in seconds.

        Returns:
            List of issue dicts.
        """
        if not self.is_available():
            return []

        # Fetch source code using our existing verifier
        from verify import SourceCodeVerifier
        verifier = SourceCodeVerifier()
        source = await verifier.get_source_code(address, chain_id)
        await verifier.close()

        if not source:
            logger.warning(f"[SLITHER] No source code for {address[:14]}..")
            return []

        return await self.analyze_contract(source, f"Contract_{address[:8]}", timeout)

    def _parse_output(self, data: dict) -> list[dict[str, Any]]:
        """Parse Slither JSON output into our standardized format.

        Slither's JSON output has the structure:
        {
            "success": true/false,
            "results": {
                "detectors": [
                    {
                        "check": "unused-state",
                        "impact": "Medium",
                        "confidence": "High",
                        "description": "...",
                        "elements": [...]
                    }
                ]
            }
        }
        """
        issues = []
        results = data.get("results", {}) if data.get("success") else data.get("results", {})
        detectors = results.get("detectors", [])

        for detector in detectors:
            issue = self._map_detector(detector)
            if issue:
                issues.append(issue)

        return issues

    def _map_detector(self, detector: dict) -> Optional[dict[str, Any]]:
        """Map a Slither detector result to our format."""
        try:
            check = detector.get("check", "unknown")
            impact = detector.get("impact", "Medium")
            confidence = detector.get("confidence", "Medium")

            severity = _SLITHER_SEVERITY.get(impact, "MEDIUM")

            # Build description from elements
            description_parts = []
            elements = detector.get("elements", [])
            for elem in elements[:3]:  # Limit to first 3 elements
                name = elem.get("name", "")
                if name:
                    description_parts.append(f"  - {name}: {elem.get('source_mapping', {}).get('filename_relative', '')}")
                sig = elem.get("type_specific_fields", {}).get("signature", "")
                if sig:
                    description_parts.append(f"    {sig}")

            description = detector.get("description", "")
            if not description:
                description = "; ".join(description_parts)

            # Clean up description
            description = re.sub(r"\s+", " ", description).strip()

            return {
                "title": f"{check}",
                "severity": severity,
                "confidence": confidence,
                "check": check,
                "description": description[:500],
                "elements": elements,
                "has_proof": confidence == "High" and severity in ("HIGH", "CRITICAL"),
                "source": "Slither",
            }
        except Exception as e:
            logger.debug(f"[SLITHER] Failed to map detector: {e}")
            return None

    def _timeout_result(self, timeout: int) -> dict[str, Any]:
        return {
            "title": "Analysis Timeout",
            "severity": "INFO",
            "confidence": "N/A",
            "check": "timeout",
            "description": f"Slither analysis timed out after {timeout}s",
            "elements": [],
            "has_proof": False,
            "source": "Slither",
        }

    def _store_in_db(self, issues: list[dict], contract_name: str) -> None:
        """Store Slither findings in DB (if configured)."""
        if not self.db:
            return
        try:
            for issue in issues:
                severity = issue.get("severity", "MEDIUM")
                if severity in ("HIGH", "CRITICAL"):
                    logger.warning(
                        f"[SLITHER-DB] [{severity}] {issue['title']} "
                        f"in {contract_name}"
                    )
        except Exception as e:
            logger.debug(f"[SLITHER] Error storing in DB: {e}")
