#!/usr/bin/env python3
"""dump_results.py — Export guardian DB stats to findings/scanned_contracts.md"""
import sqlite3
import os
import sys
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "guardian_data.db")
MD_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "findings", "scanned_contracts.md")

restart_label = sys.argv[1] if len(sys.argv) > 1 else "manual"

if not os.path.exists(DB_PATH):
    print(f"[dump] DB not found: {DB_PATH}")
    sys.exit(0)

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row

c = conn.execute("SELECT COUNT(*) FROM contracts")
total = c.fetchone()[0]
c = conn.execute("SELECT COUNT(*) FROM contracts WHERE verified=1")
verified = c.fetchone()[0]
c = conn.execute("SELECT COUNT(*) FROM findings")
findings = c.fetchone()[0]
c = conn.execute("SELECT COUNT(*) FROM findings WHERE exploitable=1")
exploitable = c.fetchone()[0]
c = conn.execute("SELECT COUNT(*) FROM findings WHERE hardhat_result='CONFIRMED'")
confirmed = c.fetchone()[0]
c = conn.execute("SELECT COUNT(*) FROM findings WHERE hardhat_result='FAILED'")
failed = c.fetchone()[0]

# Top 15 exploitable
c = conn.execute("""
    SELECT f.contract_addr, f.finding_name, f.severity, c.chain_name, c.bnb_balance, c.name
    FROM findings f 
    LEFT JOIN contracts c ON f.contract_addr=c.address AND f.chain_id=c.chain_id
    WHERE f.exploitable=1 
    ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 ELSE 2 END
    LIMIT 15
""")
top = c.fetchall()

# Per-chain breakdown
c = conn.execute("""
    SELECT chain_name, COUNT(*) as cnt, SUM(CASE WHEN verified=1 THEN 1 ELSE 0 END) as ver
    FROM contracts GROUP BY chain_name ORDER BY cnt DESC
""")
chains = c.fetchall()

conn.close()

# Build markdown
now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
md = f"""# Guardian Auto-Report
> **{restart_label}** — {now} UTC

## Global Stats

| Metric | Count |
|--------|-------|
| Contracts in DB | {total} |
| Verified (source available) | {verified} |
| Total findings | {findings} |
| Exploitable findings | {exploitable} |
| Hardhat confirmed exploits | {confirmed} |
| Hardhat test failures | {failed} |

## Per-Chain Breakdown

| Chain | Contracts | Verified |
|-------|-----------|----------|
"""
for ch in chains:
    md += f"| {ch['chain_name'] or '?'} | {ch['cnt']} | {ch['ver']} |\n"

md += f"""
## Top 15 Exploitable Findings

| Contract | Chain | Severity | Balance | Contract Name | Finding |
|----------|-------|----------|---------|---------------|---------|
"""
for r in top:
    addr = r["contract_addr"][:14] + ".." if r["contract_addr"] else "?"
    chain = r["chain_name"] or "?"
    sev = r["severity"]
    bal = f"{r['bnb_balance']:.4f}" if r["bnb_balance"] else "0"
    name = (r["name"] or "?")[:20]
    finding = (r["finding_name"] or "?")[:55]
    md += f"| {addr} | {chain} | {sev} | {bal} | {name} | {finding} |\n"

os.makedirs(os.path.dirname(MD_PATH), exist_ok=True)
with open(MD_PATH, "w", encoding="utf-8") as f:
    f.write(md)

print(f"[dump] {MD_PATH} written: {total} contracts, {findings} findings, {exploitable} exploitable, {confirmed} confirmed")
