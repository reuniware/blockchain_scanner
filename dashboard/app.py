#!/usr/bin/env python3
"""
Dashboard — Web UI pour Blockchain Scanner
===========================================
Application FastAPI avec templates Jinja2 pour visualiser en temps réel :
  - Statistiques de la base (contrats, findings, tests Hardhat)
  - Liste des findings exploitables
  - Alertes d'exploits confirmés
  - Graphique des 34 patterns de vulnérabilité

Usage:
    python -m dashboard.app
    # ou
    uvicorn dashboard.app:app --reload --port 8080
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from fastapi import FastAPI, Request, Query
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates
except ImportError:
    print("[DASHBOARD] Install dependencies: pip install fastapi uvicorn jinja2")
    sys.exit(1)

import sqlite3

logger = logging.getLogger("dashboard")

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "guardian_data.db",
)


def get_db() -> Optional[sqlite3.Connection]:
    """Get a read-only connection to the guardian database."""
    if not os.path.exists(DB_PATH):
        return None
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _row_to_dict(row) -> dict:
    """Convert sqlite3.Row to a plain dict with safe values for Jinja2.
    
    sqlite3.Row can sometimes return nested Row objects that Jinja2
    can't cache, causing 'unhashable type: dict' errors.
    """
    d = {}
    for key in row.keys():
        val = row[key]
        if hasattr(val, 'keys') and hasattr(val, '__getitem__'):
            val = _row_to_dict(val) if not isinstance(val, (dict,)) else dict(val)
        d[key] = val
    return d


def get_stats() -> dict:
    """Aggregate stats from the database."""
    stats = {
        "contracts_total": 0,
        "contracts_verified": 0,
        "findings_total": 0,
        "findings_exploitable": 0,
        "exploits_confirmed": 0,
        "exploits_failed": 0,
        "exploits_pending": 0,
        "severity_breakdown": {},
        "top_contracts": [],
        "recent_exploits": [],
        "pattern_stats": [],
        "latest_scan": None,
        "db_exists": False,
    }

    conn = get_db()
    if not conn:
        return stats

    try:
        cur = conn.execute("SELECT COUNT(*) FROM contracts")
        stats["contracts_total"] = cur.fetchone()[0]

        cur = conn.execute("SELECT COUNT(*) FROM contracts WHERE verified = 1")
        stats["contracts_verified"] = cur.fetchone()[0]

        cur = conn.execute("SELECT COUNT(*) FROM findings")
        stats["findings_total"] = cur.fetchone()[0]

        cur = conn.execute("SELECT COUNT(*) FROM findings WHERE exploitable = 1")
        stats["findings_exploitable"] = cur.fetchone()[0]

        cur = conn.execute("SELECT COUNT(*) FROM findings WHERE hardhat_result = 'CONFIRMED'")
        stats["exploits_confirmed"] = cur.fetchone()[0]

        cur = conn.execute("SELECT COUNT(*) FROM findings WHERE hardhat_result = 'FAILED'")
        stats["exploits_failed"] = cur.fetchone()[0]

        cur = conn.execute("SELECT COUNT(*) FROM findings WHERE hardhat_result IS NULL AND exploitable = 1")
        stats["exploits_pending"] = cur.fetchone()[0]

        # Severity breakdown
        cur = conn.execute("""
            SELECT severity, COUNT(*) as cnt
            FROM findings
            GROUP BY severity
            ORDER BY CASE severity
                WHEN 'CRITICAL' THEN 0
                WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 3
                ELSE 4
            END
        """)
        stats["severity_breakdown"] = {row["severity"]: row["cnt"] for row in cur.fetchall()}

        # Top contracts by balance
        cur = conn.execute("""
            SELECT address, chain_name, bnb_balance, finding_count, exploitable_count,
                   hardhat_tested, hardhat_confirmed
            FROM contracts
            WHERE verified = 1
            ORDER BY bnb_balance DESC
            LIMIT 20
        """)
        stats["top_contracts"] = [_row_to_dict(r) for r in cur.fetchall()]

        # Recent exploits (confirmed)
        cur = conn.execute("""
            SELECT f.contract_addr, f.chain_id, f.finding_name, f.severity,
                   f.hardhat_evidence, f.created_at,
                   c.chain_name, c.bnb_balance
            FROM findings f
            JOIN contracts c ON c.address = f.contract_addr AND c.chain_id = f.chain_id
            WHERE f.hardhat_result = 'CONFIRMED'
            ORDER BY f.id DESC
            LIMIT 20
        """)
        stats["recent_exploits"] = [_row_to_dict(r) for r in cur.fetchall()]

        # Pattern stats
        cur = conn.execute("""
            SELECT finding_name, COUNT(*) as cnt,
                   SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                   SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
                   SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
                   SUM(exploitable) as exploitable
            FROM findings
            GROUP BY finding_name
            ORDER BY cnt DESC
            LIMIT 40
        """)
        stats["pattern_stats"] = [_row_to_dict(r) for r in cur.fetchall()]

        # Latest scan time
        cur = conn.execute("SELECT MAX(scanned_at) as latest FROM contracts")
        row = cur.fetchone()
        stats["latest_scan"] = row["latest"] if row else None

        stats["db_exists"] = True

    except Exception as e:
        logger.error(f"[DASHBOARD] DB error: {e}")
    finally:
        conn.close()

    return stats


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Blockchain Scanner Dashboard",
    description="Real-time monitoring dashboard for Blockchain Scanner",
    version="1.0.0",
)

# Templates — module-level singleton (Jinja2 cache is per-environment)
TEMPLATES_DIR = Path(__file__).parent / "templates"
TEMPLATES_DIR.mkdir(exist_ok=True)

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Main dashboard page."""
    stats = get_stats()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"request": request, "stats": stats},
    )


@app.get("/api/stats")
async def api_stats():
    """JSON API for stats (for real-time refresh)."""
    return JSONResponse(get_stats())


@app.get("/api/findings")
async def api_findings(
    severity: str = Query("", description="Filter by severity"),
    exploitable: bool = Query(None, description="Filter exploitable only"),
    limit: int = Query(100, description="Max results"),
):
    """JSON API for findings list."""
    conn = get_db()
    if not conn:
        return JSONResponse({"error": "No database"}, status_code=404)

    try:
        query = """
            SELECT f.id, f.contract_addr, f.chain_id, f.finding_name, f.severity,
                   f.exploitable, f.exploit_notes, f.hardhat_result, f.created_at,
                   c.chain_name, c.bnb_balance
            FROM findings f
            JOIN contracts c ON c.address = f.contract_addr AND c.chain_id = f.chain_id
            WHERE 1=1
        """
        params = []

        if severity:
            query += " AND f.severity = ?"
            params.append(severity.upper())

        if exploitable is not None:
            query += " AND f.exploitable = ?"
            params.append(1 if exploitable else 0)

        query += " ORDER BY f.id DESC LIMIT ?"
        params.append(limit)

        cur = conn.execute(query, params)
        results = [dict(r) for r in cur.fetchall()]
        return JSONResponse({"findings": results, "total": len(results)})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    finally:
        conn.close()


@app.get("/api/contracts")
async def api_contracts(
    min_balance: float = Query(0, description="Minimum balance"),
    limit: int = Query(50, description="Max results"),
):
    """JSON API for contracts list."""
    conn = get_db()
    if not conn:
        return JSONResponse({"error": "No database"}, status_code=404)

    try:
        cur = conn.execute("""
            SELECT * FROM contracts
            WHERE bnb_balance >= ?
            ORDER BY bnb_balance DESC
            LIMIT ?
        """, (min_balance, limit))
        results = [dict(r) for r in cur.fetchall()]
        return JSONResponse({"contracts": results, "total": len(results)})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    finally:
        conn.close()


@app.get("/api/contract/{address}")
async def api_contract_detail(address: str, chain_id: int = Query(1)):
    """JSON API for a specific contract with its findings."""
    conn = get_db()
    if not conn:
        return JSONResponse({"error": "No database"}, status_code=404)

    try:
        cur = conn.execute(
            "SELECT * FROM contracts WHERE address = ? AND chain_id = ?",
            (address.lower(), chain_id),
        )
        contract = cur.fetchone()
        if not contract:
            return JSONResponse({"error": "Contract not found"}, status_code=404)

        cur = conn.execute(
            "SELECT * FROM findings WHERE contract_addr = ? AND chain_id = ? ORDER BY id DESC",
            (address.lower(), chain_id),
        )
        findings = [dict(r) for r in cur.fetchall()]

        return JSONResponse({
            "contract": dict(contract),
            "findings": findings,
            "finding_count": len(findings),
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

def main():
    """Run the dashboard server."""
    import uvicorn

    host = os.environ.get("DASHBOARD_HOST", "127.0.0.1")
    port = int(os.environ.get("DASHBOARD_PORT", "8080"))

    print(f"\n{'=' * 60}")
    print(f"  Blockchain Scanner Dashboard")
    print(f"  http://{host}:{port}")
    print(f"{'=' * 60}\n")

    # Check if DB exists
    if not os.path.exists(DB_PATH):
        print(f"  [WARN] No database found at: {DB_PATH}")
        print(f"  [WARN] Start the Guardian first to populate data.\n")

    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
