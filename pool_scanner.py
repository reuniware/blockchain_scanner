#!/usr/bin/env python3
"""
Pool Scanner — Trouve et scanne les pools DEX avec TVL
=======================================================
Recupere les pools les plus liquides via DEX Screener API,
les filtre (ignore les clones UniswapV2Pair standardises),
et les scanne avec exploit_pipeline pour trouver des failles.

Modes:
    --all          Scan TOUS les pools sans filtre TVL ni limite
    --min-tvl X    Ne scanner que les pools avec TVL >= X USD
    --audit-local  Lance un test Hardhat fork sur chaque contrat scanne

Usage:
    python pool_scanner.py                          # Scan des pools top 5 par DEX
    python pool_scanner.py --all                    # Scan absolument TOUS les pools
    python pool_scanner.py --all --audit-local      # Tous les pools + Hardhat systematique
    python pool_scanner.py --min-tvl 1000000        # Seules les pools > $1M TVL
    python pool_scanner.py --chains bsc,polygon     # Chaines specifiques
    python pool_scanner.py --daemon                 # Mode boucle (toutes les 30min)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from exploit_pipeline import ExploitPipeline, CHAIN_REGISTRY
from hardhat_fork_tester import HardhatForkTester

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [POOLSCAN] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("pool-scanner")

# ---------------------------------------------------------------------------
# DEX Screener configuration
# ---------------------------------------------------------------------------

# DEX protocols to scan: name -> (chain_id, chain_name_for_dex_screener)
# DEX Screener returns results by chain ID string like "polygon", "optimism", "bsc"
TARGET_DEXES = {
    "quickswap":  {"chain_id": 137, "dex_chain": "polygon",   "min_tvl": 10000},
    "velodrome":  {"chain_id": 10,  "dex_chain": "optimism",  "min_tvl": 50000},
    "thena":      {"chain_id": 56,  "dex_chain": "bsc",       "min_tvl": 50000},
    "uniswap":    {"chain_id": 1,   "dex_chain": "ethereum",  "min_tvl": 100000},
    "pancakeswap":{"chain_id": 56,  "dex_chain": "bsc",       "min_tvl": 100000},
    "sushiswap":  {"chain_id": 1,   "dex_chain": "ethereum",  "min_tvl": 50000},
    "balancer":   {"chain_id": 1,   "dex_chain": "ethereum",  "min_tvl": 50000},
    "curve":      {"chain_id": 1,   "dex_chain": "ethereum",  "min_tvl": 100000},
}

# Contract types that are clones/standard (high false positive rate)
KNOWN_STANDARD_TYPES = [
    "UniswapV2Pair",
    "UniswapV3Pool",
    "AlgebraPool",
    "BalancerPool",
    "CurveStableSwap",
    "PancakePair",
    "BabyPair",
]


@dataclass
class PoolInfo:
    address: str
    chain_id: int
    chain_name: str
    dex: str
    token0: str
    token1: str
    tvl_usd: float
    url: str = ""


# ---------------------------------------------------------------------------
# DEX Screener API client
# ---------------------------------------------------------------------------

class DEXScreenerAPI:
    """Fetch top pools by TVL from DEX Screener public API."""

    BASE_URL = "https://api.dexscreener.com/latest/dex"

    def __init__(self):
        import httpx
        self._http = httpx.AsyncClient(timeout=15)

    async def search_pools(self, query: str, chain_filter: Optional[str] = None) -> list[dict]:
        """Search for pools matching a query (DEX name or token symbol)."""
        url = f"{self.BASE_URL}/search?q={query}"
        r = await self._http.get(url)
        if r.status_code != 200:
            logger.warning(f"DEX Screener HTTP {r.status_code} for '{query}'")
            return []

        data = r.json()
        pairs = data.get("pairs", [])

        if chain_filter:
            pairs = [p for p in pairs if p.get("chainId") == chain_filter]

        return pairs

    async def close(self):
        await self._http.aclose()

    async def get_top_pools(self, dex_name: str, dex_config: dict,
                            limit: int = 10, all_pools: bool = False,
                            user_min_tvl: float = 0) -> list[PoolInfo]:
        """Get pools for a DEX protocol.

        Args:
            dex_name: DEX protocol name
            dex_config: Configuration dict with chain_id, dex_chain, min_tvl
            limit: Max pools to return (ignored if all_pools=True)
            all_pools: If True, return ALL pools (no TVL filter, no limit)
            user_min_tvl: Override DEX-specific min_tvl with user value
        """
        dex_chain = dex_config["dex_chain"]
        chain_id = dex_config["chain_id"]
        # Determine TVL threshold
        if all_pools:
            min_tvl = 0  # No filter
        elif user_min_tvl > 0:
            min_tvl = user_min_tvl
        else:
            min_tvl = dex_config["min_tvl"]

        pairs = await self.search_pools(dex_name, chain_filter=dex_chain)

        # Filter and sort by TVL
        valid_pools = []
        for p in pairs:
            liquidity = p.get("liquidity", {}) or {}
            tvl = float(liquidity.get("usd", 0))
            pair_addr = p.get("pairAddress", "")
            base = p.get("baseToken", {}) or {}
            quote = p.get("quoteToken", {}) or {}

            if tvl >= min_tvl and pair_addr and pair_addr.startswith("0x"):
                valid_pools.append(PoolInfo(
                    address=pair_addr,
                    chain_id=chain_id,
                    chain_name=CHAIN_REGISTRY.get(chain_id, ("?",))[0],
                    dex=dex_name,
                    token0=base.get("symbol", "?"),
                    token1=quote.get("symbol", "?"),
                    tvl_usd=tvl,
                    url=f"https://dexscreener.com/{dex_chain}/{pair_addr}",
                ))

        valid_pools.sort(key=lambda p: p.tvl_usd, reverse=True)
        if all_pools:
            return valid_pools  # Return ALL pools, no limit
        return valid_pools[:limit]


# ---------------------------------------------------------------------------
# Pool Analyzer
# ---------------------------------------------------------------------------

class PoolAnalyzer:
    """Analyze pools for vulnerabilities using exploit_pipeline."""

    def __init__(self, api_key: str = ""):
        self.pipeline = ExploitPipeline(api_key=api_key)
        self.results: list[dict] = []

    async def analyze_pool(self, pool: PoolInfo) -> Optional[dict]:
        """Run exploit pipeline on a single pool and return summary."""
        logger.info(f"[ANALYZE] {pool.dex}: {pool.token0}-{pool.token1} "
                   f"(${pool.tvl_usd:,.0f}) sur {pool.chain_name}")

        try:
            report = await self.pipeline.run_for_address(
                pool.address, pool.chain_id, pool.chain_name
            )

            if not report.findings:
                logger.info(f"  -> Propre (0 findings)")
                return None

            # Determine if this is a known standard contract type
            contract_type = report.contract_name
            is_standard = any(t in contract_type for t in KNOWN_STANDARD_TYPES)

            result = {
                "address": pool.address,
                "chain": pool.chain_name,
                "chain_id": pool.chain_id,
                "dex": pool.dex,
                "pair": f"{pool.token0}-{pool.token1}",
                "tvl_usd": pool.tvl_usd,
                "contract_name": contract_type,
                "source_length": report.source_length,
                "is_standard_clone": is_standard,
                "total_findings": len(report.findings),
                "critical": sum(1 for f in report.findings if f.severity == "CRITICAL"),
                "high": sum(1 for f in report.findings if f.severity == "HIGH"),
                "medium": sum(1 for f in report.findings if f.severity == "MEDIUM"),
                "exploitable": report.total_exploitable,
                "findings": [
                    {
                        "name": f.name, "severity": f.severity,
                        "lines": f.line_numbers,
                        "exploitable": v.theoretically_exploitable,
                        "notes": v.exploit_notes[:200],
                    }
                    for f, v in zip(report.findings, report.validations)
                ],
                "dex_url": pool.url,
                "scanned_at": datetime.utcnow().isoformat(),
            }

            # Mark as interesting if:
            # - Not a standard clone AND has exploitable findings
            # - OR has CRITICAL findings regardless
            # - OR has >3 exploitable findings
            if is_standard:
                result["verdict"] = "FAUX_POSITIF_PROBABLE (clone standard)"
            elif report.total_exploitable >= 3:
                result["verdict"] = "INTERESSANT (3+ exploitables)"
            elif any(f.severity == "CRITICAL" for f in report.findings):
                result["verdict"] = "INTERESSANT (CRITICAL trouve)"
            else:
                result["verdict"] = "A_VERIFIER"

            self.results.append(result)

            # Log verdict
            verdict_tag = {
                "FAUX_POSITIF_PROBABLE (clone standard)": "[FP]",
                "INTERESSANT (3+ exploitables)": "[!!!]",
                "INTERESSANT (CRITICAL trouve)": "[!!!]",
                "A_VERIFIER": "[?]",
            }.get(result["verdict"], "[?]")

            logger.info(f"  {verdict_tag} {contract_type}: "
                       f"{len(report.findings)} findings, "
                       f"{report.total_exploitable} exploitables - {result['verdict']}")

            return result

        except Exception as e:
            logger.error(f"[ERROR] Analyzing {pool.address[:14]}..: {e}")
            return None

    async def close(self):
        await self.pipeline.close()


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

class PoolScanner:
    """Main scanner: fetches pools, analyzes them, reports findings."""

    def __init__(self, api_key: str = "", db=None):
        self.api_key = api_key
        self.db = db  # Optional guardian DB
        self.dex_api = DEXScreenerAPI()
        self.analyzer = PoolAnalyzer(api_key=api_key)
        self._hardhat_tester = None  # Lazy init
        self._hardhat_available = None

    async def scan_all(self, top_n: int = 5,
                       chain_filter: Optional[list[str]] = None,
                       all_pools: bool = False,
                       min_tvl: float = 0,
                       audit_local: bool = False) -> list[dict]:
        """Scan pools from each target DEX.

        Args:
            top_n: Max pools per DEX (ignored if all_pools=True)
            chain_filter: Optional list of chain names to scan
            all_pools: Scan ALL pools without TVL filter or limit
            min_tvl: User-specified minimum TVL in USD
            audit_local: Run Hardhat fork test on each contract after scan
        """
        all_results = []
        total_pools = 0

        for dex_name, dex_config in TARGET_DEXES.items():
            dex_chain = dex_config["dex_chain"]
            if chain_filter and dex_chain not in chain_filter:
                continue

            logger.info(f"\n{'='*60}")
            logger.info(f"  {dex_name.upper()} sur {dex_chain}")
            logger.info(f"{'='*60}")

            pools = await self.dex_api.get_top_pools(
                dex_name, dex_config, limit=top_n,
                all_pools=all_pools, user_min_tvl=min_tvl
            )
            if not pools:
                logger.info(f"  Aucun pool trouve (min TVL: ${dex_config['min_tvl']:,})")
                continue

            logger.info(f"  {len(pools)} pools trouve(s)")
            total_pools += len(pools)

            for pool in pools:
                logger.info(f"\n  --- {pool.token0}-{pool.token1} "
                          f"(${pool.tvl_usd:,.0f}) ---")
                logger.info(f"  Adresse: {pool.address}")
                logger.info(f"  DEX: {pool.url}")

                result = await self.analyzer.analyze_pool(pool)
                if result:
                    all_results.append(result)

                    # LIVE FEEDBACK: print result immediately (ASCII-safe)
                    verdict = result.get("verdict", "?")
                    fcount = result["total_findings"]
                    exploitable = result["exploitable"]
                    pair_name = f"{pool.token0}-{pool.token1}"
                    tvl_str = f"${pool.tvl_usd:,.0f}" if pool.tvl_usd > 0 else "$0"
                    # Encode to ASCII for Windows cp1252 safety
                    live_line = f"  [LIVE] {pair_name:20s} | {tvl_str:>12s} | " \
                                f"{fcount:>3d} findings | {exploitable:>3d} exploitables | {verdict}"
                    print(live_line.encode('ascii', errors='replace').decode('ascii'), flush=True)

                    # Hardhat local audit (systematic)
                    if audit_local and exploitable > 0:
                        await self._audit_hardhat(pool, result)

                # Small delay between scans to avoid rate limiting
                await asyncio.sleep(1)

        # Print summary
        self._print_summary(all_results, total_pools)
        return all_results

    def _print_summary(self, results: list[dict], total_pools: int):
        """Log a formatted summary of scan results."""
        logger.info(f"{'='*60}")
        logger.info("  POOL SCANNER — RAPPORT FINAL")
        logger.info(f"{'='*60}")
        logger.info(f"  Pools trouves: {total_pools}")
        logger.info(f"  Scannes: {len(results)}")
        logger.info(f"  Avec findings: {len([r for r in results if r['total_findings'] > 0])}")

        interesting = [r for r in results if r["verdict"].startswith("INTERESSANT")]
        if interesting:
            logger.info(f"  [!!!] POOLS INTERESSANTS ({len(interesting)}):")
            for r in interesting[:10]:
                logger.info(f"    {r['pair']:20s} | ${r['tvl_usd']:>12,.0f} | "
                     f"{r['contract_name']:20s} | {r['exploitable']} exploitables")

        fps = [r for r in results if "FAUX_POSITIF" in r["verdict"]]
        if fps:
            logger.info(f"  [FP] Faux positifs (clones standardises): {len(fps)}")

        logger.info(f"  Resultats sauvegardes: pool_scan_results.json")

    def save_results(self, results: list[dict], path: str = "pool_scan_results.json"):
        """Save scan results to JSON file."""
        output = {
            "scan_timestamp": datetime.utcnow().isoformat(),
            "total_scanned": len(results),
            "interesting": [r for r in results if r["verdict"].startswith("INTERESSANT")],
            "hardhat_tested": [r for r in results if r.get("hardhat_confirmed") is not None],
            "hardhat_confirmed": [r for r in results if r.get("hardhat_confirmed")],
            "results": results,
        }
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), path), "w") as f:
            json.dump(output, f, indent=2, default=str)
        logger.info(f"[SAVE] {len(results)} resultats dans {path}")

    async def _audit_hardhat(self, pool: PoolInfo, pipeline_result: dict):
        """Run systematic Hardhat fork test on a scanned pool.

        Skips standard clones (false positives) and contracts with 0 balance.
        Prints live feedback.
        """
        # Skip known false positives
        verdict = pipeline_result.get("verdict", "")
        if "FAUX_POSITIF" in verdict:
            print(f"  [HARDHAT] SKIP: faux positif standard ({verdict})", flush=True)
            return

        # Lazy-init Hardhat tester
        if self._hardhat_tester is None:
            print(f"  [HARDHAT] Initializing Hardhat fork tester...", flush=True)
            self._hardhat_tester = HardhatForkTester(api_key=self.api_key)
            # Check availability once
            self._hardhat_available = await self._hardhat_tester._check_hardhat()
            if not self._hardhat_available:
                print(f"  [HARDHAT] NOT AVAILABLE — install Hardhat: npm install -g hardhat", flush=True)
                return
            # Pre-compile contracts
            print(f"  [HARDHAT] Pre-compiling exploit contracts...", flush=True)
            ok = await self._hardhat_tester._compile_contracts()
            if not ok:
                print(f"  [HARDHAT] Compilation FAILED — skipping all audits", flush=True)
                self._hardhat_available = False
                return
            print(f"  [HARDHAT] Ready.", flush=True)

        if not self._hardhat_available:
            return

        pair_name = f"{pool.token0}-{pool.token1}"
        # ASCII-safe pair name
        pair_name_ascii = pair_name.encode('ascii', errors='replace').decode('ascii')
        print(f"\n{'~' * 50}", flush=True)
        print(f"  [HARDHAT AUDIT] {pair_name_ascii} | ${pool.tvl_usd:,.0f} | "
              f"{pipeline_result['exploitable']} exploitables", flush=True)
        print(f"  [HARDHAT] Forking {pool.chain_name} at latest block...", flush=True)

        try:
            result = await asyncio.wait_for(
                self._hardhat_tester.test_contract(pool.address, pool.chain_id),
                timeout=240
            )

            if result.confirmed:
                print(f"  [!!!] HARDHAT EXPLOIT CONFIRMED: {result.drained:.6f} native drained!", flush=True)
                print(f"  [!!!] EVIDENCE: {result.evidence[:300]}", flush=True)
                pipeline_result["hardhat_confirmed"] = True
                pipeline_result["hardhat_drained"] = result.drained
                pipeline_result["hardhat_evidence"] = result.evidence[:1000]
            else:
                drain_info = f" (drained {result.drained:.6f})" if result.drained > 0 else ""
                print(f"  [HARDHAT] NOT exploitable{drain_info}: {result.evidence[:120]}", flush=True)
                pipeline_result["hardhat_confirmed"] = False
                pipeline_result["hardhat_evidence"] = result.evidence[:500]

        except asyncio.TimeoutError:
            print(f"  [HARDHAT] TIMEOUT after 240s", flush=True)
            pipeline_result["hardhat_confirmed"] = False
            pipeline_result["hardhat_evidence"] = "Timeout"
        except Exception as e:
            print(f"  [HARDHAT] Error: {e}", flush=True)
            pipeline_result["hardhat_confirmed"] = False
            pipeline_result["hardhat_evidence"] = str(e)[:200]

    async def close(self):
        await self.analyzer.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

async def main_async(args):
    scanner = PoolScanner(api_key=args.api_key)

    if args.daemon:
        # Run in loop every 30 minutes
        logger.info("[DAEMON] Mode boucle 30min demarre")
        try:
            while True:
                results = await scanner.scan_all(
                    top_n=0 if args.all else args.top,
                    all_pools=args.all,
                    min_tvl=args.min_tvl,
                    audit_local=args.audit_local,
                )
                scanner.save_results(results)
                if results:
                    interesting = [r for r in results if r["verdict"].startswith("INTERESSANT")]
                    hardhat_ok = [r for r in results if r.get("hardhat_confirmed")]
                    if hardhat_ok:
                        logger.critical(f"[!!!] {len(hardhat_ok)} EXPLOIT(S) CONFIRME(S) PAR HARDHAT !")
                    elif interesting:
                        logger.critical(f"[!!!] {len(interesting)} pool(s) interessant(s) trouve(s)!")
                logger.info(f"[DAEMON] Prochain scan dans 30min...")
                await asyncio.sleep(1800)  # 30 minutes
        except asyncio.CancelledError:
            logger.info("[DAEMON] Arrete")
        except KeyboardInterrupt:
            logger.info("[DAEMON] Interrompu par utilisateur")
    else:
        chain_filter = args.chains.split(",") if args.chains else None
        results = await scanner.scan_all(
            top_n=0 if args.all else args.top,
            chain_filter=chain_filter,
            all_pools=args.all,
            min_tvl=args.min_tvl,
            audit_local=args.audit_local,
        )
        scanner.save_results(results)

        # Final Hardhat summary
        if args.audit_local:
            hardhat_ok = [r for r in results if r.get("hardhat_confirmed")]
            hardhat_no = [r for r in results if r.get("hardhat_confirmed") is False]
            if hardhat_ok:
                logger.critical(f"\n[!!!] {len(hardhat_ok)} EXPLOIT(S) CONFIRME(S) PAR HARDHAT !")
                for r in hardhat_ok:
                    logger.critical(f"  {r['pair']}: {r.get('hardhat_drained', 0):.6f} drained")
            if hardhat_no:
                logger.info(f"[HARDHAT] {len(hardhat_no)} contracts tested — NOT exploitable")

    await scanner.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Pool Scanner — Trouve et scanne les pools DEX avec TVL"
    )
    parser.add_argument("--top", "-n", type=int, default=5,
                        help="Nombre de pools par DEX (defaut: 5, ignore avec --all)")
    parser.add_argument("--all", "-a", action="store_true",
                        help="Scan ABSOLUMENT TOUS les pools (pas de filtre TVL, pas de limite)")
    parser.add_argument("--min-tvl", "-t", type=float, default=0,
                        help="TVL minimum en USD (ex: --min-tvl 1000000 pour $1M+)")
    parser.add_argument("--audit-local", "-l", action="store_true",
                        help="Lancer un test Hardhat fork systematique sur CHAQUE contrat scanne")
    parser.add_argument("--chains", "-c", default=None,
                        help="Chaines (ex: polygon,optimism,bsc)")
    parser.add_argument("--daemon", "-d", action="store_true",
                        help="Mode boucle (toutes les 30min)")
    parser.add_argument("--api-key", "-k", default="47JTF3MC7RJ24NSZGTIXNT84KFBQDHWY8E",
                        help="Etherscan API V2 key")
    args = parser.parse_args()

    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
