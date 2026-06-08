"""Orchestrator — launches and manages multiple blockchain scanners."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from scanner.base import BaseScanner, TransactionEvent
from scanner.evm_scanner import EVMScanner
from scanner.bitcoin_scanner import BitcoinScanner
from scanner.solana_scanner import SolanaScanner
from filters.filters import TransactionFilter
from output.display import DisplayManager
from verify import SourceCodeVerifier
from analysis.vulnerability_scanner import analyze_contract, VulnerabilityFinding

logger = logging.getLogger("scanner.orchestrator")


class ScannerOrchestrator:
    """Orchestrates multiple blockchain scanners.

    Manages lifecycle (start/stop), event routing, and stats aggregation.
    """

    def __init__(
        self,
        config: dict[str, Any],
        on_contract_checked: Optional[callable] = None,
        on_unverified_contract: Optional[callable] = None,
        auto_stop_enabled: bool = True,
    ):
        """
        Args:
            config: YAML config dict
            on_contract_checked: async callback(address, chain_id, chain_name, findings, source_code)
                                Called when a verified contract is fully scanned.
            on_unverified_contract: async callback(address, chain_id, chain_name)
                                    Called when a contract is detected but NOT verified.
            auto_stop_enabled: If True, sets vulnerability_found_event on HIGH/CRITICAL finding
                               (used by main.py). Guardian mode sets this to False.
        """
        self.config = config
        self.global_config = config.get("global", {})
        self.chains_config = config.get("chains", {})
        self._on_contract_checked = on_contract_checked
        self._on_unverified_contract = on_unverified_contract
        self._auto_stop_enabled = auto_stop_enabled

        self.scanners: dict[str, BaseScanner] = {}
        self.display: Optional[DisplayManager] = None
        self.filter: Optional[TransactionFilter] = None

        # Stats aggregation
        self.total_stats: dict[str, dict[str, int]] = {}

        # Event queue for async processing (unbounded to avoid dropping events)
        self._event_queue: asyncio.Queue[TransactionEvent] = asyncio.Queue()
        self._processor_task: Optional[asyncio.Task] = None

        # Auto-stop: set when a vulnerability is found (for user-facing "stop on first vuln" mode)
        self.vulnerability_found_event: asyncio.Event = asyncio.Event()
        self._found_vulnerability: Optional[VulnerabilityFinding] = None
        self._last_vuln_address: Optional[str] = None
        self._last_vuln_chain_id: Optional[int] = None
        self._last_source_code: Optional[str] = None  # Cache source for exploit pipeline

        # Source code verifier (checks if contracts are verified on block explorers)
        # A single Etherscan API V2 key works for ALL chains (60+ chains)
        explorer_key = self.global_config.get("explorer_api_key") or ""
        self.verifier = SourceCodeVerifier(api_key=explorer_key)

        # Cache of contract verification lookups already queued or in progress
        self._verifying: set[str] = set()

        # Cache of vulnerability scan results to avoid re-scanning
        self._vuln_cache: dict[str, list[VulnerabilityFinding]] = {}
        self._scanning_vulns: set[str] = set()

        # Cache of EOA checks (addresses confirmed to have no bytecode)
        self._eoa_cache: set[str] = set()
        self._checking_eoa: set[str] = set()

        # Build chain_id -> rpc_http mapping from config for EOA checks
        self._chain_rpc_map: dict[int, str] = {}
        for chain_key, chain_cfg in self.chains_config.items():
            cid = chain_cfg.get("chain_id")
            rpc = chain_cfg.get("rpc_http", "")
            if cid and rpc:
                self._chain_rpc_map[cid] = rpc

        # Fire-and-forget tasks (verify, vuln scan) — tracked so they can be
        # cancelled on shutdown instead of leaking.
        self._fire_and_forget: set[asyncio.Task] = set()

    @property
    def found_vulnerability(self) -> Optional[VulnerabilityFinding]:
        return self._found_vulnerability

    @property
    def last_vuln_address(self) -> Optional[str]:
        return self._last_vuln_address

    @property
    def last_vuln_chain_id(self) -> Optional[int]:
        return self._last_vuln_chain_id

    @property
    def last_source_code(self) -> Optional[str]:
        return self._last_source_code

    def _create_scanner(
        self, chain_key: str, chain_cfg: dict
    ) -> Optional[BaseScanner]:
        """Create a scanner instance for a chain based on its type."""
        if not chain_cfg.get("enabled", False):
            return None

        chain_name = chain_cfg.get("name", chain_key.capitalize())

        # Detect chain type
        if chain_key in ("ethereum", "polygon", "bsc", "arbitrum", "optimism", "avalanche"):
            scanner = EVMScanner(
                name=chain_name,
                chain_key=chain_key,
                config=chain_cfg,
                callback=self._on_event,
            )
        elif chain_key == "bitcoin":
            scanner = BitcoinScanner(
                name=chain_name,
                config=chain_cfg,
                callback=self._on_event,
            )
        elif chain_key == "solana":
            scanner = SolanaScanner(
                name=chain_name,
                config=chain_cfg,
                callback=self._on_event,
            )
        else:
            logger.warning(f"Unknown chain type: {chain_key}")
            return None

        return scanner

    async def start(self) -> None:
        """Initialize all enabled scanners and start them."""
        logger.info("Starting scanner orchestrator...")

        # Initialize display
        output_format = self.global_config.get("output_format", "rich")
        self.display = DisplayManager(format=output_format)

        # Initialize filter and configure from chain configs
        self.filter = TransactionFilter()
        for chain_key, chain_cfg in self.chains_config.items():
            self.filter.configure_from_config(chain_cfg)

        # Create scanners for each enabled chain
        for chain_key, chain_cfg in self.chains_config.items():
            scanner = self._create_scanner(chain_key, chain_cfg)
            if scanner:
                self.scanners[chain_key] = scanner
                logger.info(f"  + {chain_key}: {chain_cfg.get('name', chain_key)}")

        if not self.scanners:
            logger.warning("No scanners enabled. Check your config.yaml")
            return

        # Start event processor
        self._processor_task = asyncio.create_task(self._process_events())

        # Start all scanners in parallel (tolerate individual failures)
        start_tasks = [scanner.start() for scanner in self.scanners.values()]
        results = await asyncio.gather(*start_tasks, return_exceptions=True)
        failed = []
        for chain_key, result in zip(list(self.scanners.keys()), results):
            if isinstance(result, Exception):
                logger.error(f"[{chain_key}] Scanner failed to start: {result}")
                failed.append(chain_key)
        # Remove failed scanners entirely so they don't block stop()
        for chain_key in failed:
            del self.scanners[chain_key]

        logger.info(
            f"Orchestrator running: {len(self.scanners)} scanner(s) active"
        )

        # Display the dashboard header
        if self.display:
            self.display.show_header(list(self.scanners.values()))

    async def stop(self) -> None:
        """Stop all scanners gracefully."""
        logger.info("Stopping all scanners...")

        # Stop all scanners
        stop_tasks = [scanner.stop() for scanner in self.scanners.values()]
        await asyncio.gather(*stop_tasks, return_exceptions=True)

        # Stop event processor
        if self._processor_task:
            self._processor_task.cancel()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass

        # Cancel fire-and-forget tasks (verify, vuln scan) that may still be running.
        # Use a list copy for gather because add_done_callback fires on cancel
        # and removes tasks from the set before we can await them.
        pending = list(self._fire_and_forget)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        self._fire_and_forget.clear()

        self.scanners.clear()

        # Close contract verifier HTTP session
        await self.verifier.close()

        logger.info("All scanners stopped")

    def _on_event(self, event: TransactionEvent) -> None:
        """Callback when a scanner detects a transaction.

        This is called synchronously — we put the event on the async queue.
        """
        # Put event on the queue (queue is unbounded, so this won't block)
        self._event_queue.put_nowait(event)

    async def _process_events(self) -> None:
        """Process events from the queue — filter, format, display, verify contracts."""
        while True:
            try:
                event = await self._event_queue.get()

                # Apply global filters
                if self.filter and not self.filter.passes(event):
                    continue

                # Update stats
                chain = event.chain
                if chain not in self.total_stats:
                    self.total_stats[chain] = {"txs": 0, "blocks": 0}
                self.total_stats[chain]["txs"] += 1
                if event.event_type == "block":
                    self.total_stats[chain]["blocks"] += 1

                # Display the event
                if self.display:
                    await self.display.show_event(event)

                # Async contract source code verification (non-blocking)
                # Only for EVM chains with a contract address
                if event.contract_address and event.chain_id and event.event_type in ("transfer", "transaction", "contract_deploy"):
                    task = asyncio.create_task(self._verify_contract(event))
                    self._fire_and_forget.add(task)
                    task.add_done_callback(self._fire_and_forget.discard)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error processing event: {e}")

    async def _verify_contract(self, event: TransactionEvent) -> None:
        """Asynchronously check if a contract's source code is verified.

        Results are cached in the verifier, so repeated requests
        for the same address only query the explorer once.
        """
        if not event.contract_address or not event.chain_id:
            return

        addr_key = f"{event.chain_id}:{event.contract_address.lower()}"

        # Skip if already checked or currently verifying
        cached = self.verifier.is_cached(event.contract_address, event.chain_id)
        if cached is not None or addr_key in self._verifying:
            return

        self._verifying.add(addr_key)

        try:
            verified = await self.verifier.is_verified(
                event.contract_address, event.chain_id
            )

            if verified is not None:
                # Update the event's verification status
                event.contract_verified = verified
                logger.info(
                    f"[verify] {event.contract_address[:10]}.. "
                    f"-> {'VERIFIED' if verified else 'NOT VERIFIED'}"
                    f" ({event.chain})"
                )

                # Re-display with verification info
                if self.display:
                    await self.display.show_verification(event)

                # If verified, scan for vulnerabilities
                if verified:
                    task = asyncio.create_task(self._scan_vulnerabilities(event))
                    self._fire_and_forget.add(task)
                    task.add_done_callback(self._fire_and_forget.discard)
                elif self._on_unverified_contract:
                    # Fire callback for unverified contracts too
                    try:
                        await self._on_unverified_contract(
                            address=event.contract_address,
                            chain_id=event.chain_id,
                            chain_name=event.chain,
                        )
                    except Exception as e:
                        logger.error(f"[callback] Error in on_unverified_contract: {e}")

        except Exception as e:
            logger.debug(f"[verify] Error verifying {addr_key}: {e}")
        finally:
            self._verifying.discard(addr_key)

    async def _is_eoa(self, address: str, chain_id: int) -> bool:
        """Check if an address is an EOA (not a contract) via eth_getCode.

        Uses the chain's RPC HTTP endpoint to check if the address has
        any bytecode. If not, it's an EOA and should be skipped to avoid
        false positive vulnerability scans on externally owned accounts.
        """
        addr_key = f"{chain_id}:{address.lower()}"
        if addr_key in self._eoa_cache:
            return True
        if addr_key in self._checking_eoa:
            return False  # Already checking, assume it's a contract

        rpc_url = self._chain_rpc_map.get(chain_id)
        if not rpc_url:
            return False  # No RPC configured, assume contract

        self._checking_eoa.add(addr_key)
        try:
            import httpx
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_getCode",
                "params": [address, "latest"],
                "id": 1,
            }
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(rpc_url, json=payload)
                data = resp.json()
                code = data.get("result", "0x")
                is_eoa = (code == "0x" or code == "0x0")
                if is_eoa:
                    self._eoa_cache.add(addr_key)
                return is_eoa
        except Exception as e:
            logger.debug(f"[eoa] Error checking {addr_key}: {e}")
            return False  # On error, assume contract (better to scan than miss)
        finally:
            self._checking_eoa.discard(addr_key)

    async def _scan_vulnerabilities(self, event: TransactionEvent) -> None:
        """Asynchronously scan a verified contract's source code
        for security vulnerabilities.

        Results are cached so repeated transfers to the same contract
        only trigger the scan once.
        """
        if not event.contract_address or not event.chain_id:
            return

        addr_key = f"{event.chain_id}:{event.contract_address.lower()}"

        # Skip if already scanned or currently scanning
        if addr_key in self._vuln_cache or addr_key in self._scanning_vulns:
            return

        self._scanning_vulns.add(addr_key)

        # Filter out EOAs (externally owned accounts) — they have no bytecode
        # and would produce false positive vulnerability detections.
        # This avoids issues with Etherscan returning metadata for addresses
        # that are actually EOAs on the current chain (but contracts on others).
        if await self._is_eoa(event.contract_address, event.chain_id):
            logger.debug(f"[vuln] {event.contract_address[:10]}.. is EOA, skipping")
            self._vuln_cache[addr_key] = []
            self._scanning_vulns.discard(addr_key)
            return

        try:
            # Fetch the full source code
            source_code = await self.verifier.get_source_code(
                event.contract_address, event.chain_id
            )

            if not source_code:
                logger.debug(f"[vuln] No source code available for {addr_key}")
                return

            # Analyze the source code for vulnerabilities
            findings = analyze_contract(source_code)
            self._vuln_cache[addr_key] = findings

            if findings:
                # Display vulnerability warnings
                logger.info(
                    f"[vuln] {event.contract_address[:10]}.. "
                    f"-> {len(findings)} vulnerability(ies) found"
                )

                if self.display:
                    await self.display.show_vulnerabilities(
                        event, findings
                    )

                # Check if any finding is exploitable (HIGH or CRITICAL)
                exploitable = [f for f in findings if f.severity in ("HIGH", "CRITICAL")]
                if exploitable and self._auto_stop_enabled:
                    # Guard against race: only store the FIRST vulnerability found.
                    # Concurrent _scan_vulnerabilities tasks may finish at the same
                    # time; preserve the original finding to avoid mismatched
                    # address/vulnerability pairs in main.py's display.
                    if not self.vulnerability_found_event.is_set():
                        self._found_vulnerability = exploitable[0]
                        self._last_vuln_address = event.contract_address
                        self._last_vuln_chain_id = event.chain_id
                        self._last_source_code = source_code  # Cache source for exploit pipeline
                    self.vulnerability_found_event.set()
                    logger.warning(
                        f"[AUTO-STOP] HIGH/CRITICAL vulnerability found in "
                        f"{event.contract_address[:14]}.. — stopping scanner!"
                    )
            else:
                logger.info(
                    f"[vuln] {event.contract_address[:10]}.. "
                    f"-> No vulnerabilities detected"
                )

            # Fire callback to guardian (if set) with findings and source code
            # Called ALWAYS — even with 0 findings, so the guardian knows about the contract
            if self._on_contract_checked and event.contract_address:
                try:
                    await self._on_contract_checked(
                        address=event.contract_address,
                        chain_id=event.chain_id,
                        chain_name=event.chain,
                        findings=findings,
                        source_code=source_code,
                    )
                except Exception as e:
                    logger.error(f"[callback] Error in on_contract_checked: {e}")

        except Exception as e:
            logger.debug(f"[vuln] Error scanning {addr_key}: {e}")
        finally:
            self._scanning_vulns.discard(addr_key)

    def get_all_stats(self) -> dict[str, Any]:
        """Get aggregated stats from all scanners."""
        stats = {}
        for chain_key, scanner in self.scanners.items():
            stats[chain_key] = {
                "status": scanner.status,
                **scanner.stats,
                "name": scanner.name,
            }
        return stats

    async def wait_forever(self) -> None:
        """Keep running until interrupted."""
        try:
            while True:
                await asyncio.sleep(1)

                # Periodically update display with stats
                if self.display and len(self.scanners) > 0:
                    self.display.show_status(self.get_all_stats())

        except asyncio.CancelledError:
            pass
