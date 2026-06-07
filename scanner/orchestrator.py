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

logger = logging.getLogger("scanner.orchestrator")


class ScannerOrchestrator:
    """Orchestrates multiple blockchain scanners.

    Manages lifecycle (start/stop), event routing, and stats aggregation.
    """

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.global_config = config.get("global", {})
        self.chains_config = config.get("chains", {})

        self.scanners: dict[str, BaseScanner] = {}
        self.display: Optional[DisplayManager] = None
        self.filter: Optional[TransactionFilter] = None

        # Stats aggregation
        self.total_stats: dict[str, dict[str, int]] = {}

        # Event queue for async processing (unbounded to avoid dropping events)
        self._event_queue: asyncio.Queue[TransactionEvent] = asyncio.Queue()
        self._processor_task: Optional[asyncio.Task] = None

        # Source code verifier (checks if contracts are verified on block explorers)
        # A single Etherscan API V2 key works for ALL chains (60+ chains)
        explorer_key = self.global_config.get("explorer_api_key") or ""
        self.verifier = SourceCodeVerifier(api_key=explorer_key)

        # Cache of contract verification lookups already queued or in progress
        self._verifying: set[str] = set()

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

        # Start all scanners in parallel
        start_tasks = [scanner.start() for scanner in self.scanners.values()]
        await asyncio.gather(*start_tasks)

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
                if event.contract_address and event.chain_id and event.event_type in ("transfer", "transaction"):
                    asyncio.create_task(
                        self._verify_contract(event)
                    )

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

        except Exception as e:
            logger.debug(f"[verify] Error verifying {addr_key}: {e}")
        finally:
            self._verifying.discard(addr_key)

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
