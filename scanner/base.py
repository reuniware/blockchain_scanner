"""Abstract base class for all blockchain scanners."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional

logger = logging.getLogger("scanner")


@dataclass
class TransactionEvent:
    """Represents a detected transaction event from any blockchain."""

    chain: str
    chain_id: Optional[int] = None
    tx_hash: str = ""
    block_number: Optional[int] = None
    block_hash: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    from_address: Optional[str] = None
    to_address: Optional[str] = None
    value: Optional[float] = None
    value_currency: Optional[str] = None
    value_usd: Optional[float] = None
    gas_price: Optional[float] = None
    gas_used: Optional[int] = None
    fee: Optional[float] = None
    status: Optional[str] = None  # pending, confirmed, failed
    contract_address: Optional[str] = None  # Main contract address involved (token, DEX, etc.)
    contract_verified: Optional[bool] = None  # Whether source code is verified on block explorer
    data: Optional[dict] = None  # Raw data / extra fields
    event_type: str = "transaction"  # transaction, block, event, mempool

    def __str__(self) -> str:
        return (
            f"[{self.chain}] {self.event_type.upper()} "
            f"{self.tx_hash[:10]}... "
            f"{self.from_address or '?'} → {self.to_address or '?'} "
            f"{self.value or ''} {self.value_currency or ''}"
        )


class BaseScanner(ABC):
    """Abstract base scanner with WebSocket connection management and auto-reconnect."""

    def __init__(
        self,
        name: str,
        config: dict[str, Any],
        callback: Optional[Callable[[TransactionEvent], None]] = None,
    ):
        self.name = name
        self.config = config
        self.callback = callback
        self._running = False
        self._tasks: list[asyncio.Task] = []
        self._ws = None
        self._reconnect_delay = 1.0  # seconds, doubles on each retry
        self._max_reconnect_delay = 60.0
        self._status = "disconnected"
        self._stats: dict[str, int] = {
            "txs_seen": 0,
            "txs_matched": 0,
            "blocks_seen": 0,
            "reconnects": 0,
            "errors": 0,
        }

    @property
    def status(self) -> str:
        return self._status

    @property
    def stats(self) -> dict[str, int]:
        return self._stats

    @abstractmethod
    async def _connect(self) -> Any:
        """Establish connection to the blockchain node/API."""
        ...

    @abstractmethod
    async def _subscribe(self) -> None:
        """Subscribe to relevant streams (mempool, blocks, events)."""
        ...

    @abstractmethod
    async def _handle_message(self, message: Any) -> None:
        """Process an incoming message and emit TransactionEvents."""
        ...

    async def start(self) -> None:
        """Start the scanner with auto-reconnect loop."""
        self._running = True
        task = asyncio.create_task(self._run_loop())
        self._tasks.append(task)
        logger.info(f"[{self.name}] Scanner started")

    async def stop(self) -> None:
        """Stop the scanner gracefully."""
        self._running = False
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        await self._disconnect()
        logger.info(f"[{self.name}] Scanner stopped")

    async def _run_loop(self) -> None:
        """Main loop with auto-reconnect logic."""
        while self._running:
            try:
                self._status = "connecting"
                self._ws = await self._connect()
                self._status = "connected"
                self._reconnect_delay = 1.0  # Reset delay on successful connect
                logger.info(f"[{self.name}] Connected successfully")
                await self._subscribe()
                await self._listen()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self._stats["errors"] += 1
                logger.error(f"[{self.name}] Connection error: {e}")
                if not self._running:
                    break
                self._status = "reconnecting"
                await self._disconnect()
                self._stats["reconnects"] += 1
                logger.info(
                    f"[{self.name}] Reconnecting in {self._reconnect_delay}s..."
                )
                await asyncio.sleep(self._reconnect_delay)
                self._reconnect_delay = min(
                    self._reconnect_delay * 2, self._max_reconnect_delay
                )

    async def _listen(self) -> None:
        """Listen for messages from the WebSocket connection."""
        # Override in subclasses that use raw WebSocket
        # EVMs use web3.py's subscription handler instead
        pass

    async def _disconnect(self) -> None:
        """Close the connection."""
        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass
            self._ws = None
        self._status = "disconnected"

    def emit(self, event: TransactionEvent) -> None:
        """Emit a transaction event to the callback."""
        self._stats["txs_seen"] += 1
        if self.callback:
            self.callback(event)

    async def emit_async(self, event: TransactionEvent) -> None:
        """Async wrapper: runs emit in the default executor to avoid blocking."""
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self.emit, event)
