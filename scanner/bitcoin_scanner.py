"""Bitcoin blockchain scanner using mempool.space WebSocket API."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Optional

import httpx

from scanner.base import BaseScanner, TransactionEvent

logger = logging.getLogger("scanner.bitcoin")

# Try to import websockets
try:
    import websockets
except ImportError:
    websockets = None  # type: ignore


class BitcoinScanner(BaseScanner):
    """Real-time Bitcoin scanner using mempool.space WebSocket API.

    No local Bitcoin node required — works with the public mempool.space API.
    Can be configured to use a private mempool.space instance.
    """

    def __init__(self, name: str, config: dict, callback=None):
        super().__init__(name, config, callback)
        self.api_url = config.get("api_url", "https://mempool.space/api")
        self.ws_url = config.get("ws_url", "wss://mempool.space/api/v1/ws")
        self.track_mempool = config.get("track_mempool", True)
        self.track_blocks = config.get("track_blocks", True)
        self.filters_config = config.get("filters", {})

        # Filter parameters
        self.min_value_sat = self._btc_to_sat(
            self.filters_config.get("min_value_btc")
        )
        self.max_value_sat = self._btc_to_sat(
            self.filters_config.get("max_value_btc")
        )
        self.tracked_addresses = set(
            self.filters_config.get("tracked_addresses", [])
        )

        # REST client for fetching extra data
        self.http_client: Optional[httpx.AsyncClient] = None

        # Cache of recent tx hashes to avoid duplicates
        self._recent_hashes: set = set()
        self._max_cache = 1000

    @staticmethod
    def _btc_to_sat(value: Optional[float]) -> Optional[int]:
        if value is None:
            return None
        return int(value * 100_000_000)

    async def _connect(self) -> Any:
        """Connect to mempool.space WebSocket."""
        if websockets is None:
            raise ImportError(
                "websockets library is required. Install: pip install websockets"
            )

        self.http_client = httpx.AsyncClient(timeout=30.0)

        ws = await websockets.connect(
            self.ws_url,
            ping_interval=30,
            max_size=5 * 1024 * 1024,  # 5MB max message
        )
        logger.info(f"[{self.name}] WebSocket connected to {self.ws_url}")

        # mempool.space WebSocket automatically broadcasts mempool and block
        # updates after connection — no subscription message needed.
        # See: https://mempool.space/docs/api/websocket
        if self.track_mempool:
            logger.info(f"[{self.name}] Listening for mempool updates")

        return ws

    async def _subscribe(self) -> None:
        """mempool.space sends all data on one channel after init."""
        pass  # Handled in _connect

    async def _listen(self) -> None:
        """Listen for messages from mempool.space WebSocket."""
        if not self._ws:
            return

        async for raw_msg in self._ws:
            if not self._running:
                break
            try:
                data = json.loads(raw_msg)
                await self._handle_message(data)
            except json.JSONDecodeError:
                logger.warning(f"[{self.name}] Invalid JSON received")
            except Exception as e:
                logger.error(f"[{self.name}] Error handling message: {e}")

    async def _handle_message(self, data: dict) -> None:
        """Process incoming WebSocket messages from mempool.space."""
        msg_type = data.get("type") or data.get("action", "")

        if msg_type == "block":
            await self._handle_block_data(data)
        elif msg_type in ("tx", "transaction", "mempool"):
            await self._handle_mempool_tx(data)
        elif msg_type == "init":
            logger.info(f"[{self.name}] Initialized — {data.get('message', '')}")

    async def _handle_block_data(self, data: dict) -> None:
        """Process a new Bitcoin block."""
        block_data = data.get("data", data)
        block_hash = block_data.get("id") or block_data.get("hash", "")
        block_height = block_data.get("height") or block_data.get("number", 0)
        tx_count = block_data.get("transactionCount", 0)

        self._stats["blocks_seen"] += 1

        event = TransactionEvent(
            chain=self.name,
            tx_hash=f"block_{block_hash[:16]}",
            block_number=block_height,
            block_hash=block_hash,
            event_type="block",
            data={
                "tx_count": tx_count,
                "timestamp": block_data.get("timestamp"),
                "size": block_data.get("size"),
                "weight": block_data.get("weight"),
            },
        )
        await self.emit_async(event)

    async def _handle_mempool_tx(self, data: dict) -> None:
        """Process a new mempool transaction."""
        tx_data = data.get("data", data)
        txid = tx_data.get("txid") or tx_data.get("hash", "")

        if not txid or txid in self._recent_hashes:
            return

        # Maintain hash cache
        self._recent_hashes.add(txid)
        if len(self._recent_hashes) > self._max_cache:
            self._recent_hashes.clear()

        # Extract transaction info
        value_sat = tx_data.get("value", 0)
        if isinstance(value_sat, dict):
            value_sat = value_sat.get("total", 0)

        fee_sat = tx_data.get("fee", 0)
        if isinstance(fee_sat, dict):
            fee_sat = fee_sat.get("total", 0) or fee_sat.get("amount", 0)

        vbytes = tx_data.get("vsize") or tx_data.get("size", 0)
        fee_rate = round(fee_sat / vbytes, 1) if vbytes > 0 else 0

        # Extract addresses from vin/vout
        vin = tx_data.get("vin", tx_data.get("inputs", []))
        vout = tx_data.get("vout", tx_data.get("outputs", []))

        from_addresses = set()
        to_addresses = []
        for inp in vin[:3]:  # First 3 inputs max
            addr = (
                inp.get("address")
                or inp.get("prevout", {}).get("address")
                or inp.get("script", "")
            )
            if addr:
                from_addresses.add(addr)

        for out in vout[:5]:  # First 5 outputs max
            addr = out.get("address") or ""
            out_value_sat = out.get("value", 0)
            to_addresses.append(
                {"address": addr, "value_sat": out_value_sat}
            )

        # Apply value filter
        if self.min_value_sat is not None:
            max_out = max((o["value_sat"] for o in to_addresses), default=0)
            if max_out < self.min_value_sat:
                return

        # Apply address filter
        if self.tracked_addresses:
            all_addrs = from_addresses | {
                o["address"] for o in to_addresses if o["address"]
            }
            if not all_addrs & self.tracked_addresses:
                return

        value_btc = round(value_sat / 100_000_000, 8)
        self._stats["txs_matched"] += 1

        event = TransactionEvent(
            chain=self.name,
            tx_hash=txid,
            from_address=", ".join(from_addresses)[:100] if from_addresses else None,
            to_address=(
                to_addresses[0]["address"] if to_addresses else None
            ),
            value=value_btc,
            value_currency="BTC",
            fee=round(fee_sat / 100_000_000, 8),
            status="pending",
            event_type="mempool",
            data={
                "fee_rate_sat_vb": fee_rate,
                "vsize": vbytes,
                "output_count": len(vout),
                "input_count": len(vin),
            },
        )
        await self.emit_async(event)

    async def _disconnect(self) -> None:
        """Close connections."""
        await super()._disconnect()
        if self.http_client:
            await self.http_client.aclose()
            self.http_client = None

    async def get_address_history(
        self, address: str, limit: int = 25
    ) -> list[dict]:
        """Fetch transaction history for a Bitcoin address via REST API."""
        if not self.http_client:
            self.http_client = httpx.AsyncClient(timeout=30.0)

        try:
            resp = await self.http_client.get(
                f"{self.api_url}/address/{address}/txs",
                params={"limit": limit},
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error(f"[{self.name}] Error fetching address history: {e}")
            return []

    async def get_recommended_fees(self) -> dict:
        """Get current recommended Bitcoin fees."""
        if not self.http_client:
            self.http_client = httpx.AsyncClient(timeout=30.0)

        try:
            resp = await self.http_client.get(f"{self.api_url}/v1/fees/recommended")
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error(f"[{self.name}] Error fetching fees: {e}")
            return {}
