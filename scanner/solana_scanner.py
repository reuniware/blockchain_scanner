"""Solana blockchain scanner using solana.py async WebSocket."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from scanner.base import BaseScanner, TransactionEvent

logger = logging.getLogger("scanner.solana")

try:
    from solana.rpc.async_api import AsyncClient
    from solana.rpc.websocket_api import connect as solana_ws_connect
    from solders.pubkey import Pubkey
    from solders.signature import Signature
    HAS_SOLANA = True
except ImportError:
    HAS_SOLANA = False
    Pubkey = None  # type: ignore
    Signature = None  # type: ignore


class SolanaScanner(BaseScanner):
    """Real-time Solana blockchain scanner."""

    def __init__(self, name: str, config: dict, callback=None):
        super().__init__(name, config, callback)
        self.rpc_ws = config.get("rpc_ws", "wss://api.mainnet-beta.solana.com")
        self.rpc_http = config.get(
            "rpc_http", "https://api.mainnet-beta.solana.com"
        )
        self.filters_config = config.get("filters", {})

        self.min_value_lamports = self._sol_to_lamports(
            self.filters_config.get("min_value_sol")
        )
        self.tracked_accounts = set(
            self.filters_config.get("tracked_accounts", [])
        )
        self.tracked_programs = set(
            self.filters_config.get("tracked_programs", [])
        )

        # RPC client for fetching extra data
        self.rpc_client: Optional[AsyncClient] = None
        self.ws_connection = None

    @staticmethod
    def _sol_to_lamports(value: Optional[float]) -> Optional[int]:
        if value is None:
            return None
        return int(value * 1_000_000_000)  # 1 SOL = 1_000_000_000 lamports

    async def _connect(self) -> Any:
        """Connect to Solana WebSocket endpoint."""
        if not HAS_SOLANA:
            raise ImportError(
                "solana and solders packages required. "
                "Install: pip install solana solders"
            )

        self.rpc_client = AsyncClient(self.rpc_http)
        ws = await solana_ws_connect(self.rpc_ws)
        logger.info(f"[{self.name}] WebSocket connected")
        return ws

    async def _subscribe(self) -> None:
        """Subscribe to Solana transaction streams."""
        if not self._ws or not HAS_SOLANA:
            return

        ws = self._ws

        # Subscribe to logs (includes all transactions)
        if self.tracked_programs:
            for program_id in self.tracked_programs:
                pubkey = Pubkey.from_string(program_id)
                await ws.logs_subscribe(pubkey, commitment="processed")
                logger.info(
                    f"[{self.name}] Subscribed to logs for program: {program_id}"
                )
        else:
            # Subscribe to all logs
            await ws.logs_subscribe(commitment="processed")
            logger.info(f"[{self.name}] Subscribed to all logs")

        # Subscribe to specific accounts if configured
        if self.tracked_accounts:
            for account in self.tracked_accounts:
                pubkey = Pubkey.from_string(account)
                await ws.account_subscribe(pubkey, commitment="processed")
                logger.info(
                    f"[{self.name}] Subscribed to account: {account}"
                )

    async def _listen(self) -> None:
        """Listen for messages from Solana WebSocket."""
        if not self._ws:
            return

        async for msg in self._ws:
            if not self._running:
                break
            try:
                await self._handle_message(msg)
            except Exception as e:
                logger.error(f"[{self.name}] Error handling message: {e}")

    async def _handle_message(self, message: Any) -> None:
        """Process incoming Solana WebSocket message."""
        if not HAS_SOLANA:
            return

        try:
            # Solana WebSocket returns lists of notifications from solana.py
            results = message if isinstance(message, list) else [message]

            for result in results:
                if result is None:
                    continue

                # solana.py notifications have a .result attribute with subscription data
                data = getattr(result, "result", result)
                if data is None:
                    continue

                # Detect message type from the structure
                # Logs subscription returns logs data with a .value.signature
                # Account subscription returns account data with .value.lamports
                value = getattr(data, "value", data)
                if value is None:
                    continue

                # Check if it's a logs notification (has signature)
                signature = getattr(value, "signature", None)
                lamports = getattr(value, "lamports", None)

                if signature:
                    await self._handle_log(data)
                elif lamports is not None:
                    await self._handle_account(data)

        except Exception as e:
            logger.error(f"[{self.name}] Error parsing message: {e}")

    async def _handle_log(self, data: Any) -> None:
        """Process a Solana log notification."""
        try:
            value = getattr(data, "value", data)
            if not value:
                return

            logs = getattr(value, "logs", [])
            signature = getattr(value, "signature", "")
            err = getattr(value, "err", None)

            if not signature:
                return

            # Parse transaction info
            tx_sig = str(signature)

            # Look for SOL value transfers in the logs
            sol_value = None
            for log_line in logs:
                log_str = str(log_line)

                # Detect SPL Token transfers
                if "Transfer" in log_str and "amount" in log_str.lower():
                    try:
                        parts = log_str.split()
                        for i, part in enumerate(parts):
                            if "amount" in part.lower() and i + 1 < len(parts):
                                sol_value = float(parts[i + 1])
                    except (ValueError, IndexError):
                        pass

            # Apply filters
            if self.min_value_lamports is not None and sol_value is not None:
                if sol_value * 1e9 < self.min_value_lamports:
                    return

            self._stats["txs_matched"] += 1

            event = TransactionEvent(
                chain=self.name,
                tx_hash=tx_sig,
                status="failed" if err else "confirmed",
                event_type="transaction",
                value=sol_value,
                value_currency="SOL",
                data={
                    "log_count": len(logs),
                    "error": str(err) if err else None,
                    "logs": logs[:5],  # First 5 logs
                },
            )
            await self.emit_async(event)

        except Exception as e:
            logger.error(f"[{self.name}] Error processing log: {e}")

    async def _handle_account(self, data: Any) -> None:
        """Process a Solana account update."""
        try:
            value = getattr(data, "value", data)
            if not value:
                return

            account = getattr(value, "account", value)
            pubkey = getattr(value, "pubkey", "")

            # Extract lamports (SOL value)
            lamports = getattr(account, "lamports", 0)
            sol_balance = lamports / 1e9

            self._stats["txs_matched"] += 1

            event = TransactionEvent(
                chain=self.name,
                tx_hash=f"account_update_{pubkey}",
                to_address=str(pubkey) if pubkey else None,
                value=round(sol_balance, 6),
                value_currency="SOL",
                event_type="account_update",
                data={
                    "lamports": lamports,
                    "owner": str(getattr(account, "owner", "")),
                    "executable": getattr(account, "executable", False),
                },
            )
            await self.emit_async(event)

        except Exception as e:
            logger.error(f"[{self.name}] Error processing account update: {e}")

    async def _disconnect(self) -> None:
        """Close all connections."""
        await super()._disconnect()
        if self.rpc_client:
            await self.rpc_client.close()
            self.rpc_client = None

    async def get_account_balance(self, address: str) -> Optional[float]:
        """Fetch SOL balance for an account via REST RPC."""
        if not self.rpc_client or not HAS_SOLANA:
            return None
        try:
            pubkey = Pubkey.from_string(address)
            resp = await self.rpc_client.get_balance(pubkey)
            if resp and resp.value:
                return resp.value / 1e9
        except Exception as e:
            logger.error(f"[{self.name}] Error fetching balance: {e}")
        return None
