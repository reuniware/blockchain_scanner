"""EVM (Ethereum, Polygon, BSC, Arbitrum) blockchain scanner using web3.py async."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from typing import Any, Optional

from web3 import AsyncWeb3
from web3.providers.persistent import WebSocketProvider

from scanner.base import BaseScanner, TransactionEvent

logger = logging.getLogger("scanner.evm")

# ERC-20 Transfer event signature hash
ERC20_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4b11628f55a4df523b3ef"


class EVMScanner(BaseScanner):
    """Real-time scanner for EVM-compatible blockchains via WebSocket."""

    def __init__(self, name: str, chain_key: str, config: dict, callback=None):
        super().__init__(name, config, callback)
        self.chain_key = chain_key
        self.chain_id = config.get("chain_id")
        self.currency = config.get("currency", "ETH")
        self.track_mempool = config.get("track_mempool", True)
        self.track_blocks = config.get("track_blocks", True)
        self.rpc_ws = config.get("rpc_ws", "")
        self.filters_config = config.get("filters", {})

        # Filter parameters
        self.min_value_wei = self._eth_to_wei(self.filters_config.get("min_value_eth"))
        self.max_value_wei = self._eth_to_wei(self.filters_config.get("max_value_eth"))
        self.tracked_addresses = set(
            addr.lower() for addr in self.filters_config.get("tracked_addresses", [])
        )
        self.tracked_tokens = set(
            addr.lower() for addr in self.filters_config.get("tracked_tokens", [])
        )
        self.tracked_events = self.filters_config.get("tracked_events", [])

        # web3.py async instance
        self.w3: Optional[AsyncWeb3] = None

    @staticmethod
    def _eth_to_wei(value: Optional[float]) -> Optional[int]:
        if value is None:
            return None
        return int(value * 10**18)

    async def _connect(self) -> AsyncWeb3:
        """Connect to the EVM node via WebSocket (web3.py v7 persistent connection)."""
        if not self.rpc_ws:
            raise ValueError(f"[{self.name}] No rpc_ws configured")

        # web3.py v7 persistent WebSocket provider
        provider = WebSocketProvider(
            self.rpc_ws,
            websocket_kwargs={"ping_interval": 30},
        )
        self.w3 = AsyncWeb3(provider)

        # Connect (establishes the persistent WebSocket connection)
        await provider.connect()

        # Verify connection
        if not await self.w3.is_connected():
            raise ConnectionError(f"[{self.name}] Failed to connect to {self.rpc_ws}")

        block_num = await self.w3.eth.block_number
        chain_id = await self.w3.eth.chain_id
        logger.info(
            f"[{self.name}] Connected - Chain ID: {chain_id}, Block: #{block_num}"
        )
        return self.w3

    async def _subscribe(self) -> None:
        """Subscribe to pending transactions and new blocks."""
        if not self.w3:
            raise RuntimeError("Not connected")

        # Subscribe to new block headers
        if self.track_blocks:
            try:
                sub_id = await self.w3.eth.subscribe("newHeads")
                logger.info(f"[{self.name}] Subscribed to newHeads (id: {sub_id})")
            except Exception as e:
                logger.warning(f"[{self.name}] Could not subscribe to newHeads: {e}")

        # Subscribe to pending transactions
        if self.track_mempool:
            try:
                sub_id = await self.w3.eth.subscribe("newPendingTransactions")
                logger.info(
                    f"[{self.name}] Subscribed to newPendingTransactions (id: {sub_id})"
                )
            except Exception as e:
                logger.warning(
                    f"[{self.name}] Could not subscribe to mempool: {e}. "
                    "Some providers require a paid plan for mempool access."
                )

        # Subscribe to logs (Transfer events)
        if "Transfer" in self.tracked_events:
            try:
                if self.tracked_tokens:
                    for token_addr in self.tracked_tokens:
                        await self.w3.eth.subscribe(
                            "logs",
                            {
                                "address": AsyncWeb3.to_checksum_address(token_addr),
                                "topics": [ERC20_TRANSFER_TOPIC],
                            },
                        )
                else:
                    await self.w3.eth.subscribe(
                        "logs", {"topics": [ERC20_TRANSFER_TOPIC]}
                    )
                logger.info(f"[{self.name}] Subscribed to Transfer events")
            except Exception as e:
                logger.warning(f"[{self.name}] Could not subscribe to logs: {e}")

    async def _listen(self) -> None:
        """Listen for subscription messages via persistent connection."""
        if not self.w3:
            return

        try:
            # web3.py v7: process_subscriptions() is an async generator
            # that yields subscription responses as they arrive
            if not hasattr(self.w3, 'socket'):
                logger.warning(f"[{self.name}] No socket available for subscriptions")
                return

            async for response in self.w3.socket.process_subscriptions():
                if not self._running:
                    break
                try:
                    await self._handle_message(response)
                except Exception as e:
                    logger.error(f"[{self.name}] Error handling message: {e}")
        except AttributeError as e:
            logger.warning(f"[{self.name}] Subscription streaming not available")
            await self._poll_blocks()
        except Exception as e:
            logger.warning(
                f"[{self.name}] Switching to polling mode (subscriptions not supported)"
            )
            await self._poll_blocks()

    async def _handle_message(self, message: Any) -> None:
        """Process an incoming WebSocket message."""
        try:
            # web3.py subscription result format
            if not isinstance(message, dict):
                return

            result = message.get("result") or message.get("params", {}).get("result")
            if not result:
                return

            # Use Mapping to handle both dict and web3.py's AttributeDict (v7)
            if isinstance(result, Mapping):
                has_number = "number" in result
                has_tx_hash = "transactionHash" in result
                has_topics = "topics" in result
                has_gas = "gas" in result

                # Block headers have a "number" field (hex string from subscription)
                if has_number:
                    await self._handle_block(result)
                elif has_tx_hash or "hash" in result:
                    if has_topics:
                        await self._handle_log(result)
                    else:
                        await self._handle_transaction(result)
                elif has_gas:
                    await self._handle_transaction(result)
            elif isinstance(result, str) and len(result) == 66:
                await self._handle_pending_hash(result)

        except Exception as e:
            logger.error(f"[{self.name}] Error in handle_message: {type(e).__name__}: {e}")

    async def _handle_block(self, block: dict) -> None:
        """Process a new block header."""
        block_num = block.get("number", 0)
        # Subscription results return block numbers as hex strings ("0x...")
        # Convert to int for consistency
        if isinstance(block_num, str) and block_num.startswith("0x"):
            block_num = int(block_num, 16)
        self._stats["blocks_seen"] += 1

        event = TransactionEvent(
            chain=self.name,
            chain_id=self.chain_id,
            block_number=block_num,
            block_hash=block.get("hash", ""),
            event_type="block",
            data={
                "timestamp": block.get("timestamp"),                    "tx_count": len(block.get("transactions", [])),
                "gas_used": block.get("gasUsed"),
                "gas_limit": block.get("gasLimit"),
            },
        )
        await self.emit_async(event)

    async def _fetch_logs_for_block(self, block_number: int) -> None:
        """Fetch Transfer event logs for a given block (used in polling fallback).

        Note: Most free public nodes (PublicNode.com) do NOT support eth_getLogs.
        This method silently handles the error so polling continues uninterrupted.
        Transfer events on BSC require a paid RPC provider (Alchemy/QuickNode).
        """
        if not self.w3 or "Transfer" not in self.tracked_events:
            return
        if hasattr(self, '_logs_not_supported'):
            return  # Permanently disabled after first failure

        for attempt in range(3):
            try:
                logs_resp = await self.w3.provider.make_request(
                    "eth_getLogs",
                    [{
                        "fromBlock": hex(block_number),
                        "toBlock": hex(block_number),
                        "topics": [ERC20_TRANSFER_TOPIC],
                    }],
                )

                # JSON-RPC error response (expected on some public nodes)
                if isinstance(logs_resp, dict) and logs_resp.get("error"):
                    self._logs_not_supported = True
                    logger.info(
                        f"[{self.name}] eth_getLogs not supported on this provider. "
                        "Transfer events will not be detected in polling mode."
                    )
                    return

                # Success: process log entries
                log_entries = logs_resp.get("result") if isinstance(logs_resp, dict) else []
                if log_entries:
                    for log_entry in log_entries[:50]:
                        await self._handle_log(log_entry)
                    logger.info(
                        f"[{self.name}] {len(log_entries)} Transfer events in block #{block_number}"
                    )
                return  # Success

            except asyncio.CancelledError:
                return
            except Exception as e:
                if attempt < 2:
                    await asyncio.sleep(0.5)
                    continue
                self._logs_not_supported = True
                logger.debug(f"[{self.name}] eth_getLogs unavailable: {e}")

    async def _poll_blocks(self) -> None:
        """Fallback: poll for new blocks using raw RPC calls.

        Uses raw JSON-RPC instead of web3.py's typed get_block() to avoid
        formatting issues with non-standard block data (e.g. BSC's extraData).
        """
        if not self.w3:
            return

        # Init last_block to current block to avoid re-scanning history
        init_resp = await self.w3.provider.make_request("eth_blockNumber", [])
        last_block = int(init_resp["result"], 16) if not init_resp.get("error") else 0
        logger.info(f"[{self.name}] Starting block polling at #{last_block}")

        while self._running:
            try:
                # Use raw JSON-RPC call to avoid web3.py formatter issues
                resp = await self.w3.provider.make_request(
                    "eth_blockNumber", []
                )
                if resp.get("error"):
                    logger.warning(f"[{self.name}] RPC error: {resp['error']}")
                    await asyncio.sleep(15)
                    continue

                block_num = int(resp["result"], 16)

                if block_num > last_block:
                    for i in range(last_block + 1, block_num + 1):
                        try:
                            raw_resp = await self.w3.provider.make_request(
                                "eth_getBlockByNumber",
                                [hex(i), False],
                            )
                            if raw_resp.get("error"):
                                continue

                            block = raw_resp["result"]
                            if not block:
                                continue

                            event = TransactionEvent(
                                chain=self.name,
                                chain_id=self.chain_id,
                                block_number=i,
                                block_hash=block.get("hash", ""),
                                event_type="block",
                                data={
                                    "timestamp": block.get("timestamp"),
                                    "tx_count": len(block.get("transactions", [])),
                                    "gas_used": block.get("gasUsed"),
                                    "gas_limit": block.get("gasLimit"),
                                },
                            )
                            await self.emit_async(event)

                        except Exception as e:
                            logger.debug(
                                f"[{self.name}] Error fetching block {i}: {e}"
                            )

                    last_block = block_num

                # Dynamic polling interval based on chain
                # BSC = 3s, Ethereum = 12s, Polygon = 2s, Arbitrum = 0.25s
                if self.chain_id == 56:  # BSC
                    await asyncio.sleep(3)
                elif self.chain_id == 42161:  # Arbitrum
                    await asyncio.sleep(1)
                elif self.chain_id == 137:  # Polygon
                    await asyncio.sleep(3)
                else:
                    await asyncio.sleep(12)  # Ethereum

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"[{self.name}] Polling error (will retry): {e}")
                await asyncio.sleep(15)

    async def _handle_pending_hash(self, tx_hash: str) -> None:
        """Process a pending transaction hash by fetching its details."""
        try:
            tx = await self.w3.eth.get_transaction(tx_hash)  # type: ignore
            if tx:
                await self._handle_transaction(dict(tx), is_pending=True)
        except Exception:
            pass  # Transaction might have been dropped before we could fetch it

    async def _handle_transaction(
        self, tx: dict, is_pending: bool = False
    ) -> None:
        """Process a transaction and emit if it passes filters."""
        if not tx:
            return

        from_addr = tx.get("from", "")
        to_addr = tx.get("to", "")
        value_wei = tx.get("value", 0)
        if isinstance(value_wei, str):
            value_wei = int(value_wei, 16)
        elif not isinstance(value_wei, int):
            value_wei = 0

        # Convert to ETH
        value_eth = value_wei / 1e18

        # Apply filters
        if self.min_value_wei is not None and value_wei < self.min_value_wei:
            return
        if self.max_value_wei is not None and value_wei > self.max_value_wei:
            return
        if self.tracked_addresses:
            to_match = to_addr.lower() if to_addr else ""
            from_match = from_addr.lower() if from_addr else ""
            if to_match not in self.tracked_addresses and from_match not in self.tracked_addresses:
                return

        gas_price = tx.get("gasPrice", 0)
        if isinstance(gas_price, str):
            gas_price = int(gas_price, 16)

        gas = tx.get("gas", 0)
        if isinstance(gas, str):
            gas = int(gas, 16)

        self._stats["txs_matched"] += 1

        # The 'to' address is often the contract being called
        # (e.g., a DEX router, a token contract, etc.)
        # We'll set it as contract_address for contract verification checks.
        # If the 'to' field is empty, it's a contract deployment.
        tx_contract = to_addr if to_addr else None

        event = TransactionEvent(
            chain=self.name,
            chain_id=self.chain_id,
            tx_hash=tx.get("hash", ""),
            block_number=tx.get("blockNumber"),
            block_hash=tx.get("blockHash"),
            from_address=from_addr,
            to_address=to_addr,
            value=round(value_eth, 6),
            value_currency=self.currency,
            gas_price=gas_price,
            gas_used=gas,
            status="pending" if is_pending else "confirmed",
            event_type="transaction",
            contract_address=tx_contract,
            data={
                "input": tx.get("input", "")[:50],
                "nonce": tx.get("nonce"),
                "r": tx.get("r", ""),
            },
        )
        await self.emit_async(event)

    async def _handle_log(self, log: dict) -> None:
        """Process a log event (e.g., ERC-20 Transfer)."""
        topics = log.get("topics", [])
        if not topics:
            return

        # Check if this is an ERC-20 Transfer event
        if topics[0] == ERC20_TRANSFER_TOPIC:
            # Topics are 32-byte hex strings ("0x" + 64 hex chars)
            # The actual address is the last 20 bytes (40 hex chars)
            from_addr = AsyncWeb3.to_checksum_address("0x" + topics[1][-40:]) if len(topics) > 1 else ""
            to_addr = AsyncWeb3.to_checksum_address("0x" + topics[2][-40:]) if len(topics) > 2 else ""

            data_hex = log.get("data", "0x0")
            try:
                value = int(data_hex, 16) / 1e18
            except (ValueError, TypeError):
                value = 0

            token_addr = log.get("address", "")

            if self.min_value_wei is not None and int(data_hex, 16) < self.min_value_wei:
                return
            if self.tracked_tokens and token_addr.lower() not in self.tracked_tokens:
                return

            self._stats["txs_matched"] += 1

            event = TransactionEvent(
                chain=self.name,
                chain_id=self.chain_id,
                tx_hash=log.get("transactionHash", ""),
                block_number=log.get("blockNumber"),
                from_address=from_addr,
                to_address=to_addr,
                value=round(value, 6),
                value_currency="TOKEN",
                event_type="transfer",
                contract_address=token_addr,  # Le token contract (central)
                data={
                    "token_contract": token_addr,
                    "log_index": log.get("logIndex"),
                },
            )
            await self.emit_async(event)
