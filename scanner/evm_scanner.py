"""EVM (Ethereum, Polygon, BSC, Arbitrum) blockchain scanner using web3.py async."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from typing import Any, Optional

import httpx
from web3 import AsyncWeb3
from web3.providers.persistent import WebSocketProvider

from scanner.base import BaseScanner, TransactionEvent

logger = logging.getLogger("scanner.evm")

# ERC-20 Transfer event signature hash
ERC20_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


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

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client for RPC calls (separate from WebSocket)."""
        if not hasattr(self, '_http_client') or self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=30.0,
                headers={"Content-Type": "application/json"},
            )
        return self._http_client

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

        # Monkey-patch the subscription queue to suppress QueueFull during shutdown.
        # web3.py's _message_listener_callback does put_nowait() on an internal queue
        # that fills up when the consumer stops. We catch QueueFull only when the
        # scanner is shutting down; during normal operation we log a warning.
        if hasattr(provider, '_request_processor'):
            rp = provider._request_processor
            if hasattr(rp, '_subscription_response_queue'):
                q = rp._subscription_response_queue
                _orig_put = q.put_nowait
                _scanner = self  # Capture for closure
                def _safe_put_nowait(item):
                    try:
                        _orig_put(item)
                    except asyncio.QueueFull:
                        if not _scanner._running:
                            pass  # Shutdown: safe to discard
                        else:
                            logger.warning(
                                f"[{_scanner.name}] Web3 subscription queue FULL! "
                                "Scanner may be lagging — events are being lost."
                            )
                q.put_nowait = _safe_put_nowait

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

        # Pre-create HTTP client for log fetching (separate from WebSocket)
        self.rpc_http = self.config.get("rpc_http", "")
        await self._get_http_client()

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
                "timestamp": block.get("timestamp"),
                "tx_count": len(block.get("transactions", [])),
                "gas_used": block.get("gasUsed"),
                "gas_limit": block.get("gasLimit"),
            },
        )
        await self.emit_async(event)

        # Fallback: fetch Transfer events via eth_getLogs over HTTP.
        # Uses a separate HTTP connection (not the WebSocket) to avoid
        # interfering with the subscription stream.
        # Queries a range of recent blocks for better coverage:
        # [block_num - 4, block_num - 1] (skips current unindexed block)
        if self.rpc_http and "Transfer" in self.tracked_events:
            # Query only the most recent fully-indexed block to avoid overlap
            to_block = block_num - 1
            from_block = max(to_block, 1)  # Single block query
            if from_block <= to_block:
                task = asyncio.create_task(
                    self._fetch_logs_http(from_block, to_block)
                )
                task.add_done_callback(
                    lambda t: self._tasks.remove(t) if t in self._tasks else None
                )
                self._tasks.append(task)

        # Also scan transactions in this block to find existing contracts
        # Extract unique 'to' addresses from transaction objects
        txs = block.get("transactions", [])
        if txs:
            seen_addrs = set()
            tx_count = 0
            for tx in txs:
                to_addr = tx.get("to")
                if to_addr and to_addr not in seen_addrs:
                    seen_addrs.add(to_addr)
                    tx_count += 1
                    await self._handle_transaction(dict(tx))
                    if tx_count >= 50:
                        break

        # Also check for new contract deployments in this block
        task = asyncio.create_task(
            self._check_new_contracts(block_num)
        )
        task.add_done_callback(
            lambda t: self._tasks.remove(t) if t in self._tasks else None
        )
        self._tasks.append(task)

    async def _fetch_logs_http(self, from_block: int, to_block: int) -> None:
        """Fetch event logs via HTTP RPC and filter for Transfer events client-side.

        Infura's free tier blocks eth_getLogs with address/topic filters.
        We query ALL logs for the block range and let _handle_log filter
        only ERC-20 Transfer events via topic comparison.
        """
        if not self.rpc_http:
            return
        if hasattr(self, '_logs_http_failed'):
            return

        payload = {
            "jsonrpc": "2.0",
            "method": "eth_getLogs",
            "params": [{
                "fromBlock": hex(from_block),
                "toBlock": hex(to_block),
            }],
            "id": from_block,
        }

        try:
            client = await self._get_http_client()
            resp = await client.post(self.rpc_http, json=payload)
            resp.raise_for_status()
            data = resp.json()

            if data.get("error"):
                err_msg = str(data.get("error", {}))
                if "dedicated full node" in err_msg:
                    self._logs_http_failed = True
                    logger.info(f"[{self.name}] eth_getLogs requires a dedicated RPC node.")
                return

            log_entries = data.get("result", [])
            if not log_entries:
                return

            # Process logs — _handle_log filters by Transfer topic internally
            # Cap at 1000 to avoid overwhelming the event loop (~1.3 blocks worth)
            for log_entry in log_entries[:1000]:
                await self._handle_log(log_entry)

            logger.info(
                f"[{self.name}] Processed {min(len(log_entries), 1000)}/{len(log_entries)} logs "
                f"(blocks #{from_block}-#{to_block})"
            )

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                await asyncio.sleep(1.0)
            return
        except (httpx.TimeoutException, httpx.ConnectError):
            return
        except Exception as e:
            logger.debug(f"[{self.name}] eth_getLogs HTTP error: {e}")

    async def _fetch_logs_for_block(self, block_number: int) -> None:
        """Fetch Transfer event logs for a given block via WebSocket make_request.

        Used ONLY in polling mode where there's no subscription stream to
        interfere with. In subscription mode, _fetch_logs_http is used instead.
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
                        f"[{self.name}] eth_getLogs not supported. "
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

    async def _check_new_contracts(self, block_number: int) -> None:
        """Check a block for newly deployed contracts.

        Fetches the block with full transaction objects, finds transactions
        where 'to' is None (contract creation), fetches receipts to get the
        deployed contract address, and emits a 'contract_deploy' event.

        Newly deployed contracts are the most likely to have vulnerabilities
        because they haven't been audited yet.
        """
        if not self.w3 or not self.rpc_http:
            return

        try:
            # Use raw JSON-RPC to avoid web3.py formatting overhead
            raw_resp = await self._rpc_call(
                "eth_getBlockByNumber",
                [hex(block_number), True],  # True = include full tx objects
            )
            if raw_resp.get("error"):
                return

            block = raw_resp.get("result")
            if not block:
                return

            txs = block.get("transactions", [])
            if not txs:
                return

            # Find contract creation transactions (to is None)
            deploy_txs = [tx for tx in txs if tx.get("to") is None]
            if not deploy_txs:
                return

            logger.info(
                f"[{self.name}] Found {len(deploy_txs)} contract deployment(s) in block #{block_number}"
            )

            # Fetch receipts for each deployment to get the contract address
            for tx in deploy_txs:
                try:
                    receipt_resp = await self._rpc_call(
                        "eth_getTransactionReceipt",
                        [tx["hash"]],
                    )
                    if receipt_resp.get("error"):
                        continue

                    receipt = receipt_resp.get("result")
                    if not receipt:
                        continue

                    contract_address = receipt.get("contractAddress")
                    if not contract_address:
                        continue

                    # Check if this is a user-deployed contract (not a factory)
                    # Factory contracts deploy many contracts; we only care about
                    # contracts deployed directly by EOA wallets
                    tx_from = tx.get("from", "")
                    tx_input = tx.get("input", "")

                    logger.info(
                        f"[{self.name}] New contract deployed at {contract_address[:14]}.. "
                        f"by {tx_from[:14]}.. (block #{block_number})"
                    )

                    event = TransactionEvent(
                        chain=self.name,
                        chain_id=self.chain_id,
                        tx_hash=tx["hash"],
                        block_number=block_number,
                        block_hash=block.get("hash", ""),
                        from_address=tx_from,
                        to_address=None,
                        value=None,  # No ETH value in deployment; skip value filter
                        value_currency=self.currency,
                        event_type="contract_deploy",
                        contract_address=contract_address,
                        data={
                            "input_size": len(tx_input) // 2 if tx_input else 0,
                            "deployer": tx_from,
                        },
                    )
                    await self.emit_async(event)

                except Exception as e:
                    logger.debug(f"[{self.name}] Error fetching receipt: {e}")
                    await asyncio.sleep(0.1)  # Rate limit
                    continue

        except Exception as e:
            logger.debug(f"[{self.name}] Error checking contract deployments: {e}")

    async def _disconnect(self) -> None:
        """Close connections gracefully to avoid QueueFull / resource leaks."""
        # 1. Disconnect the WebSocketProvider properly BEFORE the event loop
        #    releases its tasks. This stops the internal message listener and
        #    prevents QueueFull from subscription callbacks during shutdown.
        if self.w3 is not None and hasattr(self.w3, 'provider'):
            try:
                await self.w3.provider.disconnect()
            except Exception:
                pass

        # 2. Close the HTTP client (used for eth_getLogs / RPC calls)
        if hasattr(self, '_http_client') and self._http_client is not None:
            try:
                await self._http_client.aclose()
            except Exception:
                pass
            self._http_client = None

        # 3. Let the base class clean up self._ws
        await super()._disconnect()

    async def _rpc_call(self, method: str, params: list) -> dict:
        """Make an RPC call, preferring HTTP for BSC (fast Binance dataseed).
        
        BSC's PublicNode WebSocket is slow and times out, but the HTTP
        Binance dataseed (bsc-dataseed1.binance.org) is fast and reliable.
        """
        # BSC: always use HTTP (Binance dataseed is fast, WebSocket times out)
        if self.chain_id == 56 and self.rpc_http:
            try:
                client = await self._get_http_client()
                payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": hash(method + str(params)) & 0xFFFF}
                resp = await client.post(self.rpc_http, json=payload, timeout=15.0)
                data = resp.json()
                return data
            except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError, asyncio.TimeoutError):
                pass  # Fall through to WebSocket
        
        # Default: use WebSocket
        return await self.w3.provider.make_request(method, params)

    async def _poll_blocks(self) -> None:
        """Fallback: poll for new blocks using RPC calls.

        Uses raw JSON-RPC instead of web3.py's typed get_block() to avoid
        formatting issues with non-standard block data (e.g. BSC's extraData).
        BSC uses HTTP RPC (Binance dataseed) for speed.
        """
        if not self.w3:
            return

        # Init last_block to current block to avoid re-scanning history
        init_resp = await self._rpc_call("eth_blockNumber", [])
        last_block = int(init_resp["result"], 16) if not init_resp.get("error") else 0
        logger.info(f"[{self.name}] Starting block polling at #{last_block}")

        while self._running:
            try:
                # Use raw JSON-RPC call to avoid web3.py formatter issues
                resp = await self._rpc_call("eth_blockNumber", [])
                if resp.get("error"):
                    logger.warning(f"[{self.name}] RPC error: {resp['error']}")
                    await asyncio.sleep(15)
                    continue

                block_num = int(resp["result"], 16)

                if block_num > last_block:
                    for i in range(last_block + 1, block_num + 1):
                        try:
                            raw_resp = await self._rpc_call(
                                "eth_getBlockByNumber",
                                [hex(i), True],  # True = include full tx objects
                            )
                            if raw_resp.get("error"):
                                continue

                            block = raw_resp["result"]
                            if not block:
                                continue

                            txs = block.get("transactions", [])
                            event = TransactionEvent(
                                chain=self.name,
                                chain_id=self.chain_id,
                                block_number=i,
                                block_hash=block.get("hash", ""),
                                event_type="block",
                                data={
                                    "timestamp": block.get("timestamp"),
                                    "tx_count": len(txs),
                                    "gas_used": block.get("gasUsed"),
                                    "gas_limit": block.get("gasLimit"),
                                },
                            )
                            await self.emit_async(event)

                            # Extract unique contract addresses from transaction 'to' fields
                            # This finds already-deployed contracts being interacted with
                            seen_addrs = set()
                            tx_count = 0
                            for tx in txs:
                                to_addr = tx.get("to")
                                if to_addr and to_addr not in seen_addrs:
                                    seen_addrs.add(to_addr)
                                    tx_count += 1
                                    await self._handle_transaction(dict(tx))
                                    if tx_count >= 50:  # Cap per block to avoid overload
                                        break

                            if seen_addrs:
                                logger.debug(
                                    f"[{self.name}] Block #{i}: {len(txs)} txs, "
                                    f"{len(seen_addrs)} unique contracts"
                                )

                            # Also check for new contract deployments in this block
                            task = asyncio.create_task(
                                self._check_new_contracts(i)
                            )
                            task.add_done_callback(
                                lambda t: self._tasks.remove(t) if t in self._tasks else None
                            )
                            self._tasks.append(task)

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

        # Deduplication: skip if we already processed this log
        tx_hash = log.get("transactionHash", "")
        log_index = log.get("logIndex", "")
        log_key = f"{tx_hash}:{log_index}"
        if hasattr(self, '_seen_logs') and log_key in self._seen_logs:
            return
        if not hasattr(self, '_seen_logs'):
            self._seen_logs: set[str] = set()
        self._seen_logs.add(log_key)
        if len(self._seen_logs) > 10000:
            self._seen_logs.clear()

        # Check if this is an ERC-20 Transfer event
        # Topics can be str (raw) or HexBytes (formatted) in web3.py v7
        topic0 = topics[0]
        if isinstance(topic0, str):
            match = topic0.lower() == ERC20_TRANSFER_TOPIC.lower()
        else:
            match = str(topic0) == ERC20_TRANSFER_TOPIC

        if match:
            # Topics are 32-byte hex strings ("0x" + 64 hex chars)
            # The actual address is the last 20 bytes (40 hex chars)
            from_addr = AsyncWeb3.to_checksum_address("0x" + topics[1][-40:]) if len(topics) > 1 else ""
            to_addr = AsyncWeb3.to_checksum_address("0x" + topics[2][-40:]) if len(topics) > 2 else ""

            data_hex = log.get("data", "0x0")
            # data can be HexBytes or str; convert to int safely
            if hasattr(data_hex, 'hex'):
                raw_value = int(data_hex.hex(), 16)
            elif isinstance(data_hex, str):
                raw_value = int(data_hex, 16) if data_hex.startswith("0x") else int(data_hex, 10)
            else:
                raw_value = 0

            try:
                value = raw_value / 1e18 if raw_value > 0 else 0
            except (ValueError, TypeError):
                value = 0

            token_addr = log.get("address", "")

            # Note: min_value_wei filter is NOT applied to token transfers
            # because tokens have different decimal places (6 for USDC, 18 for most)
            # and the raw value cannot be compared to a wei-based threshold.
            if self.tracked_tokens:
                t_addr = token_addr.lower() if isinstance(token_addr, str) else str(token_addr).lower()
                if t_addr not in self.tracked_tokens:
                    return

            self._stats["txs_matched"] += 1

            event = TransactionEvent(
                chain=self.name,
                chain_id=self.chain_id,
                tx_hash=tx_hash,
                block_number=log.get("blockNumber"),
                from_address=from_addr,
                to_address=to_addr,
                value=round(value, 6),
                value_currency="TOKEN",
                event_type="transfer",
                contract_address=token_addr,  # Le token contract (central)
                data={
                    "token_contract": token_addr,
                    "log_index": log_index,
                },
            )
            await self.emit_async(event)
