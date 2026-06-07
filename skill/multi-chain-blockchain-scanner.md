# Skill: Multi-Chain Blockchain Transaction Scanner (Python)

## 1. Architecture

### Pattern: Modular async scanners with BaseScanner ABC
- `BaseScanner` (abstract): WebSocket lifecycle, auto-reconnect with exponential backoff, stats, event emission
- `EVMScanner`: Ethereum, Polygon, BSC, Arbitrum (web3.py v7 async)
- `BitcoinScanner`: Bitcoin via mempool.space WebSocket API
- `SolanaScanner`: Solana via solana.py WebSocket
- `ScannerOrchestrator`: Starts/stops all scanners, routes events, manages display
- `DisplayManager`: Rich terminal output (must be ASCII-safe on Windows)
- `TransactionFilter`: Address/value/pattern filtering

### Project structure
```
blockchain_scanner/
  config.yaml              # YAML config (free public endpoints by default)
  main.py                  # CLI entry point (argparse)
  scanner/
    base.py                # BaseScanner ABC
    evm_scanner.py         # EVM chains
    bitcoin_scanner.py     # Bitcoin
    solana_scanner.py      # Solana
    orchestrator.py        # Scanner lifecycle manager
  filters/
    filters.py             # Transaction filters
  output/
    display.py             # Terminal display
```

## 2. web3.py v7 Async API (Critical)

### Problem
`Web3.AsyncWebsocketProvider` does NOT exist in web3.py v7.

### Solution
```python
from web3 import AsyncWeb3
from web3.providers.persistent import WebSocketProvider

# Correct connection pattern:
provider = WebSocketProvider(
    "wss://ethereum.publicnode.com",
    websocket_kwargs={"ping_interval": 30},  # NO max_interval on Windows
)
w3 = AsyncWeb3(provider)
await provider.connect()  # Must explicitly connect

# Verify:
await w3.is_connected()
block_num = await w3.eth.block_number
chain_id = await w3.eth.chain_id

# Subscribe:
sub_id = await w3.eth.subscribe("newHeads")
sub_id = await w3.eth.subscribe("logs", {"topics": [SIGNATURE_HASH]})

# Listen:
async for response in w3.socket.process_subscriptions():
    # response is a dict with "result" or "params.result"
    ...

# Raw RPC (bypasses formatters):
resp = await w3.provider.make_request("eth_blockNumber", [])
block_num = int(resp["result"], 16)
```

### What NOT to do
- `Web3.AsyncWebsocketProvider` ❌ (doesn't exist)
- `websocket_kwargs={"max_interval": None}` ❌ (crashes on Windows)
- `w3 = Web3(...)` ❌ (use `AsyncWeb3`)
- `w3.eth.get_block(number)` ❌ (may fail on BSC's extraData)

## 3. BSC Compatibility (extraData)

### Problem
BSC puts non-standard validator signatures in the block `extraData` field. web3.py's BlockData formatter throws:
`Could not format invalid value '0x...' as field 'extraData'`

This kills both `process_subscriptions()` AND `eth.get_block()`.

### Solution: Raw RPC polling fallback
```python
# Instead of: block = await w3.eth.get_block(number)  # crashes on BSC
resp = await w3.provider.make_request(
    "eth_getBlockByNumber",
    [hex(number), False],  # False = no full tx bodies
)
if not resp.get("error") and resp.get("result"):
    block = resp["result"]  # Raw dict, no formatting
```

### Important: Initialize last_block to current block
```python
# DON'T: last_block = 0  # Will try to fetch 100M+ historical blocks
init_resp = await w3.provider.make_request("eth_blockNumber", [])
last_block = int(init_resp["result"], 16)  # Start from current block
```

### Dynamic polling intervals by chain
```python
if chain_id == 56:      # BSC:    3s blocks
    interval = 3
elif chain_id == 42161: # Arbitrum: 0.25s blocks
    interval = 1
elif chain_id == 137:   # Polygon: 2s blocks
    interval = 3
else:                   # Ethereum: 12s blocks
    interval = 12
```

## 4. Windows cp1252 Encoding

### Problem
Windows terminal uses cp1252 encoding which does NOT support:
- Emoji (🔗, 🟢, ❌, 📡, ⏳, etc.)  
- Unicode arrows (→)
- Bullets (●, ◌, ○)
- Various Unicode symbols

Rich's `Console()` handles encoding internally but will crash if stdout can't encode the character.

### Solution: ASCII-only output
Replace ALL non-ASCII characters with ASCII equivalents:
```
🔗 → [ ] or not used
🟢 → [ON]
🔴 → [OFF]
📡 → [TX]
⏳ → [MP]
📦 → [BLK]
💸 → [XFR]
🔄 → [ACC]
→ → ->
● → [ON]
❌ → [ERROR]
⚠️ → [WARN]
✅ → [DONE]
🛑 → [!]
```

### For Rich Console
```python
# Simple init is fine since all text is now ASCII:
console = Console()

# DO NOT use: Console(encoding="utf-8")  # TypeError in some Rich versions
# force_terminal=True IS valid in Rich, but not needed with ASCII text
```

### File reading (config.yaml)
```python
# ALWAYS specify encoding on Windows:
with open(path, "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)
```

## 5. RPC Endpoints

### Free Public Endpoints (No API Key)

| Chain | WebSocket Endpoint | Provider |
|:---|:---|:---|
| Polygon | `wss://polygon-bor-rpc.publicnode.com` | PublicNode |
| BSC | `wss://bsc.publicnode.com` | PublicNode |
| Arbitrum | `wss://arbitrum-one-rpc.publicnode.com` | PublicNode |
| Solana | `wss://solana-rpc.publicnode.com` | PublicNode |
| Bitcoin | `wss://mempool.space/api/v1/ws` | mempool.space |

### Infura (API Key Required — Email Only, No Phone)

**Recommended for Ethereum** — Infura's free tier (100k requests/day) is more reliable than PublicNode and supports `eth_getLogs` with client-side filtering.

| Endpoint | URL Format |
|:---|:---|
| WebSocket | `wss://mainnet.infura.io/ws/v3/{PROJECT_ID}` |
| HTTP | `https://mainnet.infura.io/v3/{PROJECT_ID}` |

#### Getting an Infura API Key
1. Go to [infura.io/register](https://infura.io/register) — email only, no phone required
2. Create a new API key → copy the **Project ID** (32 hex chars like `420dca4972c44ff9b72c95c4ac7a0cd1`)
3. If the **"Require API Key Secret for all requests"** setting is enabled in your Infura dashboard, you must also pass the Secret (a long base64 string).

#### Authenticating with API Key Secret

When "Require API Key Secret" is enabled, pass the secret via:

**Option A — HTTP Header (recommended):**
```python
headers = {
    "Content-Type": "application/json",
    "x-infura-api-key-secret": "YOUR_SECRET"
}
resp = httpx.post(f"https://mainnet.infura.io/v3/{PROJECT_ID}", json=payload, headers=headers)
```

**Option B — Query parameter (used in config.yaml):**
```yaml
rpc_http: "https://mainnet.infura.io/v3/{PROJECT_ID}?secret={URL_ENCODED_SECRET}"
```
The secret must be URL-encoded (`/` → `%2F`, `+` → `%2B`).

> **⚠️ Security**: The secret contains `+` and `/` characters which break URL parsing if not encoded. Always URL-encode when using query parameter auth. Prefer the `x-infura-api-key-secret` header method in code.

#### Infura eth_getLogs Limitation (Critical)

Infura's **free tier** blocks `eth_getLogs` requests that include `address` and/or `topics` filters:
```python
# ❌ This returns empty result [] on Infura free tier:
payload = {
    "method": "eth_getLogs",
    "params": [{
        "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",  # Blocked!
        "topics": [ERC20_TRANSFER_TOPIC],  # Blocked!
        "fromBlock": hex(N),
        "toBlock": hex(N),
    }]
}

# ✅ This works — query ALL logs and filter client-side:
payload = {
    "method": "eth_getLogs",
    "params": [{
        # No address, no topics! ← The trick
        "fromBlock": hex(N),
        "toBlock": hex(N),
    }]
}
```

**Limitations of public and free-tier nodes:**
- Rate-limited (no SLA)
- `newPendingTransactions` subscription NOT supported (requires paid Alchemy/QuickNode)
- BSC `newHeads` subscription may fail due to extraData → fall back to polling
- Infura free tier: 100k requests/day, ~720 req/15s burst
- No guarantees on uptime

## 6. Bitcoin via mempool.space WebSocket

### Connection
```python
import websockets
ws = await websockets.connect(
    "wss://mempool.space/api/v1/ws",
    ping_interval=30,
    max_size=5 * 1024 * 1024,
)
```

### NO subscription message needed
mempool.space automatically broadcasts:
- `{"type": "tx", ...}` -> new mempool transaction
- `{"type": "block", ...}` -> new block

Do NOT send `{"action": "init"}` — this is NOT a valid mempool.space API message.

### Mempool tx deduplication
```python
_recent_hashes = set()
_max_cache = 1000

if txid in _recent_hashes:
    return  # Skip duplicates
_recent_hashes.add(txid)
if len(_recent_hashes) > _max_cache:
    _recent_hashes.clear()
```

## 7. Contract Source Code Verification via Etherscan API V2

### Critical: V1 endpoints are deprecated
Etherscan **V1 endpoints** (`api.bscscan.com/api`, `api.etherscan.io/api`) are **deprecated** for new API keys since mid-2026. New V2 keys ONLY work with the V2 endpoint.

### Single endpoint for ALL chains
```python
# V2: single endpoint with chainid parameter
EXPLORER_API_V2_URL = "https://api.etherscan.io/v2/api"

params = {
    "chainid": "56",       # BSC, Ethereum=1, Polygon=137, Arbitrum=42161
    "module": "contract",
    "action": "getsourcecode",
    "address": "0x...",
    "apikey": "YOUR_KEY",
}

# Response format (same as V1):
# {
#   "status": "1",          # "1" = success
#   "message": "OK",
#   "result": [{
#     "SourceCode": "...",  # Empty string if not verified
#     "ContractName": "...",
#     "ABI": "...",         # Empty if not verified
#     "CompilerVersion": "...",
#   }]
# }

# Check verification:
is_verified = bool(result[0].get("SourceCode", "").strip())
```

### Rate limits (free tier)
- **5 calls/second** across all chains
- **100,000 calls/day**
- A single key works for 60+ chains

### Get a free key
- https://etherscan.io/myapikey
- Configure in config.yaml:
```yaml
global:
  explorer_api_key: "YOUR_ETHERSCAN_V2_KEY"
```


## 8. web3.py v7 AttributeDict (Critical)

### Problem
Messages from `w3.socket.process_subscriptions()` contain `web3.datastructures.AttributeDict` objects. In web3.py v7, `AttributeDict` does **NOT** inherit from `dict`, so `isinstance(x, dict)` returns `False`!

### Solution: Use `collections.abc.Mapping`
```python
from collections.abc import Mapping

# DON'T: isinstance(result, dict)  # FAILS for AttributeDict!
# DO:
if isinstance(result, Mapping):
    # Works for both dict and AttributeDict
    ...
```

### Type hints should use Mapping too
```python
# DON'T: async def _handle_block(self, block: dict) -> None:
# DO (for accuracy):
async def _handle_block(self, block: Mapping) -> None:
    block_num = block.get("number", 0)  # .get() works on both
```

### Block number is a hex string in subscriptions
In subscription results, `block.number` is a hex string (`"0x123456"`), NOT a Python int:
```python
# Subscription message format (from process_subscriptions()):
# {
#   "subscription": "0x...",
#   "result": {  # AttributeDict, not dict!
#     "number": "0x18179b4",  # hex string, not int!
#     "hash": "0x...",
#     ...
#   }
# }

# Convert hex to int:
block_num = block.get("number", 0)
if isinstance(block_num, str) and block_num.startswith("0x"):
    block_num = int(block_num, 16)

# Detection in handle_message:
# Use 'number' in result (dict check), NOT isinstance(number, int)
if "number" in result:
    await self._handle_block(result)
```

### Key differences: subscription vs polling
| Aspect | Subscription (newHeads) | Polling (eth_getBlockByNumber) |
|:---|---:|:---|
| `number` type | Hex string `"0x123"` | Hex string `"0x123"` |
| `transactions` | Empty list `[]` | List of tx hashes |
| `timestamp` | Present | Present |
| Data type | `AttributeDict` | Plain `dict` |
| Format errors | None | Can fail on BSC extraData |


## 9. ERC-20 Transfer Event Parsing

### Correct address extraction from topics
```python
ERC20_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"  # ← CORRECT! (a at pos 46)

# Topics are 32-byte hex strings: "0x" + 64 hex chars
# The actual address is the LAST 20 bytes (40 hex chars)
from_addr = AsyncWeb3.to_checksum_address("0x" + topics[1][-40:])
to_addr = AsyncWeb3.to_checksum_address("0x" + topics[2][-40:])

# Don't use: "0x" + topics[1][26:]  # Wrong! Includes zero padding
```

## 10. Auto-Reconnect with Exponential Backoff

```python
_reconnect_delay = 1.0   # Start at 1 second
_max_reconnect_delay = 60.0  # Cap at 60 seconds

# In reconnect loop:
await asyncio.sleep(_reconnect_delay)
_reconnect_delay = min(_reconnect_delay * 2, _max_reconnect_delay)

# Reset on successful connect:
_reconnect_delay = 1.0
```

## 11. Graceful Shutdown on Windows

```python
# Signal handlers (add_signal_handler) are NOT supported on Windows.
# Use polling loop instead:
stop_event = asyncio.Event()

try:
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown)
except (NotImplementedError, AttributeError):
    pass  # Windows: falls back to KeyboardInterrupt

# Polling loop (allows KeyboardInterrupt to fire on Windows):
while not stop_event.is_set():
    try:
        await asyncio.wait_for(
            asyncio.shield(stop_event.wait()), timeout=0.5
        )
    except asyncio.TimeoutError:
        continue
    except asyncio.CancelledError:
        break
```

## 12. ERC-20 Transfer Event Detection Bugs

### Bug 1: Indentation Corruption

During a str_replace refactoring, the `_handle_log` method got corrupted:
```python
# BROKEN: return on same line as comment, code indented inside if block
if not topics:
    return            # ERC-20 Transfer
    if topics[0] == ERC20_TRANSFER_TOPIC:  # NEVER EXECUTES (dead code)
```

**Fix:**
```python
# CORRECT: return on its own line, if block at method level
if not topics:
    return

if topics[0] == ERC20_TRANSFER_TOPIC:
    # ... parsing logic
```

**Lesson**: Always double-check indentation after str_replace operations, especially around `return` statements with inline comments.

### Bug 2: ERC20_TRANSFER_TOPIC Typo (Critical — Blocked ALL Transfer Detection)

A **single hex character typo** prevented ALL ERC-20 Transfer events from being detected since day one.

#### The bug
```python
# WRONG (position 46):
ERC20_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4b11628f55a4df523b3ef"
#                                                              ^ b (WRONG!)

# CORRECT (position 46):
ERC20_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
#                                                              ^ a (CORRECT!)
```

The character at index 46 was `b` instead of `a`. This caused the topic comparison `topics[0] == ERC20_TRANSFER_TOPIC` to ALWAYS fail, even though every other character matched.

#### How to diagnose
If the WebSocket subscription succeeds and blocks arrive but **no Transfer events** are detected:

```python
# 1. Fetch logs from a recent block via eth_getLogs (without filter on Infura)
resp = httpx.post(url, json={
    "method": "eth_getLogs",
    "params": [{"fromBlock": hex(N-1), "toBlock": hex(N)}]
})

# 2. Find a Transfer-like log (it has 3+ topics)
for log in logs:
    topics = log.get("topics", [])
    if len(topics) >= 3:
        t0 = str(topics[0])
        # Compare character by character with your constant
        for i, (a, b) in enumerate(zip(t0, OUR_TOPIC)):
            if a != b:
                print(f"Position {i}: API={a} vs CODE={b}")
```

#### Lesson
- Always validate topic hashes against actual API responses when debugging zero-detection issues
- Use character-by-character comparison (not just equality) to find the exact mismatch
- The Keccak-256 hash of `"Transfer(address,address,uint256)"` is well-known and should be verified independently

## 13. Scanner/Display Async Decoupling Pattern

### Problem
Scanners produce events synchronously (from WebSocket callbacks), but display/processing should not block the scanner.

### Solution: asyncio.Queue
```python
# In Orchestrator:
self._event_queue: asyncio.Queue[TransactionEvent] = asyncio.Queue()

# Scanner callback (runs in executor thread via run_in_executor):
def _on_event(self, event: TransactionEvent) -> None:
    self._event_queue.put_nowait(event)

# Event processor (async consumer task):
async def _process_events(self) -> None:
    while True:
        event = await self._event_queue.get()
        # Apply filters, display, save to JSON...

# emit_async in BaseScanner:
async def emit_async(self, event: TransactionEvent) -> None:
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, self.emit, event)
    # Runs callback in thread pool to avoid blocking event loop
```

### Key insight
- Scanner WebSocket listener is async (can't block)
- Callback to orchestrator is synchronous
- `run_in_executor` bridges the gap without blocking the event loop
- `put_nowait` on an unbounded Queue never blocks (no QueueFull)

## 14. Solana Scanner Status

**IMPORTANT**: The Solana scanner (`solana_scanner.py`) is implemented but **NOT tested** on PublicNode's free endpoint (`wss://solana-rpc.publicnode.com`). Known risks:
- `solana.py` v0.36.x WebSocket message format is complex and may differ from the parsing code
- PublicNode may not support `logsSubscribe` with `commitment="processed"`
- Solana's high TPS (thousands of tx/s) may overwhelm the single-threaded event processor

**Recommendation**: Test with a dedicated Solana RPC endpoint before production use.

## 15. Inheritance Pattern for Multi-Chain Scanners

```python
class BaseScanner(ABC):
    def __init__(self, name, config, callback=None):
        self._running = False
        self._ws = None

    @abstractmethod
    async def _connect(self) -> Any: ...
    @abstractmethod
    async def _subscribe(self) -> None: ...
    @abstractmethod
    async def _handle_message(self, msg) -> None: ...

    async def start(self):
        # Creates task with _run_loop (auto-reconnect)
    async def stop(self):
        # Cancels tasks, disconnects

class EVMScanner(BaseScanner):
    async def _connect(self) -> AsyncWeb3:
        provider = WebSocketProvider(...)
        self.w3 = AsyncWeb3(provider)
        await provider.connect()
        return self.w3

    async def _subscribe(self):
        await self.w3.eth.subscribe("newHeads")
        await self.w3.eth.subscribe("logs", ...)

    async def _listen(self):
        async for response in self.w3.socket.process_subscriptions():
            await self._handle_message(response)
```

## 16. HTTP Log Fetching Strategy (eth_getLogs)

### Architecture

The scanner uses **two parallel data streams**:
1. **WebSocket subscription** (real-time): `newHeads` + `logs` for live Transfer events
2. **HTTP polling** (fallback/historical): `eth_getLogs` via httpx for logs the WebSocket may have missed

This separation is essential because:
- web3.py's WebSocket can be blocked by `eth_getLogs` requests
- A separate `httpx.AsyncClient` avoids interfering with the subscription stream
- Different auth methods can be used (Infura's secret header on HTTP only)

```python
async def _get_http_client(self) -> httpx.AsyncClient:
    if not hasattr(self, '_http_client') or self._http_client is None:
        self._http_client = httpx.AsyncClient(
            timeout=30.0,
            headers={"Content-Type": "application/json"},
        )
    return self._http_client
```

### Range: from_block / to_block

Instead of querying a single block per call, the HTTP fallback queries the **most recent fully-indexed block** on every new block:

```python
# In _handle_block (runs on every new block arrival):
to_block = block_num - 1              # Skip current (may not be indexed yet)
from_block = max(to_block, 1)         # Single block
if from_block <= to_block:
    asyncio.create_task(self._fetch_logs_http(from_block, to_block))
```

This queries only the most recent **fully-indexed** block, avoiding overlap between successive calls.

### Client-side filtering (Infura workaround)

Infura free tier blocks `eth_getLogs` with `address`/`topics` filters. The scanner works around this by:
1. Querying **ALL logs** for the block (no `address` or `topics` in payload)
2. Capping at **1000 entries** (covers ~1.3 blocks on Ethereum at ~743 logs/block)
3. Passing each log through `_handle_log` which filters by topic client-side

```python
payload = {
    "method": "eth_getLogs",
    "params": [{
        "fromBlock": hex(from_block),
        "toBlock": hex(to_block),
        # NO address filter, NO topics filter — Infura blocks them!
    }]
}

# Process each log (client-side topic filtering)
for log_entry in log_entries[:1000]:
    await self._handle_log(log_entry)  # Filter by Transfer topic internally
```

### Rate limit handling

```python
except httpx.HTTPStatusError as e:
    if e.response.status_code == 429:
        await asyncio.sleep(1.0)  # Back off on rate limit
    return
except (httpx.TimeoutException, httpx.ConnectError):
    return  # Silently retry on next block
```

### Cleanup on disconnect (critical!)

Failing to close the HTTP client on disconnect will cause **resource leaks** — especially on Windows where asyncio event loops are more sensitive to lingering connections:

```python
async def _disconnect(self) -> None:
    if hasattr(self, '_http_client') and self._http_client is not None:
        await self._http_client.aclose()
        self._http_client = None
    await super()._disconnect()
```

### Log deduplication (_seen_logs)

To avoid processing the same log twice (from overlapping WebSocket + HTTP), a dedup set tracks already-seen logs:

```python
log_key = f"{tx_hash}:{log_index}"
if hasattr(self, '_seen_logs') and log_key in self._seen_logs:
    return
if not hasattr(self, '_seen_logs'):
    self._seen_logs: set[str] = set()
self._seen_logs.add(log_key)
if len(self._seen_logs) > 10000:
    self._seen_logs.clear()  # Prevent unbounded memory growth
```

## 17. YAML Configuration Best Practice

```yaml
# Always document which fields require API keys vs free
# Use comments to explain limitations (e.g., "requires paid plan")
# Enable/disable chains individually
# Keep filter settings per-chain

global:
  log_level: "INFO"
  output_format: "rich"

chains:
  ethereum:
    enabled: true
    rpc_ws: "wss://ethereum.publicnode.com"  # Free, no API key
    # For Infura (more reliable):
    # rpc_ws: "wss://mainnet.infura.io/ws/v3/{PROJECT_ID}"
    # rpc_http: "https://mainnet.infura.io/v3/{PROJECT_ID}?secret={URL_ENCODED_SECRET}"
    track_mempool: false  # Not supported on free public nodes
    track_blocks: true     # Works on free public nodes
```

## 18. Useful Debugging Commands

```bash
# Check web3.py version and available exports
python -c "import web3; print(web3.__version__); print([x for x in dir(web3) if not x.startswith('_')])"

# Check if a provider supports subscriptions
python -c "from web3.providers.persistent import WebSocketProvider; \
           from web3 import AsyncWeb3; \
           w3 = AsyncWeb3(WebSocketProvider('wss://...')); \
           print('socket:', hasattr(w3, 'socket'))"

# Test YAML config loading
python -c "import yaml; c = yaml.safe_load(open('config.yaml', encoding='utf-8')); \
           enabled = [k for k,v in c['chains'].items() if v.get('enabled')]; \
           print(f'{len(enabled)} chains: {enabled}')"

# Check pip packages
python -m pip list | findstr "web3 solana yaml httpx rich"
```
