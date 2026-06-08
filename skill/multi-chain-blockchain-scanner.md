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
- `SourceCodeVerifier`: Contract source code verification via Etherscan API V2
- `VulnerabilityScanner`: Solidity source code vulnerability analysis (**20 patterns**)
- `Guardian`: 24/7 persistent scanner with SQLite DB, auto-persistence, Hardhat pipeline
- `ForkTester`: Standalone Hardhat fork testing framework (`hardhat_fork_tester.py`)

### Extended project structure
```
blockchain_scanner/
  config.yaml                        # YAML config
  main.py                            # CLI entry point (argparse)
  guardian.py                        # 24/7 scanner + SQLite persistence
  exploit_pipeline.py                # Automated vuln validation pipeline (20 types)
  hardhat_fork_tester.py             # Standalone fork testing framework
  pool_scanner.py                    # DEX pool scanner via DEX Screener API
  scan_bsc_recent.py                 # Scan 100 BSC blocks for new deployments
  scan_bsc_500.py                    # Scan 500 BSC blocks + auto exploit pipeline
  scan_historical.py                 # Scan millions of historical BSC blocks concurrently
  scanner/
    base.py                          # BaseScanner ABC
    evm_scanner.py                   # EVM chains
    bitcoin_scanner.py               # Bitcoin
    solana_scanner.py                # Solana
    orchestrator.py                  # Scanner + vuln scan lifecycle
  analysis/
    vulnerability_scanner.py         # Solidity vuln scanner (20 patterns)
    __init__.py
  filters/
    filters.py                       # Transaction filters
  output/
    display.py                       # Terminal display (vuln output added)
  verify.py                          # Source code verification via Etherscan V2
  exploit/                           # Local Hardhat exploitation demos
    contracts/
      VulnerableBank.sol             # Deliberately vulnerable bank (reentrancy)
      Exploit.sol                    # Reentrancy attack contract
      ExploitV2.sol                  # Debug version with configurable maxRounds
      CampaignVulnerable.sol         # CEI reentrancy reproduction
      CampaignExploit.sol            # CEI exploit with guard-rail
      PrismReentrancyExploit.sol        # PrismHook-specific exploit
      AIDogeExploit.sol                 # AIDoge-specific exploit
      UniversalExploit.sol              # Universal exploit: 28 attack types, 80+ sigs
      PredictionV2OracleManipulator.sol # PredictionV2 oracle manipulation
      PredictionV2ReentrancyExploit.sol # PredictionV2 reentrancy
      PredictionV2TXOriginExploit.sol   # PredictionV2 tx.origin exploit
      PredictionV2DelegatecallExploit.sol # PredictionV2 delegatecall
      PredictionV2TreasuryExploit.sol   # PredictionV2 treasury drain
    scripts/
      deploy_and_exploit.js                  # Full reentrancy attack demo
      test_campaign_reentrancy.js            # CampaignWrapper CEI validation
      test_cei_reentrancy.js                 # Combined validation suite
      test_simple_withdraw.js                # Sanity check
      test_fork_exploit.js                   # Universal fork exploitation (28 attacks)
      test_prediction_v2_all.js              # Master suite PredictionV2
      test_prediction_v2_oracle_manipulation.js
      test_prediction_v2_reentrancy.js
      test_prediction_v2_delegatecall.js
      test_prediction_v2_txorigin.js
      test_prediction_v2_treasury.js
    generated/                               # Dynamically generated test files
    hardhat.config.js                # Hardhat config (Solidity 0.8.20, allowUnlimitedContractSize)
    package.json
    .gitignore
```

## 2. web3.py v7 Async API (Critical)

### Problem
`Web3.AsyncWebsocketProvider` does NOT exist in web3.py v7.

### Solution
```python
from web3 import AsyncWeb3
from web3.providers.persistent import WebSocketProvider

provider = WebSocketProvider(
    "wss://ethereum.publicnode.com",
    websocket_kwargs={"ping_interval": 30},
)
w3 = AsyncWeb3(provider)
await provider.connect()

sub_id = await w3.eth.subscribe("newHeads")
async for response in w3.socket.process_subscriptions():
    ...
```

## 3. BSC Compatibility (extraData) + WebSocketProvider Disconnect

Use raw RPC polling fallback for BSC:
```python
resp = await w3.provider.make_request("eth_getBlockByNumber", [hex(number), False])
block = resp["result"]
```

**Shutdown fix:** Always call `provider.disconnect()` before cleanup + **monkey-patch `put_nowait`** on the subscription queue to catch `asyncio.QueueFull` (suppressed during shutdown, logged as warning during normal ops):
```python
async def _disconnect(self):
    if self.w3 and hasattr(self.w3, 'provider'):
        await self.w3.provider.disconnect()  # Stop internal message listener first
    ...

# In _connect(): monkey-patch the queue to survive QueueFull during shutdown
q = provider._request_processor._subscription_response_queue
_orig = q.put_nowait
q.put_nowait = lambda item: _orig(item) if not queue_full else ...
```

## 4. Windows cp1252 Encoding

Always use ASCII-safe output:
```python
def _s(text: str) -> str:
    return text.encode('ascii', errors='replace').decode('ascii')
```

## 5. RPC Endpoints

| Chain | Endpoint | Provider |
|:---|:---|:---|
| BSC HTTP | `https://bsc-dataseed1.binance.org` | Binance |
| BSC WS | `wss://bsc.publicnode.com` | PublicNode |

## 6. Contract Source Code via Etherscan API V2

```python
EXPLORER_API_V2_URL = "https://api.etherscan.io/v2/api"
# chainid=56 for BSC, 1 for Ethereum
```

## 7. Solidity Vulnerability Scanner — 20 Types

### Complete Vulnerability Table

| ID | Vulnerability | Severity | Description |
|:---|:---|---:|:---|
| `reentrancy` | Reentrancy (state change AFTER external call) | CRITICAL | `.call{value:}` before state update |
| `selfdestruct` | Contract can be destroyed | CRITICAL | `selfdestruct`/`suicide` without ACL |
| `delegatecall` | Code execution in caller context | CRITICAL | Dynamic `delegatecall` target |
| `tx-origin` | tx.origin authorization | HIGH | `tx.origin` used for auth — phishing |
| `unprotected-withdraw` | Withdraw without ACL | HIGH | Withdraw/claim without access control |
| `unprotected-init` | Initializer without modifier | HIGH | `initialize()` callable multiple times |
| `unchecked-call` | Unchecked external call result | MEDIUM | `.call()` return value not verified |
| `integer-overflow` | Arithmetic without SafeMath (pre-0.8) | MEDIUM | No overflow protection on pre-0.8 |
| `gas-loop` | Unbounded loop over dynamic array | MEDIUM | DOS via gas exhaustion |
| `arbitrary-from` | transferFrom with user-controlled 'from' | MEDIUM | `from` parameter not validated |
| `flash-loan` | Flash loan susceptibility | HIGH | DEX swap without access control |
| `oracle-manipulation` | Oracle price manipulation | HIGH | Spot price (getReserves) instead of TWAP |
| `slippage-deadline` | Missing slippage / deadline | HIGH | Zero slippage or no deadline — MEV |
| `force-feed-eth` | Force-fed ETH manipulation | MEDIUM | `address(this).balance` via selfdestruct |
| `erc20-return` | ERC20 return value unchecked | MEDIUM | `transfer()` return not checked (USDT) |
| `signature-replay` | Signature replay attack | HIGH | `ecrecover` without chainId/nonce |
| `rounding-error` | Division before multiplication | MEDIUM | Precision loss due to rounding |
| `storage-collision` | Storage collision in proxy | HIGH | Upgradeable without `__gap` |
| `timestamp-manipulation` | Block timestamp manipulation | MEDIUM | `block.timestamp` in critical logic |
| `ownership-renounce` | Ownership renouncement | MEDIUM | `renounceOwnership()` without recovery |

### Reentrancy Detection Strategy
- Find external calls with value (`.call{value:...}()`, `.send()`)
- Skip `.transfer()` (limited to 2300 gas)
- Check `nonReentrant` modifier
- Look for state changes BEFORE the external call (CEI violation)
- CRITICAL if state change before call, HIGH if call without modifier

### Key Scanner Limitation

The scanner detects **code patterns** but does **not** understand context:
- `onlyOwner` modifiers: functions are flagged but actually protected
- Proxy patterns (EIP-1967): `delegatecall` is intentional
- OpenZeppelin libraries: `Ownable`, `ReentrancyGuard` are audited standards
- **Result:** ~85% false positive rate on audited contracts, **100% on ERC20 memecoins with balance**

## 8. Exploit Pipeline

### Usage
```bash
python exploit_pipeline.py --address 0x... --chain bsc
python exploit_pipeline.py --live --chains bsc,ethereum
python exploit_pipeline.py --batch addresses.txt
```

### Exploitability Validation (20 types) — + Proxy Fallback

When `SourceCode` is empty (common with proxy contracts), the pipeline now detects `Proxy`/`Implementation` fields from Etherscan API and auto-fetches the implementation source.

| Finding Type | Exploitable? | Condition |
|:---|:---|---:|
| Reentrancy | YES | Solidity < 0.8 |
| Reentrancy | YES | Solidity >= 0.8 WITH unchecked {} |
| Reentrancy | PARTIAL | Solidity >= 0.8 (CEI on bool — not arithmetic) |
| Selfdestruct | YES | Without ACL |
| Delegatecall | YES | Dynamic target |
| Flash Loan | YES | Swap function without access control |
| Oracle Manipulation | YES | Uses getReserves() without TWAP |
| Slippage/Deadline | YES | amountOutMin = 0 or no deadline |
| ERC20 Return | YES | transfer() call without require(success) |
| Signature Replay | YES | ecrecover without chainId or nonce |
| Storage Collision | YES | Upgradeable contract without __gap |

### Key Discovery: Solidity >=0.8 Blocks Underflow Reentrancy
`balances[msg.sender] -= amount` reverts with `panic(0x11)` on underflow in 0.8+.
In < 0.8, it wraps around (0 - 1 = 2^256 - 1), allowing the exploit.

## 9. Hardhat Fork Testing Framework

### UniversalExploit.sol
Single contract testing **18 out of 20** attack types (excludes `tx-origin` and `signature-replay` which require phishing/scenario setup):
- Reentrancy (CEI), Selfdestruct, Delegatecall, Unprotected Withdraw, Unprotected Init
- Unchecked Call, Integer Overflow, Gas Loop, Arbitrary transferFrom
- Flash Loan, Oracle Manipulation, Slippage/Deadline, Force-Fed ETH
- ERC20 Return, Rounding Error, Storage Collision, Timestamp, Ownership Renounce

### Fork Test Flow
```
1. Fork chain at latest block
2. Impersonate target contract owner
3. Deploy UniversalExploit
4. For each attack type: attack → check balance → log result
5. Report drained ETH (if any)
```

### Usage
```bash
# Via Python orchestrator
python hardhat_fork_tester.py --target 0x... --chain arbitrum

# Direct Hardhat
cd exploit
npx hardhat compile
npx hardhat run scripts/test_fork_exploit.js --network hardhat 0x... https://rpc 0.05
```

## 10. Guardian 24/7 Stats (08/06/2026)

| Metric | Value |
|:---|---|
| Contracts in DB | **24 945** |
| Verified contracts | **985** |
| Total findings | **7 365** |
| Exploitable | **4 407** |
| Hardhat tests run | **116** (55 batch + 5 PredictionV2 + 1 dynamique + 55 backfill-force) |
| Confirmed exploits | **0** |
| Batch test result | 55 contracts, 0 confirmed |
| Chains active | **6** (ETH, BSC, Arbitrum, Optimism, Avalanche, Polygon) |
| Vulnerabilities scanned | **29** (20 base + 9 OpenZeppelin) |

### Nouveaux outils (Session 5)

| Outil | Description | Commande |
|:---|---|:---|
| **`dynamic_test_generator.py`** | Génère des tests JS Hardhat depuis les findings DB | `python hardhat_fork_tester.py --dynamic` |
| **PredictionV2 exploits** | 5 contrats + 6 scripts pour PancakeSwap Prediction | `--specialized prediction-v2` |
| **UniversalExploit v2** | 28 attaques, 80+ signatures DeFi | Via `test_fork_exploit.js` |
| **Batch mode** | Teste TOUS les contrats avec balance | `python hardhat_fork_tester.py --batch` |

### Top Finding Types (exploitable)
1. Potential Reentrancy
2. Delegatecall to Variable Address
3. Unprotected Initializer
4. Unprotected Withdraw/Claim Function
5. TX Origin Authorization

### Backfill-Hardhat Mode
- `python guardian.py --backfill --backfill-hardhat` — full pipeline from DB to Hardhat confirmation
- `python guardian.py --backfill --force` — force re-scan (delete + recreate findings)
- `python guardian.py --backfill --backfill-limit 10` — limit to N contracts
- `python guardian.py --backfill --backfill-hardhat --backfill-feedback 10` — progress feedback every N contracts
- `python guardian.py --backfill --force --backfill-hardhat` — full pipeline with force re-scan + Hardhat validation

### Auto-Stop Modes (NEW)
- `--stop-on detected` — stop on first HIGH/CRITICAL (default)
- `--stop-on confirmed` — stop only after pipeline confirms
- `--stop-on none` — never auto-stop (manual)

### Performance: ×20 Optimization
- `validate_contract()` batches all findings of a contract into 1 fork + 1 compile + 1 Hardhat run
- Old: ~60s/finding → New: ~3s for 1 contract with 1 finding exploitable
- `validate_for_addresses()` and `validate_all_pending()` group by contract automatically
- `validate_finding()` preserved for backward compatibility

### Bugfixes: EOA Filter, Cache Source, RPC URLs
- **EOA filter**: `eth_getCode` before analysis — prevents false positives on EOA addresses
- **Source cache**: passes `--cached-source` via temp file to avoid duplicate Etherscan API calls (inconsistent between calls)
- **RPC URLs**: uses `config.yaml` RPC URLs (with Infura secret) instead of hardcoded `CHAIN_REGISTRY`
- **`getLatestBlock()` fix**: uses `ethers.JsonRpcProvider(url)` direct instead of `hre.network.provider` before fork initialization

### --force-hardhat Mode
- Added CLI flag `--force-hardhat` to bypass balance threshold (0.001)
- Periodic Hardhat validation every 120s for existing contracts
- `run_forever.sh` auto-restart on crash (infinite loop, no git push)

## 11. Project Evolution

### Built in Session 7
1. `--backfill --force --backfill-hardhat`: Full pipeline with force re-scan + Hardhat validation
2. `--backfill-feedback`: Progress tracking (processed, findings, exploitables, errors, ETA)
3. Backfill force + Hardhat validated on 5 BSC contracts: 33 findings tested, 0 confirmed
4. Guardian stats updated: 7,365 findings, 4,407 exploitables, 116 Hardhat tests
5. All `.md` files updated with latest changes

### Built in Session 6
1. `--backfill-hardhat`: Full pipeline from DB to Hardhat confirmation
2. `--stop-on detected|confirmed|none`: 3 auto-stop modes for main.py
3. `--backfill` mode in guardian.py: re-scan all verified contracts from DB
4. `validate_contract()`: ×20 performance optimization (1 fork/contract)
5. EOA filter: `eth_getCode` before scanning to prevent cross-chain false positives
6. Source cache: avoid duplicate Etherscan API calls via temp file
7. RPC URL fix: use config.yaml URLs (with Infura secret) for Hardhat fork
8. `getLatestBlock()` fix: use direct JsonRpcProvider instead of Hardhat provider
9. `validate_for_addresses()`: scoped validation for backfill mode
10. All `.md` files updated with latest changes

### Built in Session 5
1. UniversalExploit v2: 28 attack types, 80+ signatures
2. 5 PredictionV2 exploit contracts + 6 JS scripts
3. dynamic_test_generator.py
4. Batch mode: 55 contracts tested, 0 confirmed
5. Hardhat config: allowUnlimitedContractSize
6. Fix TDZ in test_fork_exploit.js

### Built in Session 4
1. Vulnerability scanner expanded from 10 → 20 Solidity patterns
2. UniversalExploit.sol — single contract for 18/20 attack types
3. test_fork_exploit.js — generic fork exploitation script
4. hardhat_fork_tester.py — Python orchestrator for fork testing
5. scan_bsc_recent.py — 100-block BSC deployment scanner
6. scan_bsc_500.py — 500-block BSC bulk scanner + auto exploit pipeline
7. pool_scanner.py — DEX pool scanner via DEX Screener
8. pool_scanner.py --all mode — scan ALL pools
9. pool_scanner.py --audit-local — systematic Hardhat fork test
10. First --all scan: 136 pools, 126 scanned
11. Discovery: 100% false positive rate on contracts with balance
12. Proxy fallback in exploit_pipeline

### Older Changes

### Concrete Validation vs Pattern Detection
Scanner finds patterns, not vulnerabilities. Key examples:
- WETH9: `withdraw()` without onlyOwner flagged as HIGH — but CEI pattern respected, uses `.transfer()`
- Nola/Smolcoin/PinLink: 41 exploitables flagged — but all functions behind `onlyOwner`
- Lido stETH: `delegatecall` flagged as CRITICAL — but it's an intentional EIP-1967 proxy
- **~85% of findings on audited contracts are false positives**

### Pool Scanner Modes (NEW)

| Flag | Description |
|:---|:---|
| `--all` / `-a` | Scan ALL pools returned by DEX Screener (no TVL filter, no count limit) |
| `--min-tvl X` / `-t X` | Only scan pools with TVL >= $X USD |
| `--audit-local` / `-l` | Run Hardhat fork test on each scanned contract with exploitable findings |
| `--top N` / `-n N` | Max pools per DEX (default: 5, ignored with --all) |

**Live feedback**: Each pool result printed immediately with `[LIVE]` tag, verdict, findings count.

**Hardhat integration**: `_audit_hardhat()` method lazy-inits HardhatForkTester, pre-compiles contracts once, then runs fork tests with 240s timeout per contract. Skips standard clones (UniswapV2Pair etc.) automatically.

**First --all scan results (07/06/2026):** 136 pools found, 126 scanned, 43 INTERESSANTS (Velodrome/Optimism), 60 false positives (QuickSwap/Polygon clones).

### BSC-Specific Scanning Tools

| Tool | Description | RPC |
|:---|:---|:---|
| `scan_bsc_recent.py` | Scan 100 recent BSC blocks for new contract deployments | `bsc-dataseed1.binance.org` |
| `scan_bsc_500.py` | Scan 500 BSC blocks, auto-verify + exploit pipeline | `bsc-dataseed1.binance.org` |
| `pool_scanner.py` | Scan PancakeSwap/Thena BSC pools via DEX Screener API | Etherscan V2 chainid=56 |
| `hardhat_fork_tester.py` | Fork BSC at latest block, test exploits | `bsc-dataseed1.binance.org` |

All BSC tools use free public RPC — no API key required for block scanning.

### Scanning Results by Chain
| Chain | Contracts | Verified | Balance |
|:---|---:|---:|:---:|
| Ethereum | 1 257 | 112 | 261.47 ETH |
| Arbitrum | 572 | 254 | 3.27 ETH |

### Key Lesson
Always validate findings empirically. Pipeline gives theoretical analysis (Solidity version, unchecked blocks, access control), but fork testing on Hardhat is the only way to confirm exploitability. The scanner detects code patterns — the human (or a smarter AI) must interpret context.

### CEI Reentrancy Validation

**CampaignWrapper** (0x8a56c6be..) — 7 HIGH findings, 1 MEDIUM. Validated empirically on reproduction:
- Created CampaignVulnerable.sol (reproduces `.call{value:}` BEFORE state update)
- Created CampaignExploit.sol (re-enters via `receive()` before `hasClaimed` is set)
- **5 rounds of reentrancy confirmed** — 5 ETH drained from 5 ETH
- **But false positive on real contract:** `_refund` is `private` + `nonReentrant` at top level

**Key discovery:** CEI reentrancy on bool flags works in Solidity >=0.8 because:
- `!hasClaimed[user]` is NOT arithmetic — no underflow protection applies
- State update (bool = true) happens AFTER `.call{value:}`
- Check passes every time during reentrancy because state hasn't been updated yet

**Fix for >=0.8 reentrancy:** Use `ReentrancyGuard` modifier, NOT just relying on underflow protection.
