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
      PrismReentrancyExploit.sol     # PrismHook-specific exploit
      AIDogeExploit.sol              # AIDoge-specific exploit
      UniversalExploit.sol           # Universal exploit: 18/20 attack types in one contract
    scripts/
      deploy_and_exploit.js          # Full reentrancy attack demo
      test_campaign_reentrancy.js    # CampaignWrapper CEI validation
      test_cei_reentrancy.js         # Combined validation suite
      test_simple_withdraw.js        # Sanity check
      test_fork_exploit.js           # Universal fork exploitation script
    hardhat.config.js                # Hardhat config (Solidity 0.8.20)
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

## 3. BSC Compatibility (extraData)

Use raw RPC polling fallback for BSC:
```python
resp = await w3.provider.make_request("eth_getBlockByNumber", [hex(number), False])
block = resp["result"]
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

### Exploitability Validation (20 types)

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
| Contracts in DB | **23 007** |
| Verified contracts | **923** |
| Total findings | **4 685** |
| Exploitable | **3 015** |
| Hardhat tests run | **18** (configured via `exploit/` dir) |
| Confirmed exploits | **0** |
| Pending Hardhat tests | **~2 997** (force mode active: testing ALL regardless of balance) |
| Chains active | **6** (ETH, BSC, Arbitrum, Optimism, Avalanche, Polygon) |
| Vulnerabilities scanned | **29** (20 base + 9 OpenZeppelin) |

### Top Finding Types (exploitable)
1. Potential Reentrancy
2. Delegatecall to Variable Address
3. Unprotected Initializer
4. Unprotected Withdraw/Claim Function
5. TX Origin Authorization

### --force-hardhat Mode
- Added CLI flag `--force-hardhat` to bypass balance threshold (0.001)
- Periodic Hardhat validation every 120s for existing contracts
- `run_forever.sh` auto-restart on crash (infinite loop, no git push)

## 11. Project Evolution

### Built in this session
1. Vulnerability scanner expanded from 10 → 20 Solidity patterns
2. UniversalExploit.sol — single contract for 18/20 attack types
3. test_fork_exploit.js — generic fork exploitation script
4. hardhat_fork_tester.py — Python orchestrator for fork testing
5. scan_bsc_recent.py — 100-block BSC deployment scanner
6. scan_bsc_500.py — 500-block BSC bulk scanner + auto exploit pipeline
7. pool_scanner.py — DEX pool scanner via DEX Screener (PancakeSwap, Thena on BSC)
8. pool_scanner.py --all mode — scan ALL pools without filter + live feedback
9. pool_scanner.py --audit-local — systematic Hardhat fork test on each contract
10. First --all scan: 136 pools, 126 scanned, 43 INTERESSANTS (Velodrome/Optimism)
11. All .md files updated with consolidated stats (2 340 contracts, 0 confirmed)
12. Discovery: 100% false positive rate on contracts with balance (ERC20 memecoins)

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
