# Multi-Chain Blockchain Transaction Scanner

Real-time monitoring of transactions and blocks across **6 blockchains** — Ethereum, Polygon, BSC, Arbitrum, Solana, and Bitcoin. No API keys required for basic block monitoring (free public endpoints). Optional Etherscan API key enables contract source code verification and vulnerability scanning.

## Quick Start

```bash
# 1. Install dependencies
cd blockchain_scanner
pip install -r requirements.txt

# 2. Configure (optional — works out of the box)
# Edit config.yaml to enable/disable chains or adjust filters

# 3. Launch the scanner
python main.py
```

## Usage

### Basic commands

| Command | Description |
|:---|:---|
| `python main.py` | Scan all enabled chains |
| `python main.py --chains ethereum` | Scan Ethereum only |
| `python main.py --chains ethereum,bsc,bitcoin` | Scan specific chains |
| `python main.py --list-chains` | List configured chains without scanning |
| `python exploit_pipeline.py --address 0x... --chain ethereum` | Analyze a contract's vulnerabilities |
| `python scan_bsc_recent.py` | Scan 100 recent BSC blocks for new contract deployments |
| `python scan_bsc_500.py` | Scan 500 BSC blocks + auto-run exploit pipeline on verified contracts |
| `python pool_scanner.py --chains bsc` | Scan DEX pools on BSC (PancakeSwap, Thena) for vulnerabilities |
| `cd exploit && npx hardhat run scripts/deploy_and_exploit.js` | Run classic reentrancy attack demo |
| `cd exploit && npx hardhat run scripts/test_campaign_reentrancy.js` | Run CampaignWrapper CEI reentrancy validation |
| `cd exploit && npx hardhat run scripts/test_cei_reentrancy.js` | Run combined reentrancy validation suite |
| `cat findings/README.md` | Browse the findings catalog |

### Scanner options

| Option | Description |
|:---|---:|
| `--chains X,Y,Z` | Comma-separated list of chains to scan |
| `-v` / `--verbose` | Enable DEBUG logging |
| `--list-chains` | List available chains and exit |
| `--format rich\|json\|both` | Output format |
| `-j FILE` / `--json FILE` | Export transactions to JSON file |
| `-c FILE` / `--config FILE` | Custom config file path |
| `--version` | Show version and exit |

### Exploit pipeline options

| Option | Description |
|:---|---:|
| `--address ADDR` / `-a` | Contract address to analyze |
| `--chain CHAIN` / `-c` | Chain: `ethereum`, `bsc`, `polygon`, `arbitrum` (default: bsc) |
| `--api-key KEY` / `-k` | Etherscan API V2 key |

### Guardian (24/7 scanner)

| Command | Description |
|:---|:---|
| `python guardian.py` | Start the 24/7 guardian scanner |
| `python guardian.py --status` | Show DB stats (contracts, findings, balance) |
| `python guardian.py --health` | Check if guardian process is running |

### Fork tester

| Command | Description |
|:---|:---|
| `python hardhat_fork_tester.py --target 0x... --chain bsc` | Test exploits on a forked BSC contract |
| `python hardhat_fork_tester.py --target 0x... --chain arbitrum` | Test exploits on a forked contract |
| `cd exploit && npx hardhat run scripts/test_fork_exploit.js --network hardhat <address> <rpc> <funding>` | Manual fork test |

### BSC Block Scanners (NEW)

Two dedicated scanners for Binance Smart Chain block analysis:

| Command | Description |
|:---|:---|
| `python scan_bsc_recent.py` | Scan 100 recent BSC blocks for new contract deployments |
| `python scan_bsc_500.py` | Scan 500 BSC blocks, auto-verify contracts, run exploit pipeline on verified |

These scripts:
- Fetch blocks via `bsc-dataseed1.binance.org` (free public RPC)
- Detect contract deployments (`to=null` transactions) via transaction receipts
- Check verification status via Etherscan V2 API (chainid=56)
- Auto-run `exploit_pipeline.py` on verified contracts
- Provide ASCII-safe output for Windows cp1252 terminals

### Pool Scanner (NEW)

Scan DEX pools with TVL via DEX Screener API. Supports BSC (PancakeSwap, Thena), Polygon (QuickSwap), Optimism (Velodrome), Ethereum (Uniswap, SushiSwap, Balancer, Curve).

| Command | Description |
|:---|:---|
| `python pool_scanner.py` | Scan top 5 pools per DEX across all chains |
| `python pool_scanner.py --chains bsc` | Scan BSC pools only (PancakeSwap, Thena) |
| `python pool_scanner.py --daemon` | Continuous mode — re-scan every 30 minutes |

### Examples

```bash
# Ethereum only — best for testing Transfer events + contract verification
python main.py --chains ethereum

# Bitcoin mempool — watch pending transactions in real-time
python main.py --chains bitcoin

# Ethereum + BSC + Polygon simultaneously
python main.py --chains ethereum,bsc,polygon

# With JSON export
python main.py --chains ethereum -j transactions.json --format both

# Enable debug logs
python main.py --chains ethereum -v
```

## Supported Chains

| Chain | Mode | Endpoint | Blocks |
|:---|---:|:---|---:|
| **Ethereum** | WebSocket subscription | `wss://ethereum.publicnode.com` | ~5/min |
| **Polygon** | WebSocket subscription | `wss://polygon-bor-rpc.publicnode.com` | ~30/min |
| **BSC** | Polling (no subscriptions) | `wss://bsc.publicnode.com` | ~125/min |
| **Arbitrum** | WebSocket subscription | `wss://arbitrum-one-rpc.publicnode.com` | ~240/min |
| **Solana** | WebSocket subscription | `wss://solana-rpc.publicnode.com` | High TPS |
| **Bitcoin** | WebSocket (mempool.space) | `wss://mempool.space/api/v1/ws` | Real-time |

> **Note**: All endpoints are **free public nodes** from [PublicNode.com](https://publicnode.com) (EVM/Solana) and [mempool.space](https://mempool.space) (Bitcoin). No API keys required for basic scanning. Rate limits apply.

## Features

### Real-time block monitoring
- New blocks appear as `[BLK] [Ethereum] New Block #12345678`
- Block arrival rate varies by chain (Ethereum ~5/min, BSC ~125/min)
- Bitcoin blocks detected via mempool.space WebSocket

### ERC-20 Transfer event detection
- Automatically subscribes to `Transfer` events on EVM chains
- Displays `[XFR]` lines with amount, from/to addresses, and contract address
- Configurable minimum value filters per chain

### Contract source code verification
- Detects contract addresses in Transfer events and checks if they're **verified** on the block explorer
- Displays `[verify] 0x... -> VERIFIED` or `NOT VERIFIED` alongside transactions
- Uses Etherscan API V2 — a single API key works for **all 60+ chains**
- Results cached in memory to avoid redundant API calls

### Solidity Vulnerability Scanner (NEW)
Analyzes verified smart contract source code for **20 types of security vulnerabilities**:

| Vulnerability | Severity | Description |
|:---|---:|:---|
| Reentrancy | CRITICAL | State change AFTER external call — fund theft |
| Selfdestruct | CRITICAL | Contract destruction without access control |
| Delegatecall | CRITICAL | Dynamic target — contract takeover |
| TX Origin | HIGH | tx.origin used for auth — phishing risk |
| Unprotected Withdraw | HIGH | Withdraw/claim without access control |
| Unprotected Init | HIGH | Initializer callable multiple times |
| Unchecked Call | MEDIUM | External call result not verified |
| Integer Overflow | MEDIUM | Arithmetic without SafeMath (pre-0.8) |
| Gas Loop | MEDIUM | Unbounded loop over dynamic array |
| Arbitrary transferFrom | MEDIUM | User-controlled 'from' without allowance |
| Flash Loan Susceptibility | HIGH | DEX swap without access control — flash loan vector |
| Oracle Manipulation | HIGH | Spot price (getReserves) instead of TWAP |
| Missing Slippage / Deadline | HIGH | Zero slippage or no deadline — sandwich/MEV attacks |
| Force-Fed ETH | MEDIUM | address(this).balance manipulatable via selfdestruct |
| ERC20 Return Unchecked | MEDIUM | transfer() return value not checked (USDT/BNB) |
| Signature Replay | HIGH | ecrecover without chainId/nonce |
| Rounding Error | MEDIUM | Division before multiplication — precision loss |
| Storage Collision | HIGH | Upgradeable contract without __gap |
| Timestamp Manipulation | MEDIUM | block.timestamp in critical logic |
| Ownership Renouncement | MEDIUM | renounceOwnership without recovery |

Results appear automatically when a verified contract is detected:
```
[vuln] 0x7a250d56.. -> 6 vulnerability(ies) found
  >> Security Scan: 0x7a250d56.. (6 finding(s): 2 high, 4 medium)
   [!HIGH!] Unprotected Withdraw/Claim Function (lines: 224)
       [dim]Withdraw/claim function without access control...
```

### Exploit Pipeline (NEW)
Validates whether discovered vulnerabilities are **actually exploitable** by analyzing:
- Solidity version (>=0.8 blocks reentrancy via underflow protection)
- `unchecked {}` blocks (bypass overflow protection)
- Access control modifiers (onlyOwner, onlyRole)
- CEI pattern (Checks-Effects-Interactions ordering)

```bash
# Analyze any verified contract on any chain
python exploit_pipeline.py --address 0x... --chain ethereum
python exploit_pipeline.py --address 0x... --chain bsc
```

Output: detailed report with JSON export showing which findings are exploitable.

### Local Hardhat Exploitation Demo

Two demos are available, each demonstrating a different reentrancy vector:

#### 1. Classic underflow reentrancy (VulnerableBank)
```bash
cd exploit
npx hardhat run scripts/deploy_and_exploit.js --network hardhat
```
- Alice deposits 100 ETH in a deliberately vulnerable bank
- Bob deploys an exploit contract with 60 ETH
- The reentrancy attack drains the bank in ~3 rounds
- Bob profits 100 ETH

#### 2. CEI pattern reentrancy (CampaignWrapper validation)
```bash
cd exploit
npx hardhat run scripts/test_campaign_reentrancy.js --network hardhat
npx hardhat run scripts/test_cei_reentrancy.js --network hardhat
```
- Reproduces the exact pattern found in CampaignWrapper (0x8a56c6be..)
- Demonstrates that CEI reentrancy on bool flags works even in Solidity >=0.8
- Shows that non-arithmetic state (hasClaimed flag) CAN be bypassed by reentrancy
- Validates 5 rounds of recursive claim draining 5 ETH

#### 3. Universal exploit framework (20 attack types)
```bash
cd exploit
npx hardhat compile
npx hardhat run scripts/test_fork_exploit.js --network hardhat 0x... https://rpc-url 0.05
```
- `UniversalExploit.sol` — single contract testing 18/20 vulnerability types
- `test_fork_exploit.js` — fork → impersonate → deploy → attack → verify
- `hardhat_fork_tester.py` — Python orchestrator for automated fork testing

### Key discovery: Solidity >=0.8 blocks underflow reentrancy but NOT CEI reentrancy

**Underflow reentrancy (classic DAO style):** BLOCKED in >=0.8
- `balances[msg.sender] -= amount` reverts with `panic(0x11)` on underflow
- Requires `unchecked {}` to function

**CEI reentrancy (bool flag bypass):** WORKS in >=0.8
- `!hasClaimed[user]` is not arithmetic — can be bypassed by reentrancy
- The state update happens AFTER the external call, so the check passes multiple times
- Each recursive call drains another full refund amount

### Guardian 24/7 Stats (as of 07/06/2026)

| Metric | Value |
|:---|---|
| Contracts in DB | **2 340** |
| Verified contracts | **463** |
| Total findings | **1 307** |
| Exploitable (pipeline) | **857** |
| Contracts with balance > 0 | **19** (264.74 total native) |
| Hardhat fork tests | **853** (all failed — automated testing not configured) |
| Confirmed exploits | **0** |
| Pending Hardhat tests | **4** |

> **Key finding:** 100% of contracts with balance > 0 are ERC20 memecoins protected by OpenZeppelin `Ownable`. All critical functions are behind `onlyOwner` — the scanner detects code patterns but doesn't understand access control context.

### Bitcoin mempool tracking
- Connects to mempool.space WebSocket for real-time unconfirmed transactions
- Deduplicates transactions automatically
- Configurable minimum BTC value filter

### Configurable filters
Per-chain filters in `config.yaml`:
- `min_value_eth` / `min_value_btc` / `min_value_sol` — minimum transaction value
- `tracked_addresses` — only watch specific addresses
- `tracked_events` — which event types to track
- `tracked_tokens` — filter by token address

### Multi-chain at once
Run any combination of chains simultaneously. All output is unified in a single terminal display.

## Configuration

See `config.yaml` for all settings. Key sections:

```yaml
global:
  log_level: "INFO"              # DEBUG, INFO, WARNING, ERROR
  output_format: "rich"          # rich, json, both
  explorer_api_key: ""           # Optional Etherscan V2 key (for contract verification)

chains:
  ethereum:
    enabled: true                # Set false to disable
    rpc_ws: "wss://..."          # WebSocket endpoint
    chain_id: 1                  # EVM chain ID
    filters:
      min_value_eth: 0.01        # Minimum ETH value to report
```

### Contract verification (optional)

To enable smart contract source code verification:

1. Get a **free Etherscan API V2 key** at [etherscan.io/myapikey](https://etherscan.io/myapikey)
2. Add it to `config.yaml`:
```yaml
global:
  explorer_api_key: "YOUR_ETHERSCAN_V2_KEY"
```

> **One key for all chains**: Etherscan API V2 works across 60+ chains (Ethereum, BSC, Polygon, Arbitrum, etc.) with a single key. Free tier: 5 calls/sec, 100,000 calls/day.

## Terminal Output Legend

| Prefix | Meaning |
|:---|---:|
| `[BLK]` | New block detected |
| `[XFR]` | ERC-20 transfer event |
| `[verify]` | Contract verification result (VERIFIED / NOT VERIFIED) |
| `[vuln]` | Vulnerability scan results (finding count) |
| `>> Security Scan` | Detailed vulnerability listing with severity, lines, description |
| `[!CRITICAL!]` | Critical severity vulnerability (red) |
| `[!HIGH!]` | High severity vulnerability (yellow) |
| `[WARN]` | Medium severity vulnerability |
| `[MP]` | Mempool transaction (Bitcoin / pending EVM) |
| `[ACC]` | Account activity (filtered address) |
| `[TX]` | General transaction |

## Installation Details

### Requirements (Python 3.10+)

```
web3>=7.0.0        # EVM chains
solana>=0.34.0     # Solana
solders>=0.21.0    # Solana helpers
websockets>=12.0   # WebSocket connections
rich>=13.0.0       # Terminal UI
pyyaml>=6.0        # Configuration
httpx>=0.27.0      # HTTP requests (API calls)
```

### Install

```bash
pip install -r requirements.txt
```

## Project Structure

```
blockchain_scanner/
  main.py                    # CLI entry point
  guardian.py                # 24/7 scanner + SQLite DB
  config.yaml                # Configuration (chains, filters, API keys)
  verify.py                  # Contract source code verification (Etherscan V2)
  exploit_pipeline.py        # Automated vulnerability validation pipeline
  hardhat_fork_tester.py     # Standalone fork testing framework
  pool_scanner.py            # DEX pool scanner via DEX Screener API
  scan_bsc_recent.py         # Scan 100 recent BSC blocks for new contracts
  scan_bsc_500.py            # Scan 500 BSC blocks + auto exploit pipeline
  requirements.txt           # Python dependencies
  .gitignore                 # Git ignore rules
  README.md                  # This file
  scanner/
    base.py                  # BaseScanner ABC (auto-reconnect, stats)
    evm_scanner.py           # EVM chains (Ethereum, Polygon, BSC, Arbitrum)
    bitcoin_scanner.py       # Bitcoin via mempool.space
    solana_scanner.py        # Solana
    orchestrator.py          # Scanner lifecycle + vulnerability scan integration
  analysis/
    __init__.py              # Analysis package
    vulnerability_scanner.py # Solidity vulnerability scanner (20 patterns)
  filters/
    filters.py               # Transaction filters
  output/
    display.py               # Terminal display (Rich + vulnerability output)
  exploit/                   # Local Hardhat exploitation demos
    contracts/
      VulnerableBank.sol     # Deliberately vulnerable bank (CEI violation, underflow)
      Exploit.sol            # Reentrancy attack contract (underflow)
      ExploitV2.sol          # Debug version with configurable recursion
      CampaignVulnerable.sol # Reproduces CampaignWrapper pattern (CEI bool flag)
      CampaignExploit.sol    # CEI reentrancy exploit with guard-rail
      UniversalExploit.sol   # Universal exploit testing 18/20 attack types
      PrismReentrancyExploit.sol # PrismHook-specific reentrancy exploit
      AIDogeExploit.sol      # AIDoge-specific exploit contract
    scripts/
      deploy_and_exploit.js   # Classic underflow reentrancy demo
      test_simple_withdraw.js # Basic sanity check
      test_campaign_reentrancy.js  # CampaignWrapper CEI validation
      test_cei_reentrancy.js       # Combined validation suite
      test_fork_exploit.js    # Universal fork exploitation script
    hardhat.config.js         # Hardhat config (Solidity 0.8.20)
    package.json
    .gitignore
  findings/                  # Vulnerability findings catalog
    README.md                # Index of all analyzed contracts
    campaign_wrapper.md      # Detailed CampaignWrapper vulnerability report
    scanned_contracts.md     # Log of all scanned contracts
  skill/                     # Skill documentation
    multi-chain-blockchain-scanner.md  # Full reference
```

## Limitations

| Limitation | Reason |
|:---|---:|
| **No pending mempool on EVM** | PublicNode doesn't support `newPendingTransactions` |
| **BSC polling only** | BSC's `extraData` field breaks web3.py formatters |
| **Rate limited** | Free public nodes have no SLA |
| **Windows cp1252** | Terminal output uses ASCII only (no emoji) |

For production use, replace the free endpoints with paid providers (Alchemy, QuickNode, Infura).

## Troubleshooting

### "No chains enabled"
```bash
# Enable a chain in config.yaml
nano config.yaml   # Set enabled: true for at least one chain
```

### "Connection failed"
- Check your internet connection
- The public endpoint may be temporarily rate-limited — wait a moment and retry
- Some chains (like BSC) require polling mode, which is handled automatically

### "WebSocket closed"
Auto-reconnect with exponential backoff is built-in. The scanner will retry automatically (1s → 2s → 4s → ... → 60s max).

### "No blocks appearing"
- Some chains have slow block times (Ethereum: ~12s)
- BSC shows blocks immediately in polling mode (~3s blocks)
- Bitcoin only shows blocks when a new one is mined (~10min average)
