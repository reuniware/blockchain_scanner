# Multi-Chain Blockchain Transaction Scanner

Real-time monitoring of transactions and blocks across **6 blockchains** — Ethereum, Polygon, BSC, Arbitrum, Solana, and Bitcoin. No API keys required for basic usage (free public endpoints).

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

### Options

| Option | Description |
|:---|---:|
| `--chains X,Y,Z` | Comma-separated list of chains to scan |
| `-v` / `--verbose` | Enable DEBUG logging |
| `--list-chains` | List available chains and exit |
| `--format rich\|json\|both` | Output format |
| `-j FILE` / `--json FILE` | Export transactions to JSON file |
| `-c FILE` / `--config FILE` | Custom config file path |
| `--version` | Show version and exit |

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
| `[verify]` | Contract verification result |
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
  main.py              # CLI entry point
  config.yaml          # Configuration (chains, filters, API keys)
  verify.py            # Contract source code verification (Etherscan V2)
  requirements.txt     # Python dependencies
  scanner/
    base.py            # BaseScanner ABC (auto-reconnect, stats)
    evm_scanner.py     # EVM chains (Ethereum, Polygon, BSC, Arbitrum)
    bitcoin_scanner.py # Bitcoin via mempool.space
    solana_scanner.py  # Solana
    orchestrator.py    # Scanner lifecycle manager
  filters/
    filters.py         # Transaction filters
  output/
    display.py         # Terminal display (Rich)
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
