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
- `VulnerabilityScanner`: Solidity source code vulnerability analysis (10+ patterns)

### Extended project structure
```
blockchain_scanner/
  config.yaml                        # YAML config
  main.py                            # CLI entry point (argparse)
  exploit_pipeline.py                # New: Automated vuln validation pipeline
  scanner/
    base.py                          # BaseScanner ABC
    evm_scanner.py                   # EVM chains
    bitcoin_scanner.py               # Bitcoin
    solana_scanner.py                # Solana
    orchestrator.py                  # Scanner + vuln scan lifecycle
  analysis/
    vulnerability_scanner.py         # New: Solidity vuln scanner (10+ patterns)
    __init__.py
  filters/
    filters.py                       # Transaction filters
  output/
    display.py                       # Terminal display (vuln output added)
  verify.py                          # New: Source code verification via Etherscan V2
  exploit/                           # New: Local Hardhat exploitation demo
    contracts/
      VulnerableBank.sol             # Deliberately vulnerable bank (reentrancy)
      Exploit.sol                    # Reentrancy attack contract
      ExploitV2.sol                  # Debug version with configurable maxRounds
      MinimalExploit.sol             # Minimal exploit (no reentrancy, debugging)
    scripts/
      deploy_and_exploit.js          # Full reentrancy attack demo
      test_reentrancy_levels.js      # Incremental recursion depth test
      test_minimal.js                # Basic withdraw test
      test_simple_withdraw.js        # Sanity check
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

## 7. Solidity Vulnerability Scanner

### 10 Detected Vulnerability Types

| ID | Vulnerability | Severity |
|:---|:---|---:|
| `reentrancy` | Reentrancy (state change AFTER external call) | CRITICAL |
| `selfdestruct` | Contract can be destroyed | CRITICAL |
| `delegatecall` | Code execution in caller context | CRITICAL |
| `tx-origin` | tx.origin authorization | HIGH |
| `unprotected-withdraw` | Withdraw without ACL | HIGH |
| `unprotected-init` | Initializer without modifier | HIGH |
| `unchecked-call` | Unchecked external call result | MEDIUM |
| `integer-overflow` | Arithmetic without SafeMath (pre-0.8) | MEDIUM |
| `gas-loop` | Unbounded loop over dynamic array | MEDIUM |
| `arbitrary-from` | transferFrom with user-controlled 'from' | MEDIUM |

### Reentrancy Detection Strategy
- Find external calls with value (.call{value:...}(), .send())
- Skip .transfer() (limited to 2300 gas)
- Check nonReentrant modifier
- Look for state changes BEFORE the external call (CEI violation)
- CRITICAL if state change before call, HIGH if call without modifier

## 8. Exploit Pipeline

### Usage
```bash
python exploit_pipeline.py --address 0x... --chain bsc
python exploit_pipeline.py --live --chains bsc,ethereum
python exploit_pipeline.py --batch addresses.txt
```

### Exploitability Validation

| Finding Type | Exploitable? | Condition |
|:---|:---|---:|
| Reentrancy | YES | Solidity < 0.8 |
| Reentrancy | YES | Solidity >= 0.8 WITH unchecked {} |
| Reentrancy | NO | Solidity >= 0.8 (underflow protection) |
| Selfdestruct | YES | Without ACL |
| Delegatecall | YES | Dynamic target |

### Key Discovery: Solidity >=0.8 Blocks Reentrancy
`balances[msg.sender] -= amount` reverts with `panic(0x11)` on underflow in 0.8+.
In < 0.8, it wraps around (0 - 1 = 2^256 - 1), allowing the exploit.

## 9. Local Hardhat Exploitation Demo

### Attack Flow
1. Alice deposits 100 ETH in VulnerableBank
2. Bob deposits 60 ETH in Exploit contract
3. Exploit calls withdraw(60) -> re-enters via fallback
4. After 3 rounds, the bank is drained, Bob profits 100 ETH

### Run
```bash
cd blockchain_scanner/exploit
npm install
npx hardhat run scripts/deploy_and_exploit.js --network hardhat
```

### Debugging: Solidity >=0.8 Underflow Protection
- maxRounds=0: SUCCESS (no reentry)
- maxRounds=1: FAILED with panic 0x11 (underflow)
- The classic DAO reentrancy does not work on Solidity 0.8.x

## 10. Project Evolution

### Built in this session
1. Vulnerability scanner with 10 Solidity patterns
2. False positive reduction for ERC-20 transferFrom
3. Exploit pipeline for automated validation
4. Local Hardhat demo for reentrancy
5. BSC RPC optimization with Binance dataseed
6. Discovery: Solidity >=0.8 blocks classic reentrancy

### Concrete Validation vs Pattern Detection
Scanner finds patterns, not vulnerabilities. WETH9 case:
- withdraw() without onlyOwner flagged as HIGH
- But actually safe: CEI pattern respected, uses .transfer()
- ~85% of HIGH findings on audited contracts are false positives

### Scanning Results
| Chain | Status |
|:---|:---|
| Ethereum (Infura) | Fully working - blocks, transfers, verification OK |
| BSC (PublicNode) | Connection OK, polling times out - needs paid provider |

### Key Lesson
Always validate findings manually. Pipeline gives theoretical analysis (Solidity version, unchecked blocks, access control), but empirical testing on Hardhat is the only way to confirm.

### CEI Reentrancy Validation (This Session)

**CampaignWrapper** (0x8a56c6be..) — 7 HIGH findings, 1 MEDIUM. Validated empirically:
- Created CampaignVulnerable.sol (reproduces .call{value:} BEFORE state update)
- Created CampaignExploit.sol (re-enters via receive() before hasClaimed is set)
- **5 rounds of reentrancy confirmed** — 5 ETH drained from 5 ETH

**Key discovery:** CEI reentrancy on bool flags works in Solidity >=0.8 because:
- `!hasClaimed[user]` is NOT arithmetic — no underflow protection applies
- State update (bool = true) happens AFTER .call{value:}
- Check passes every time during reentrancy because state hasn't been updated yet

**Fix for >=0.8 reentrancy:** Use ReentrancyGuard modifier, NOT just relying on underflow protection.

### Challenge: Nouveaux déploiements non vérifiés

Lors du scan des 100 derniers blocs Ethereum, **10 contrats sur 10** étaient non vérifiés sur Etherscan. Le pipeline ne peut pas analyser de code source sans vérification.

**Pourquoi les nouveaux déploiements ne sont pas vérifiés :**
- Les créateurs doivent explicitement soumettre le code source à Etherscan après le déploiement
- Beaucoup de déploiements sont des tests, des bots, ou des contrats éphémères
- Certains créateurs évitent volontairement la vérification

**Solution :** Scanner des contrats plus anciens (au moins quelques heures/jours) qui ont eu le temps d'être vérifiés, ou utiliser une base de données comme Dune Analytics pour trouver des contrats vérifiés non-bluechip.
