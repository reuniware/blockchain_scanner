# Registre des contrats scannés

Tous les contrats analysés par le scanner de vulnérabilités, classés par chaîne.

---

## Session 5 — Consolidation (07/06/2026)

### Statistiques consolidées de la DB Guardian

| Métrique | Valeur |
|:---|---|
| Contrats totaux dans la DB | **2 340** |
| Contrats vérifiés | **463** (Ethereum: 112, Arbitrum: 254) |
| Findings totaux | **1 307** |
| Exploitables (pipeline) | **857** |
| Tests Hardhat automatisés | **853** (tous échoués) |
| Contrats avec balance > 0 | **19** (264.74 total native) |
| Exploits confirmés | **0** |
| En attente | **4** |

### Répartition par chaîne

| Chaîne | Contrats totaux | Contrats vérifiés | Avec balance | Balance totale |
|:---|---:|---:|---:|:---:|
| Ethereum | 1 257 | 112 | 12 | 261.47 ETH |
| Arbitrum | 572 | 254 | 7 | 3.27 ETH |

### Top 10 types de findings (tous)

| # | Finding | Occurrences |
|:---|:---|---:|
| 1 | Potential Reentrancy (No CEI Pattern) | 232 |
| 2 | Delegatecall to Variable Address | 208 |
| 3 | Unbounded Loop Over Dynamic Array | 178 |
| 4 | Unchecked External Call | 136 |
| 5 | Unprotected Initializer | 108 |
| 6 | Unprotected Withdraw/Claim Function | 62 |
| 7 | Integer Overflow/Underflow | 37 |
| 8 | TX Origin Authorization | 14 |
| 9 | Reentrancy Vulnerability | 5 |
| 10 | Arbitrary 'from' in transferFrom | 5 |

### Exploitables par sévérité

| Sévérité | Nombre |
|:---|---:|
| CRITICAL | 192 |
| HIGH | 440 |
| MEDIUM | 5 |
| **Total** | **857** |

---

## Session 4 — Scanner 20 failles + Framework Hardhat standalone (07/06/2026)

### Nouveautés

- **Scanner enrichi de 10 → 20 failles** : 10 nouvelles détections (Flash Loan, Oracle, Slippage, Force-Fed ETH, ERC20 Return, Signature Replay, Rounding, Storage Collision, Timestamp, Ownership Renounce)
- **Framework Hardhat standalone** : `hardhat_fork_tester.py` + `UniversalExploit.sol` + `test_fork_exploit.js`
- **UniversalExploit.sol** : contrat d'exploit universel testant 18/20 types d'attaques (compilation OK ✅)

### Nouveaux contrats analysés en profondeur (source code complet)

| Contrat | Chaîne | Balance | Type | Findings | Verdict |
|:---|---|:---:|:---|:---:|:---|
| **Nola** (0xf8388c...) | Arbitrum | 0.48 ETH | ERC20 memecoin | 12 (8 exploitables) | ❌ onlyOwner partout |
| **Smolcoin** (0x9e64d3...) | Arbitrum | 0.22 ETH | ERC20 memecoin | 24 (20 exploitables) | ❌ onlyOwner partout |
| **PinLink** (0x2e44f3...) | Ethereum | 0.035 ETH | ERC20 memecoin | 5 (4 exploitables) | ❌ onlyOwner partout |

### Framework de validation créé

| Fichier | Description |
|:---|---|
| `hardhat_fork_tester.py` | Orchestrateur Python standalone pour tests fork |
| `exploit/contracts/UniversalExploit.sol` | Contrat testant 18/20 types d'attaques (sauf TX Origin et Signature Replay) |
| `exploit/scripts/test_fork_exploit.js` | Script Hardhat : fork → impersonate → deploy → attaquer → vérifier |

### Constat critique

**Tous les contrats avec balance > 0 trouvés par le scanner sont des ERC20 memecoins** utilisant OpenZeppelin `Ownable`. Les fonctions sensibles (withdraw, mint, burn, swap) sont toutes protégées par `onlyOwner`.

Le scanner détecte correctement les patterns de code (`.call{value:}`, `tx.origin`, `delegatecall` dans OZ) mais ne comprend pas que :
- Les modifiers `onlyOwner` bloquent l'accès
- Les librairies OpenZeppelin sont des standards audités
- Les proxies EIP-1967 sont des patterns volontaires

**Taux de faux positifs sur contrats avec balance : 100%** (7 contrats analysés en profondeur sur 19 au total avec balance > 0).

---

## Session 3 — Validation fork Hardhat (07/06/2026)

Pour la première fois, des contrats réels AVEC FONDS ont été testés localement.

### Contrats testés

| Contrat | Chaîne | Fonds | Findings | Test | Résultat |
|:---|---|:---:|:---:|:---|---:|
| **Lido stETH** (AppProxyUpgradeable) | Ethereum | 262.45 ETH | 3 (Delegatecall, Init) | Non testé (blue-chip) | ❌ Faux positif probable |
| **PrismHook** | Ethereum | 13.14 ETH | 4 (Reentrancy + 2× Init) | ✅ Hardhat fork | ❌ **Non exploitable** |
| **AIDoge** | Arbitrum | 2.34 ETH | 8 (Delegatecall, Reentrancy ×3, Withdraw ×3) | ✅ RPC direct | ❌ **Non exploitable** |

### Détails tests

**PrismHook** (Hardhat fork Ethereum) :
- `initialize()` / `initialize(address)` / `initializeOwner(address)` → toutes inconnues ou révert
- Reentrancy → bloqué par `ReentrancyGuard` (vérifié dans le code source)
- Balance : 12 → 13 ETH (augmentée, pas drainée)

**AIDoge** (eth_call direct sur Arbitrum) :
- `owner()` → 0x0 (owner brûlé ou fonction absente)
- `initialize(address)` / `initialize()` → REVERT (protégé)
- `withdraw()` / `withdrawAll()` → REVERT (protégé)
- `delegatecallToTarget()` → REVERT (protégé)

### Bilan des validations

| Session | Contrats scannés | Tests fork | Confirmés |
|:---|:---:|:---:|:---:|
| 1 (DEX + Campaign) | 25+ | 5 (CampaignVulnerable) | 1 pattern (faux positif réel) |
| 2 (Guardian + Pool) | 68+ | 139 (automatisés, Hardhat absent) | 0 |
| 3 (Validation fork) | 3 (DB: 913 contrats totaux) | **2 fork + 1 RPC** | **0** |
| 4 (Scanner enrichi) | 3 (nouvelles cibles) | Framework créé | 0 |
| 5 (Consolidation) | DB: 1 829 contrats | 628 (tous échoués) | **0** |
| **Total** | **~2 340** (DB Guardian) | **~855** | **0 exploit réel** |

---

## Ethereum (Chain ID: 1)

| Date | Contrat | Type | Findings | Exploitables | Notes |
|:---|:---|---:|:---:|:---|
| Juin 2026 | **CampaignWrapper** (`0x8a56c6be..06bea`) | Complexe | **8** (7 HIGH, 1 MED) | **7** | Reentrancy + TX Origin + Unprotected Init |
| Juin 2026 | **WETH9** (`0xc02aaa39..6cc2`) | Token | 2 (1 HIGH, 1 MED) | 0 | Faux positif withdraw (CEI + .transfer) |
| Juin 2026 | **USDC** (`0xa0b86991..eb48`) | Token | 0 | 0 | Blue-chip audité |
| Juin 2026 | **WBTC** (`0x2260fac5..c599`) | Token | 0 | 0 | Blue-chip audité |
| Juin 2026 | **USDT** (`0xdac17f95..1ec7`) | Token | 0 | 0 | Blue-chip audité |
| Juin 2026 | **DAI** (`0x6b175474..1d0f`) | Token | 0 | 0 | Blue-chip audité |
| Juin 2026 | **UNI** (`0x1f9840a8..f984`) | Token | 0 | 0 | Blue-chip audité |
| Juin 2026 | **PEPE** (`0x69825081..1933`) | Token | 0 | 0 | Token standard |
| Juin 2026 | **PinLink** (`0x2e44f3..07c3607c4`) | ERC20 memecoin | 5 (4 exploitables) | 0 | ❌ onlyOwner partout |

### Autres contrats vérifiés (0 findings)

| Adresse | Nom |
|:---|:---|
| `0xef0ced5d..d78` | Non vérifié |
| `0x7bf9a821..f68` | Non vérifié |
| `0xa373fbac..95b` | Non vérifié |
| `0xf8da8dc6..005` | Non vérifié |

### Nouveaux déploiements (RPC scan 100 blocs) — Tous non vérifiés

| Adresse | Txs | Verdict |
|:---|---|:---|
| `0xb3e1d10577d185f0e9ae3b8821d7a5e35b8db5f9` | 3 txs | ❌ Non vérifié — impossible d'analyser |
| `0xb4b9dc1c5a6a044b19b283d1e1a6c10030c3a35` | 2 txs | ❌ Non vérifié — impossible d'analyser |
| `0x0263d4c2b6037d5644b63d3e4fe36469e99f917f` | 2 txs | ❌ Non vérifié |
| `0x502ca72d337b39f190119a950850fff25df8c902` | 3 txs | ❌ Non vérifié |
| `0xa6498e7e9480bcb73b88b3d3bc1ebf9b8e35c23a` | 1 tx | ❌ Non vérifié |
| `0xc1d1e7081e13ee33cf9fcefcce1fc3a3ac2415cc` | 1 tx | ❌ Non vérifié |
| `0x9845a58315202293863a8dc6987c4306e4a84f1a` | 1 tx | ❌ Non vérifié |
| `0x168ca4b6a0c7637fd8d5bcfdbb44c66c3ec81e31` | 1 tx | ❌ Non vérifié |
| `0xa1eb57aadad719bdc45b3e24c97d4c67adb84372` | 1 tx | ❌ Non vérifié |
| `0x3a2ef0c6760351546da7f31180e7ddbaf768fde4` | 1 tx | ❌ Non vérifié |
| `0x10482134def86f20a1b8d4a2052eb2e02f54dac0` | 1 tx | ❌ Non vérifié |

**Leçon :** Les nouveaux déploiements sont rarement vérifiés immédiatement. Il faut soit scanner des contrats plus anciens (vérifiés), soit attendre que les nouveaux contrats soient vérifiés par leurs créateurs.

---

## Binance Smart Chain (Chain ID: 56)

### Session précédente (scan scanner live)

| Date | Contrat | Type | Findings | Exploitables | Notes |
|:---|:---|---:|:---:|:---|
| Juin 2026 | **Token** (`0xff9a0457..ed4c`) | BEP-20 | 0 | 0 | Token standard |
| Juin 2026 | **CZ** (`0xfe61a573..2a5`) | BEP-20 | 0 | 0 | Token standard |
| Juin 2026 | `0xcc4881fa..082` | - | - | - | Non vérifié |
| Juin 2026 | `0x4e5356ef..5b5` | - | - | - | Non vérifié |
| Juin 2026 | `0x84858cd7..c69` | - | - | - | Non vérifié |

### DEX non-bluechip (scan ciblé via Etherscan/research web)

| DEX | Contrat | Solidity | Source | Findings | Exploitables | Détail |
|:---|---|---|:---:|:---:|:---:|
| **BabySwap** | BabySmartRouter (`0x8317c460..32`) | `^0.7.4` | 107k | **6** (1 CRIT, 3 HIGH, 2 MED) | **4** | 🔴 Delegatecall + Reentrancy + Withdraw + Init |
| **BabySwap** | normalRouter (`0xddcc3d5f..30d`) = GnosisSafeProxy | - | 2k | **0** | 0 | Cible du delegatecall — Gnosis Safe audité |
| **BabySwap** | BabyPair WBNB-USDT (`0x04580ce6..3f`) | `^0.7.4` | 30k | **3** (2 HIGH, 1 MED) | 0 | ✅ **Faux positif** — Init protégé par `require(factory)` |
| **BabySwap** | BabyPair #1 pool (`0xbb305bde..da2`) | - | 30k | **3** (2 HIGH, 1 MED) | 0 | ✅ Même pattern BabyPair — Init protégé |
| **BabySwap** | BabyPair #2 pool (`0x7acafdf9..bf5`) | - | 30k | **3** (2 HIGH, 1 MED) | 0 | ✅ Même pattern BabyPair — Init protégé |
| **BabySwap** | BabyPair #3 pool (`0x2f4e6454..0df`) | - | 30k | **3** (2 HIGH, 1 MED) | 0 | ✅ Même pattern BabyPair — Init protégé |
| **BabySwap** | BabyFactory (`0x86407bea..da`) | - | 34k | **3** (2 HIGH, 1 MED) | 0 | ✅ **Faux positif probable** — Init protégé |
| **BiSwap** | SmartRouter (`0x0eB6949e..EF`) | `0.8.16` | 103k | **5** (3 HIGH, 2 MED) | **3** | Withdraw ×2 + Initializer |
| **ApeSwap** | ApeRouter (`0xcF0feBd3..b7`) | - | 36k | **4** (3 HIGH, 1 MED) | **3** | Reentrancy + Withdraw + Init |
| **BiSwap** | Factory (`0x858e3312..ee`) | - | 23k | **3** (2 HIGH, 1 MED) | **2** | Initializer ×2 |
| **BakerySwap** | Router (`0xCDe540d7..0F`) | - | ❌ Non vérifié | - | - | Impossible d'analyser |

**Résultat :** 4/5 DEX vérifiés ont des vulnérabilités. BabySmartRouter est le plus critique (Delegatecall en ^0.7.4). **MAIS :**
- Le delegatecall cible **GnosisSafeProxy** (audité, 0 vuln) → impasse
- Les Pair contracts (BabyPair, $27M+) sont protégés (Init avec `require(factory)`)
- Les routeurs ont des findings mais **0 BNB** de solde

**Conclusion : Aucun contrat avec des fonds ET une faille exploitable n'a été trouvé sur BSC.**

**⚠️ Vérification des soldes :** Routes et Factories ont **0 BNB** de solde. Les fonds sont dans les Pair contracts (pools de liquidité), pas dans les routeurs.

| Contrat | Balance BNB | Txs | Verdict |
|:---|---:|:---:|:---|
| BabySmartRouter | 0.00000000 | 1 | 🪹 Router — ne détient pas de fonds |
| ApeRouter | 0.00000000 | 1 | 🪹 Router — ne détient pas de fonds |
| BiSwap SmartRouter | 0.00000000 | 1 | 🪹 Router — ne détient pas de fonds |
| BiSwap Factory | 0.00000000 | 3452 | 🪹 Factory — ne détient pas de fonds |

**Leçon :** Les Routeurs et Factories DEX ne détiennent pas de fonds. Pour exploiter une faille, il faut cibler les **Pair contracts** (pools) ou d'autres protocoles qui **détiennent de la liquidité** (yield aggregators, vaults, lending).

---

## Arbitrum (Chain ID: 42161)

| Date | Contrat | Type | Findings | Exploitables | Notes |
|:---|:---|---:|:---:|:---|
| Juin 2026 | **AIDoge** (`0x09e18590..1b6b`) | Token + Delegatecall | **8** (7 exploitables) | 0 | ❌ Faux positif — fonctions protégées |
| Juin 2026 | **USDC (FiatTokenProxy)** (`0xaf88d065..5831`) | Proxy | 2 HIGH | 2 | Probable faux positif |
| Juin 2026 | **Nola** (`0xf8388c2b..141d`) | ERC20 memecoin | 12 (8 exploitables) | 0 | ❌ onlyOwner partout |
| Juin 2026 | **Smolcoin** (`0x9e64d3b9..82b5`) | ERC20 memecoin | 24 (20 exploitables) | 0 | ❌ onlyOwner partout |

---

## Statistiques globales cumulées

| Métrique | Valeur |
|:---|---|
| Total contrats scannés (DB Guardian) | **2 340** |
| Contrats vérifiés | **463** |
| Findings totaux | **1 307** |
| Exploitables (pipeline) | **857** |
| Tests de validation (Hardhat + fork + RPC) | **~855** |
| Contrats avec balance > 0 | **19** (264.74 total native) |
| Exploits confirmés | **0** |
| Taux de faux positifs global | **~85%** |
| **Fonds drainables** | **$0** |

---

## Méthodologie

1. **Détection temps réel** : `guardian.py` scanne 8 blockchains en continu via WebSocket/RPC
2. **Scan pools DEX** : `pool_scanner.py` interroge DEX Screener API pour trouver les pools avec TVL
3. **Vérification** : Appel API Etherscan V2 (1 clé pour toutes les chaînes)
4. **Analyse** : `analysis/vulnerability_scanner.py` — **20 patterns** de vulnérabilités
5. **Validation** : `exploit_pipeline.py` — validation théorique (Solidity, unchecked, ACL)
6. **Fork testing** : `hardhat_fork_tester.py` + `UniversalExploit.sol` — validation concrète sur fork
7. **Classification** : Pools standard (UniswapV2Pair, AlgebraPool) et ERC20 memecoins marqués FAUX_POSITIF

## Santé du système

```bash
# Vérifier que le Guardian tourne
python guardian.py --health

# Voir les stats de la DB
python guardian.py --status

# Scanner les pools DEX
python pool_scanner.py --top 5 --chains polygon,optimism,bsc

# Tester un contrat sur fork
python hardhat_fork_tester.py --target 0x... --chain arbitrum
```
