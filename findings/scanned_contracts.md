# Registre des contrats scannés

Tous les contrats analysés par le scanner de vulnérabilités, classés par chaîne.

## Session 3 — Validation fork Hardhat + RPC (07/06/2026)

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
| **Total** | **~1000+** (DB Guardian) | **144** | **0 exploit réel** |

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

### Autres contrats vérifiés (0 findings)

| Adresse | Nom |
|:---|---|
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
- Les vaults Beefy/AutoFarm ont des UUIDs DefiLlama, pas d'adresses contrat

**Conclusion : Aucun contrat avec des fonds ET une faille exploitable n'a été trouvé sur BSC.**

**⚠️ Vérification des soldes :** Routes et Factories ont **0 BNB** de solde. Les fonds sont dans les Pair contracts (pools de liquidité), pas dans les routeurs.

| Contrat | Balance BNB | Txs | Verdict |
|:---|---:|:---:|:---|
| BabySmartRouter | 0.00000000 | 1 | 🪹 Router — ne detient pas de fonds |
| ApeRouter | 0.00000000 | 1 | 🪹 Router — ne detient pas de fonds |
| BiSwap SmartRouter | 0.00000000 | 1 | 🪹 Router — ne detient pas de fonds |
| BiSwap Factory | 0.00000000 | 3452 | 🪹 Factory — ne detient pas de fonds |

**Leçon :** Les Routeurs et Factories DEX ne détiennent pas de fonds. Pour exploiter une faille, il faut cibler les **Pair contracts** (pools) ou d'autres protocoles qui **détiennent de la liquidité** (yield aggregators, vaults, lending).

### Nouveaux déploiements (RPC scan 500 blocs)

*3 vérifiés (BEP-20 tokens, 0 findings) + 27 non vérifiés* — voir détails dans la section précédente.

---

## Session 2 — Guardian 24/7 + Multi-chain + Pool Scanner

### Nouveaux outils construits

| Outil | Description |
|:---|---|
| **`guardian.py`** | Usine de détection 24/7 — tourne en continu, ne s'arrête jamais |
| **`pool_scanner.py`** | Scan automatique des pools DEX avec TVL via DEX Screener API |
| **`run_guardian.sh`** | Script de lancement tmux (Unix) |
| **`run_guardian.bat`** | Script de lancement (Windows) |

### Multi-chain support (8 chaînes EVM)

Via `CHAIN_REGISTRY` dans `exploit_pipeline.py` : Ethereum, BSC, Polygon, Arbitrum, Optimism, Avalanche, Base, Fantom.

### Guardian — Résultats du scan live (65s sur 6 blockchains)

| Métrique | Valeur |
|:---|---|
| Contrats détectés | **68** |
| Dont vérifiés | **25** |
| Findings totaux | **46** (10 CRITICAL, 25 HIGH, 11 MED) |
| Exploitables (théoriques) | **35** |
| Tests Hardhat | 0 (aucun contrat avec solde > 0.001) |

### Pools DEX scannés via DEX Screener + Pool Scanner

| DEX | Pool | Chaîne | TVL | Findings | Expl. | Verdict |
|:---|---|---|:---:|:---:|:---:|:---|
| **QuickSwap** | LGNS-DAI | Polygon | **$342M** 🎯 | **3** (2 HIGH, 1 MED) | **2** | ❌ FAUX_POSITIF (UniswapV2Pair standard) |
| **QuickSwap** | AS-DAI | Polygon | $16.4M | 3 (2 HIGH, 1 MED) | 2 | ❌ FAUX_POSITIF (UniswapV2Pair standard) |
| **Velodrome** | OVER-WETH | Optimism | $311k | - | - | Non vérifié (proxy 46 bytes) |
| **Thena** | THE-WBNB | BSC | $109k | - | - | Non vérifié |
| **QuickSwap** | WMATIC-USDC | Polygon | $? | **12** (9 HIGH, 3 MED) | **9** | ❌ FAUX_POSITIF (AlgebraPool standard) |

### Contrats analysés sur Arbitrum

| Contrat | Adresse | Findings | Exploitables | Notes |
|:---|---|---|:---:|:---|
| **USDC (FiatTokenProxy)** | `0xaf88d065..5831` | **2 HIGH** | **2** | Reentrancy — probables faux positifs (proxy pattern) |
| Autres contrats Arbitrum | - | 0 | 0 | Tokens standards |

### Contrats analysés sur Optimism

| Contrat | Adresse | Findings | Exploitables | Notes |
|:---|---|---|:---:|:---|
| **Velodrome PoolFactory** | `0xF1046053..FF5a` | **1 HIGH** (Init) | **1** | Factory contract — pas de fonds |

### Santé du système

```bash
# Vérifier que le Guardian tourne
python guardian.py --health

# Voir les stats de la DB
python guardian.py --status

# Scanner les pools DEX
python pool_scanner.py --top 5 --chains polygon,optimism,bsc
```

---

## Statistiques globales cumulées

| Métrique | Valeur |
|:---|---|
| Total contrats scannés (toutes sessions) | **~1000+** (DB Guardian) |
| Contrats vérifiés avec findings | 10+ (WETH9, CampaignWrapper, BabySwap, BiSwap, ApeSwap, USDC Arbitrum, Velodrome, AlgebraPool...) |
| DEX non-bluechip analysés | **6** (5 vérifiés + 1 non vérifié) |
| Pools DEX avec TVL scannés | **5** (QuickSwap ×2, Thena, Velodrome, QuickSwap Algebra) |
| Findings totaux cumulés | **46+** (hors redondances) |
| Exploitables (théoriques) | **35+** |
| Taux de faux positifs global | **~70%** |
| **Fonds drainables** | **$0** — Aucun contrat avec fonds + faille trouvé |

---

## Méthodologie (mise à jour)

1. **Détection temps réel** : `guardian.py` scanne 8 blockchains en continu via WebSocket/RPC
2. **Scan pools DEX** : `pool_scanner.py` interroge DEX Screener API pour trouver les pools avec TVL
3. **Vérification** : Appel API Etherscan V2 (1 clé pour toutes les chaînes)
4. **Analyse** : `analysis/vulnerability_scanner.py` — 10 patterns de vulnérabilités
5. **Validation** : `exploit_pipeline.py` — validation théorique (Solidity, unchecked, ACL)
6. **Classification** : Pools standard (UniswapV2Pair, AlgebraPool) marqués FAUX_POSITIF
7. **Health check** : `guardian.py --health` — vérifie PID, DB, logs en continu
