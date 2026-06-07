# Registre des contrats scannés

Tous les contrats analysés par le scanner de vulnérabilités, classés par chaîne.

---

## Ethereum (Chain ID: 1)

| Date | Contrat | Type | Findings | Exploitables | Notes |
|:---|---|:---:|:---:|:---:|:---|
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
|:---|---:|
| `0xef0ced5d..d78` | Non vérifié |
| `0x7bf9a821..f68` | Non vérifié |
| `0xa373fbac..95b` | Non vérifié |
| `0xf8da8dc6..005` | Non vérifié |

### Nouveaux déploiements (RPC scan 100 blocs) — Tous non vérifiés

| Adresse | Txs | Verdict |
|:---|---|:---:|
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


## Binance Smart Chain (Chain ID: 56)

### Session précédente (scan scanner live)

| Date | Contrat | Type | Findings | Exploitables | Notes |
|:---|---|:---:|:---:|:---:|:---|
| Juin 2026 | **Token** (`0xff9a0457..ed4c`) | BEP-20 | 0 | 0 | Token standard |
| Juin 2026 | **CZ** (`0xfe61a573..2a5`) | BEP-20 | 0 | 0 | Token standard |
| Juin 2026 | `0xcc4881fa..082` | - | - | - | Non vérifié |
| Juin 2026 | `0x4e5356ef..5b5` | - | - | - | Non vérifié |
| Juin 2026 | `0x84858cd7..c69` | - | - | - | Non vérifié |

### DEX non-bluechip (scan ciblé via Etherscan/research web)

| DEX | Contrat | Solidity | Source | Findings | Exploitables | Détail |
|:---|:---|---:|:---:|:---:|:---:|:---|
| **BabySwap** | BabySmartRouter (`0x8317c460..32`) | `^0.7.4` | 107k | **6** (1 CRIT, 3 HIGH, 2 MED) | **4** | 🔴 Delegatecall + Reentrancy + Withdraw + Init |
| **BabySwap** | normalRouter (`0xddcc3d5f..30d`) ✅ = **GnosisSafeProxy** | - | 2k | **0** | 0 | 🔍 Cible du delegatecall — Gnosis Safe audité, 0 vuln |
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
|:---|---|:---:|:---|
| BabySmartRouter | 0.00000000 | 1 | 🪹 Router — ne detient pas de fonds |
| ApeRouter | 0.00000000 | 1 | 🪹 Router — ne detient pas de fonds |
| BiSwap SmartRouter | 0.00000000 | 1 | 🪹 Router — ne detient pas de fonds |
| BiSwap Factory | 0.00000000 | 3452 | 🪹 Factory — ne detient pas de fonds |

**Leçon :** Les Routeurs et Factories DEX ne détiennent pas de fonds. Pour exploiter une faille, il faut cibler les **Pair contracts** (pools) ou d'autres protocoles qui **détiennent de la liquidité** (yield aggregators, vaults, lending).

### Nouveaux déploiements (RPC scan 500 blocs)

*3 vérifiés (BEP-20 tokens, 0 findings) + 27 non vérifiés* — voir détails dans la section précédente.


## Statistiques globales

| Métrique | Valeur |
|:---|---:|
| Total contrats scannés | ~60 |
| Contrats vérifiés avec findings | 5 (WETH9, CampaignWrapper, **BabySwap**, **BiSwap**, **ApeSwap**) |
| Contrats vérifiés sans findings | 5 (3 tokens BSC + DAI + USDC + UNI) |
| Contrats non vérifiés | 10 (ETH) + 27 (BSC) + 1 DEX (BakerySwap) = 38 |
| DEX non-bluechip analysés | **5** (4 vérifiés, 1 non vérifié) |
| Findings totaux | **28** |
| Exploitables (théoriques) | **12** (DEX, cette session) + **7** (CampaignWrapper) = **19 total** |
| Exploitables (empiriques) | ✅ 1 pattern validé (CEI reentrancy CampaignWrapper — mais faux positif sur le contrat réel) |
| Taux de faux positifs (blue-chips) | ~85% |
| Taux de faux positifs (non-bluechip DEX) | **~60%** (Init protégés, normalRouter = GnosisSafe) |
| **Fonds drainables** | **$0** — Aucun contrat avec fonds + faille trouvé |

## Méthodologie

1. **Détection** : Scanner live des blocs (Ethereum Infura) ou scan RPC direct
2. **Vérification** : Appel API Etherscan V2 pour vérifier le code source
3. **Analyse** : `analysis/vulnerability_scanner.py` — 10 patterns de vulnérabilités
4. **Validation** : `exploit_pipeline.py` — validation théorique (version Solidity, unchecked, ACL)
5. **Confirmation** : Tests Hardhat locaux pour les patterns validés
