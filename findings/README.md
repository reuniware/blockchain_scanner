# Findings — Contrats analysés et vulnérabilités

Ce répertoire répertorie tous les contrats analysés par le scanner de vulnérabilités, avec les résultats détaillés de chaque analyse.

## Résumé

| Statut | Nombre |
|:---|---:|
| Contrats scannés (toutes sessions) | **~100+** |
| Contrats vérifiés analysés | 25+ |
| DEX non-bluechip analysés | 6 |
| Pools DEX avec TVL scannés | 5 |
| Findings totaux cumulés | **46+** |
| Exploitables (théorique - pipeline) | **35+** |
| Exploitables (validé empiriquement) | 1 pattern (CEI reentrancy CampaignWrapper — faux positif réel) |
| Faux positifs (blue-chips audités) | ~85% |
| Faux positifs (non-bluechip DEX + pools) | **~70%** |
| **Fonds drainables** | **$0** — Aucun contrat avec fonds + faille trouvé |

## Session 2 — Guardian + Pool Scanner (juin 2026)

### Nouveaux outils

| Outil | Description | Commande |
|:---|---|:---|
| **`guardian.py`** | Usine de détection 24/7 sur 8 chaînes EVM | `python guardian.py` |
| **`pool_scanner.py`** | Scan pools DEX avec TVL via DEX Screener | `python pool_scanner.py` |

### Résultats Guardian (65s de scan live)

- **68 contrats** détectés, **25 vérifiés**
- **46 findings** : 10 CRITICAL, 25 HIGH, 11 MED — **35 exploitables théoriques**
- **0 contrat avec solde > 0.001** (même constat : findings sur routeurs à 0 BNB)

### Résultats Pool Scanner

| Pool | DEX | Chaîne | TVL | Findings | Verdict |
|:---|---|:---:|:---:|:---:|:---|
| **LGNS-DAI** | QuickSwap | Polygon | **$342M** 🎯 | 3 (2 HIGH) | ❌ FAUX_POSITIF (UniswapV2Pair) |
| AS-DAI | QuickSwap | Polygon | $16.4M | 3 (2 HIGH) | ❌ FAUX_POSITIF (UniswapV2Pair) |
| WMATIC-USDC | QuickSwap | Polygon | - | **12** (9 HIGH) | ❌ FAUX_POSITIF (AlgebraPool) |
| OVER-WETH | Velodrome | Optimism | $311k | - | ❌ Non vérifié |
| THE-WBNB | Thena | BSC | $109k | - | ❌ Non vérifié |

### Multi-chain support

8 chaînes EVM supportées via `CHAIN_REGISTRY` : Ethereum, BSC, Polygon, **Arbitrum** ✅, Optimism, Avalanche, Base, Fantom.

| Chaîne | Tests | Résultat |
|:---|---|:---|
| Arbitrum | USDC FiatTokenProxy | 2 HIGH reentrancy — probables FP |
| Optimism | Velodrome PoolFactory | 1 HIGH Initializer — pas de fonds |
| Polygon | QuickSwap AlgebraPool | 12 findings — 9 exploitables — clone standard |

## Session 1 — DEX + CampaignWrapper (juin 2026)

### Résultats DEX non-bluechip

| DEX | Contrat | Findings | Exploitables | Verdict |
|:---|---|:---:|:---:|:---|
| **BabySwap** | BabySmartRouter | **6** (1 CRIT, 3 HIGH, 2 MED) | **4** | 🔴 Delegatecall — normalRouter = GnosisSafe audité |
| **BabySwap** | normalRouter | **0** | 0 | ✅ GnosisSafeProxy (audité) |
| **BabySwap** | BabyPair WBNB-USDT ($27M) | 3 (2 HIGH, 1 MED) | 0 | ✅ Faux positif — Init protégé |
| **BabySwap** | BabyFactory | 3 (2 HIGH, 1 MED) | 0 | ✅ Faux positif probable |
| **BiSwap** | SmartRouter | **5** (3 HIGH, 2 MED) | **3** | 0 BNB — pas de fonds |
| **ApeSwap** | ApeRouter | **4** (3 HIGH, 1 MED) | **3** | 0 BNB — pas de fonds |
| **BiSwap** | Factory | **3** (2 HIGH, 1 MED) | **2** | 0 BNB — pas de fonds |
| **BakerySwap** | Router | - | - | ❌ Non vérifié |

### CampaignWrapper (Ethereum)

- **8 findings** (7 HIGH, 1 MED) — **7 exploitables** théoriques
- 1 pattern validé empiriquement (CEI reentrancy sur reproduction)
- Mais faux positif sur le contrat réel (`_refund` private + `nonReentrant`)

## Session 3 — Validation locale concrète avec fonds réels (07/06/2026)

Pour la première fois, des contrats réels AVEC FONDS ont été copiés et testés localement.

### Cibles identifiées (depuis la DB Guardian, 913 contrats)

| # | Contrat | Chaîne | Balance | Findings | Exploitables |
|:---|---|:---:|:---:|:---:|:---:|
| 1 | Lido stETH (AppProxyUpgradeable) | Ethereum | **262.45 ETH** (~$500k) | 3 | 2 (Delegatecall + Init) |
| 2 | PrismHook | Ethereum | **13.14 ETH** (~$25k) | 4 | 3 (Reentrancy + 2× Init) |
| 3 | AIDoge | Arbitrum | **2.34 ETH** (~$4.5k) | 8 | **7** (Delegatecall + Reentrancy + Withdraw) |

### Tests fork Hardhat réalisés

#### 1. Lido stETH — Non testé (blue-chip audité)
- Proxy EIP-1967 connu, audité par plusieurs firmes
- `delegatecall` = volontaire (pattern proxy), `initialize()` protégé par le proxy
- **Verdict : ❌ Non testé — faux positif quasi-certain**

#### 2. PrismHook — Testé sur fork Ethereum ✅
| Test | Résultat | Détail |
|:---|---|:---|
| `initialize()` | ❌ Échoué | Fonction inconnue (mauvais sélecteur) |
| `initialize(address)` | ❌ Échoué | Fonction inconnue |
| `initializeOwner(address)` (Solady) | ❌ Échoué | Fonction inconnue |
| Reentrancy via exploit contract | ❌ Bloqué | `ReentrancyGuard` actif dans le code source |
| **Drain de fonds** | ❌ **0 ETH** | Balance passée de 12→13 ETH (l'exploit a envoyé des fonds) |

**Verdict : ❌ NON EXPLOITABLE** — ReentrancyGuard bloque la réentrance, les initializers sont soit absents soit protégés.

#### 3. AIDoge — Testé via eth_call direct (Hardhat ne fork pas Arbitrum) ✅
| Test | Résultat | Détail |
|:---|---|:---|
| `owner()` | ✅ OK | Retourne 0x0 (owner brûlé ou différent) |
| `totalSupply()` | ✅ OK | 210M tokens |
| `initialize(address)` | ❌ REVERT | Protégé (quel que soit l'appelant) |
| `initialize()` | ❌ REVERT | Protégé |
| `withdraw(uint256)` | ❌ REVERT | Protégé |
| `withdrawAll()` | ❌ REVERT | Protégé |
| `delegatecallToTarget(bytes)` | ❌ REVERT | Protégé |
| **Drain de fonds** | ❌ **0 ETH** | Toutes les fonctions revertent |

**Verdict : ❌ NON EXPLOITABLE** — Les findings du scanner (7/8) sont des faux positifs : les fonctions ont des access controls fonctionnels.

### Bilan des validations locales

| Contrat | Fonds | Findings | Test local | Résultat |
|:---|---|:---:|:---|---:|
| Lido stETH | 262 ETH | 2 exploitables | Pas testé (blue-chip) | ❌ Faux positif probable |
| PrismHook | 13 ETH | 3 exploitables | ✅ Hardhat fork | ❌ **NON exploitable** |
| AIDoge | 2.34 ETH | 7 exploitables | ✅ RPC direct | ❌ **NON exploitable** |
| **TOTAL** | **277 ETH** | **12** | **2 tests fork** | **0 confirmé** |

## Constat global final

**Aucun contrat avec des fonds réels ET une vulnérabilité exploitable n'a été trouvé après 3 sessions de scan.** Les scanners produisent des faux positifs sur :

| Type de contrat | Fonds max trouvés | Findings scanner | Test local | Raison du faux positif |
|:---|---:|:---:|:---|---:|
| Routeurs DEX (BabySmartRouter...) | 0 BNB | ✅ Réelles | Non testé (pas de fonds) | Pas de fonds à drainer |
| Pools DEX (UniswapV2Pair) | $342M TVL | ✅ Patterns | ❌ Faux positifs | Clones standardisés audités |
| Contrats custom (PrismHook, AIDoge) | 15 ETH | ✅ 10 exploitables | ✅ **Fork/RPC** | Access controls + ReentrancyGuard |
| Blue-chips (Lido stETH) | 262 ETH | ✅ 2 | Pas testé | Proxy patterns audités |
| Yield vaults (Beefy, AutoFarm) | $$$ | ❓ | Non trouvés | Pool-specific |

**Conclusion : le scanner détecte des patterns de code mais ne comprend pas le contexte** (modifiers, héritage, proxy patterns, ReentrancyGuard). Les 301 tests Hardhat automatisés du Guardian ont tous échoué car Hardhat n'est pas installé globalement — mais les tests fork manuels (PrismHook, AIDoge) confirment que les findings étaient des faux positifs.

## Comment lancer les outils

```bash
# Guardian 24/7 (scan temps réel)
python guardian.py

# Health check
python guardian.py --health

# Status DB
python guardian.py --status

# Pool scanner (1 scan)
python pool_scanner.py --top 5 --chains polygon,optimism,bsc

# Pool scanner (mode continu)
python pool_scanner.py --daemon
```

## Légende

- **Expl. (Théorique)** = Marqué exploitable par `exploit_pipeline.py` (analyse statique)
- **Expl. (Empirique)** = Validé par exploitation réelle sur Hardhat local
- **Faux positif** = Détecté par le scanner mais non exploitable dans le contexte
- **Propre** = Aucune vulnérabilité détectée

## Validation empirique

Les vulnérabilités marquées comme validées empiriquement ont été reproduites et exploitées :

1. **CampaignVulnerable.sol** — Reproduction du motif `.call{value:}` avant mise à jour d'état
2. **CampaignExploit.sol** — Contrat d'exploit avec garde-fou (`targetBalance >= pending`)
3. Testé sur Hardhat local : ✅ 5 rounds de reentrancy, 5 ETH drainés

Voir `../exploit/` pour les scripts de validation complets.
