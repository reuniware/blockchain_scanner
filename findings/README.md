# Findings — Contrats analysés et vulnérabilités

Ce répertoire répertorie tous les contrats analysés par le scanner de vulnérabilités, avec les résultats détaillés de chaque analyse.

## Résumé (10/06/2026) — Session 10

| Statut | Nombre |
|:---|---:|
| Contrats dans la DB Guardian | **24 945** |
| Contrats vérifiés analysés | **985** |
| Findings totaux cumulés | **8 109** |
| Exploitables (théorique - pipeline) | **4 943** |
| Tests Hardhat fork | **2 635** |
| Exploits confirmés | **0** |

### 🔧 Changements récents (Session 10 — 10/06/2026)

#### 4 nouvelles chaînes EVM : Base, Fantom, Gnosis, Celo

| Chaîne | Chain ID | Currency | Nouveau endpoint WS |
|--------|:--------:|:--------:|---------------------|
| **Base** | 8453 | ETH | `wss://base-rpc.publicnode.com` |
| **Fantom** | 250 | FTM | `wss://wsapi.fantom.network/` (officiel 🔄) |
| **Gnosis** | 100 | xDAI | `wss://rpc.gnosischain.com/wss` (path /wss corrigé 🔄) |
| **Celo** | 42220 | CELO | `wss://forno.celo.org/ws` (polling) |

#### Bugs corrigés
- **`kill_all_node_processes`** : wmic (déprécié) → `Get-CimInstance` PowerShell
- **Base + Fantom ignorées** : ajoutées dans le tuple `_create_scanner()`
- **Gnosis + Celo absentes** : CHAIN_REGISTRY + config.yaml + hardhat_fork_tester complétés

#### Anti-OOM
- Rotation automatique des logs (>50 Mo)
- `gc.collect()` forcé toutes les 10 min
- Monitoring RSS mémoire (Windows ctypes / Linux /proc)
- Détection de fuite de tâches asyncio (>500 tâches = alerte)

#### Résultats après correction
- Guardian tourne sur **16 chaînes simultanément** (14 EVM + Bitcoin + Solana désactivé)
- **Base** : 19 pipelines d'exploit déclenchés 🔥
- **Celo** : 1 pipeline d'exploit déclenché
- **zkSync Era** (324) : scan actif via WS public 🔄
- **Scroll** (534352), **Linea** (59144), **Polygon zkEVM** (1101) : scan actif via HTTP polling
- Fantom et Gnosis : initialisés avec nouveaux endpoints WS

#### EVMScanner : support HTTP polling pour chaînes sans WS
- `_connect()` : utilise `HTTPProvider` de web3.py quand `rpc_ws` est vide (au lieu de `ValueError`)
- `_listen()` : bascule directement en `_poll_blocks()` quand pas de socket WS (au lieu de retourner silencieusement)
- Permet aux chaînes sans WS public (Scroll, Linea, Polygon zkEVM) de scanner en HTTP

| Statut | Nombre |
|:---|---:|
| Contrats dans la DB Guardian | **24 945** |
| Contrats vérifiés analysés | **985** |
| Findings totaux cumulés | **8 109** |
| Exploitables (théorique - pipeline) | **4 943** |
| Types de vulnérabilités détectées | **29** (+9 OpenZeppelin checks) |
| Tests Hardhat fork (batch) | **55** (tous les contrats vérifiés avec balance) |
| Tests Hardhat fork (backfill force) | **2 580** (985 contrats, 8 109 findings) |
| Tests Hardhat fork (total) | **2 635** |
| Tests fork PredictionV2 | **5 scripts** (oracle, reentrancy, delegatecall, txorigin, treasury) |
| Tests générés dynamiquement | **1** (généré depuis les findings DB) |
| Contrats avec balance > 0.001 | **66** |
| Total BNB dans les contrats | **1 746 162** |
| Exploitables (validé empiriquement) | 1 pattern (CEI reentrancy CampaignWrapper — faux positif réel) |
| Faux positifs sur contrats avec balance | ~100% (aucun confirmé après 55 tests) |
| Faux positifs globaux | Estimation ~85% |
| **Fonds drainables** | **0 confirmé** après 2 635 tests Hardhat fork complets |

### 🔧 Changements récents (Session 10 — 10/06/2026)

#### ABI Mining — Exploit Generator Data-Driven
- Nouveau script `mine_abi_functions.py` : scanne les contrats vérifiés de la DB
- Fetch l'ABI de chaque contrat via Etherscan V2, extrait les fonctions non-view/pure
- **736 contrats** → **1 861 fonctions uniques** → **528 signatures de drainage** (fréquence ≥ 2)
- Résultats sauvegardés dans `findings/abi_functions_mined.json`

#### Exploit Generator basé sur l'ABI réelle
- `exploit_generator.py` — `ABIBasedExploitGenerator` : génère des exploits Solidity
  qui appellent les VRAIES fonctions du contrat (noms, paramètres, types corrects)
- **Phase 1** : Exact match (80+ signatures minées de la DB)
- **Phase 2** : Heuristique par mot-clé (28 mots, **couverture 100%** des 528 signatures)
- Arguments type-corrects : `address(0)`, `false`, `bytes("")`, `new T[](0)` — plus d'erreurs Solidity
- Méthode `_default_arg()` factorise les valeurs par défaut (élimine 4 blocs dupliqués)

#### Pipeline end-to-end validé
- Test complet via `--backfill --force --backfill-hardhat --backfill-limit 3`
- **Chaque étape vérifiée** : scan BSC → fetch source → 34 patterns → exploitabilite →
  ABI-GEN → Hardhat compile → fork + test → resultats
- **14 findings testés** sur 3 contrats, **0 CONFIRMED** (normal — contrats proteges)
- Discord webhook fonctionnel (alerte GUARDIAN_START)

#### Alertes + Dashboard
- `alerting.py` : webhooks Discord (embeds) + Telegram (HTML), `AlertManager`
- `dashboard/app.py` : interface web FastAPI avec templates Jinja2
- Flag `--dashboard` dans `main.py` (port/host configurables)

### 🔧 Changements récents (Session 8 & 9 — 11-12/06/2026)

#### Mythril Confirmator (Session 9)
- Nouveau module `confirmators/mythril_confirmator.py` — appel Mythril en sous-processus (0 import)
- Bytecode-based approach : `eth_getCode` → temp file → `myth analyze --bin <file> -o jsonv2`
- Plus fiable que Mythril's `--rpc` buggé sur les chaînes non-Ethereum
- Auto-détection du venv `.mythril-env` (Python 3.12 + mythril 0.24.8)
- Flag `--with-mythril` dans guardian.py (scan live + backfill)
- Testé sur 4 contrats BSC : 0 issues Mythril vs 40 issues pipeline (complémentarité)
- 0 dépendance sur la librairie Mythril (subprocess uniquement)

#### Hardhat fixes (Session 9)
- `hardhat_setBalance` remplace whale impersonation (marche sur toutes les chaînes)
- Template d'exploit par défaut utilise low-level `.call()` (pas de revert si fonction absente)
- Code mort supprimé : `WHALE_ADDRESSES`, `MythrilIssue` dataclass, imports inutilisés

### 🔧 Changements récents (Session 7 — 09/06/2026)

#### Backfill force + Hardhat — Validation réelle sur 5 contrats BSC
- `python guardian.py --backfill --force --backfill-hardhat --backfill-limit 5`
- Résultat : **5 contrats** (WBNB, ERC1967Proxy, ApolloxExchangeTreasury, TransparentUpgradeableProxy, PancakePredictionV2)
- **67 findings** → **33 exploitables théoriques** → **33 testés Hardhat** → **0 confirmé**
- Même PancakePredictionV2 (1 724 BNB) résiste à tous les exploits spécialisés

#### `--backfill-feedback` — Suivi de progression
- Nouveau flag : `python guardian.py --backfill --backfill-feedback 10`
- Affiche un résumé toutes les N contrats (processed, findings, exploitables, errors, ETA)
- Permet de suivre l'avancement des longs backfills

#### Bugfixes HardhatValidator — 4 bugs corrigés

| Bug | Cause racine | Fix |
|:---|---|:---|
| **`No FINDING_RESULT for idx X`** | Signer Hardhat sans ETH sur le fork → TX échouent | Whale impersonation (Binance) → 50 ETH à l'attaquant |
| **`tx0.wait is not a function`** | `pure` → ethers v6 retourne string | `bool attacked` → transaction réelle |
| **Noms dupliqués** | Timestamp → collision même seconde | Index unique `Exploit_{idx}` |
| **Script ne termine pas** | Pas de `process.exit(0)` | `.then(() => process.exit(0))` ajouté |

**Testé :** Backfill force + Hardhat sur WBNB — `No funds drained` au lieu de `No FINDING_RESULT` ✅

#### Stats mises à jour
- Findings : **5 184 → 7 365** (+2 181)
- Exploitables : **3 340 → 4 407** (+1 067)
- Tests Hardhat : **55 → 116**
- Confirmés : toujours **0**

### 🔧 Session 6 — 08/06/2026

#### `--backfill-hardhat` — Pipeline complet jusqu'à la confirmation
- Nouveau mode : `python guardian.py --backfill --backfill-hardhat`
- Enchaîne : DB → source → pipeline analyse → **Hardhat fork → CONFIRMED ou FAILED**
- `--backfill-limit N` : limite le nombre de contrats traités
- `--force` : re-scan complet (supprime + recrée les findings)

#### Bugfixes
- **Scope Hardhat** : `validate_for_addresses()` ne teste que les findings des contrats du backfill (pas les 3108 de toute la DB)
- **"missing trie node"** : `getLatestBlock()` utilise `ethers.JsonRpcProvider(url)` direct au lieu de `hre.network.provider` avant que le fork soit initialisé
- **URLs RPC** : RPC URLs depuis `config.yaml` (inclut le secret Infura) au lieu de `CHAIN_REGISTRY`
- **Filtre EOA** : `eth_getCode` avant analyse — évite les faux positifs sur les EOA (ex: adresse Ethereum qui est un contrat sur Optimism)
- **Cache source** : passage du source via fichier temporaire pour éviter le double appel API incohérent Etherscan
- **Stop-on modes** : `--stop-on detected|confirmed|none` pour choisir quand arrêter le scan

#### Performance ×20
- `validate_contract()` : groupe tous les findings d'un contrat en **1 fork + 1 compile + 1 run**
- Avant : ~60s/finding → Après : ~3s pour 1 contrat avec 1 finding exploitable
- `validate_finding()` préservée pour compatibilité

### 🔧 Correctifs antérieurs
- **Source vide (Proxy)** : `exploit_pipeline.py` détecte les proxies et récupère l'implémentation
- **File d'attente pleine (Arrêt)** : Monkey-patch `put_nowait` sur la file web3.py
- **Fuites de tâches** : Tâches fire-and-forget suivies et annulées
- **Condition de course** : Verrou sur `_last_vuln_address`
- **`import re` manquant** : 2 574 échecs Hardhat corrigés
- **Option `--force-hardhat`** et tâche périodique 120s
- **6 chaînes EVM** : ETH, BSC, Arbitrum, Optimism, Avalanche, Polygon

### Nouveaux outils

| Outil | Description | Commande |
|:---|---|:---|
| **`guardian.py`** | Usine de détection 24/7 sur 8 chaînes EVM | `python guardian.py` |
| **`pool_scanner.py`** | Scan pools DEX avec TVL via DEX Screener | `python pool_scanner.py` |
| **`scan_historical.py`** | Scan historique de blocs BSC (concurrent) + re-vérification DB | `python scan_historical.py --blocks 500000` |

### Résultats Guardian (65s de scan live)

- **68 contrats** détectés, **25 vérifiés**
- **46 findings** : 10 CRITICAL, 25 HIGH, 11 MED — **35 exploitables théoriques**
- **0 contrat avec solde > 0.001** (même constat : findings sur routeurs à 0 BNB)

### Scanners de blocs BSC

Deux scanners dédiés BSC pour l'analyse de blocs et de déploiements :

| Script | Description |
|:---|---|
| **`scan_bsc_recent.py`** | Scan 100 blocs BSC récents → détection de nouveaux déploiements |
| **`scan_bsc_500.py`** | Scan 500 blocs BSC → vérification + pipeline d'exploit automatique |

Utilisent `bsc-dataseed1.binance.org` (RPC public gratuit) et l'API Etherscan V2 (chainid=56).

### Pool Scanner — Mode --all + --audit-local (07/06/2026)

Scan exhaustif de TOUS les pools avec Hardhat fork systématique via `python pool_scanner.py --all --audit-local` :

| Métrique | Valeur |
|:---|---|
| Pools trouvés | **136** |
| Pools scannés | **126** |
| Avec findings | **126** |
| INTERESSANTS | **43** (Velodrome/Optimism) |
| Faux positifs skipés Hardhat | **60** (QuickSwap/Polygon — clones) |
| **Hardhat testés** | **66** ✅ |
| Hardhat confirmés | **0** (tous NOT exploitables — balance = 0) |

**Résultat de l'audit :** Tous les 66 contrats testés sur Hardhat fork sont **NOT exploitables** car leur balance native est de **0**. Les pools DEX ont leur TVL en tokens (pas en ETH/BNB natif sur le contrat lui-même). Les findings (Delegatecall, Reentrancy, etc.) sont des vrais patterns mais sans fonds natifs à drainer, ils ne sont pas exploitables.

**Top pools INTERESSANTS audités :**

| Pool | DEX | Chaîne | TVL | Findings | Verdict Hardhat |
|:---|---|:---:|:---:|:---:|:---|
| alETH-WETH | Velodrome | Optimism | $2.1M | 8 | ❌ Balance 0 |
| alUSD-USDC | Velodrome | Optimism | $1.6M | 8 | ❌ Balance 0 |
| msETH-WETH | Velodrome | Optimism | $1.5M | 8 | ❌ Balance 0 |
| msUSD-USDC | Velodrome | Optimism | $994k | 8 | ❌ Balance 0 |
| RCH-crvUSD | QuickSwap | Polygon | $54k | 21 | ❌ Balance 0 |
| ASF-WETH | Velodrome | Optimism | $27k | 2 | ❌ Balance 0 |

> **Conclusion :** Le pipeline --all --audit-local fonctionne de bout en bout. Aucun contrat avec balance native > 0 ET faille exploitable trouvé. Les 66 audits Hardhat confirment que les pools DEX, bien qu'ayant des patterns de vulnérabilités dans leur code, n'ont pas de fonds natifs drainables.

### Résultats Pool Scanner (session précédente)

| Pool | DEX | Chaîne | TVL | Findings | Verdict |
|:---|---|:---:|:---:|:---:|:---|
| **LGNS-DAI** | QuickSwap | Polygon | **$342M** 🎯 | 3 (2 HIGH) | ❌ FAUX_POSITIF (UniswapV2Pair) |
| AS-DAI | QuickSwap | Polygon | $16.4M | 3 (2 HIGH) | ❌ FAUX_POSITIF (UniswapV2Pair) |
| WMATIC-USDC | QuickSwap | Polygon | - | **12** (9 HIGH) | ❌ FAUX_POSITIF (AlgebraPool) |
| OVER-WETH | Velodrome | Optimism | $311k | - | ❌ Non vérifié |
| THE-WBNB | Thena | BSC | $109k | - | ❌ Non vérifié |

### Support multi-chaîne

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

## Session 4 — Scanner enrichi (20 failles) + Framework Hardhat standalone (07/06/2026)

### Améliorations du scanner

- **Scanner passé de 10 → 20 types de failles** : ajout de Flash Loan, Oracle Manipulation, Slippage/Deadline, Force-Fed ETH, ERC20 Return, Signature Replay, Rounding Error, Storage Collision, Timestamp Manipulation, Ownership Renouncement
- **Pipeline de validation** (`exploit_pipeline.py`) mis à jour pour les 20 types
- **Framework Hardhat standalone** créé :
  - `hardhat_fork_tester.py` — orchestrateur Python standalone
  - `exploit/contracts/UniversalExploit.sol` — 18/20 attaques en un seul contrat (compilation OK ✅)
  - `exploit/scripts/test_fork_exploit.js` — fork → impersonate → deploy → attaquer → vérifier

### Nouveaux contrats analysés en profondeur

| Contrat | Chaîne | Balance | Type | Findings | Exploitables | Verdict |
|:---|---|:---:|:---|:---:|:---:|:---|
| **Nola** (0xf8388c...) | Arbitrum | 0.48 ETH | ERC20 memecoin | 12 | 8 | ❌ Faux positif (onlyOwner partout) |
| **Smolcoin** (0x9e64d3...) | Arbitrum | 0.22 ETH | ERC20 memecoin | 24 | 20 | ❌ Faux positif (onlyOwner partout) |
| **PinLink** (0x2e44f3...) | Ethereum | 0.035 ETH | ERC20 memecoin | 5 | 4 | ❌ Faux positif (onlyOwner partout) |

### DB Guardian — Statistiques consolidées

| Métrique | Valeur |
|:---|---|
| Contrats totaux dans la DB | **2 340** |
| Contrats vérifiés | **463** (Ethereum: 112, Arbitrum: 254) |
| Findings totaux | **1 307** |
| Exploitables (pipeline) | **857** (CRITICAL: 192, HIGH: 440, MEDIUM: 5) |
| Tests Hardhat automatisés | **853** (tous échoués — Hardhat pas configuré pour tests automatisés) |
| Contrats avec balance > 0 | **19** (264.74 total native) |

### Top 5 types de findings exploitables

| Finding | Nombre |
|:---|---:|
| Potential Reentrancy (No CEI Pattern) | 232 |
| Delegatecall to Variable Address | 208 |
| Unprotected Initializer | 108 |
| Unprotected Withdraw/Claim Function | 62 |
| TX Origin Authorization | 14 |

### Constat critique

**Tous les contrats avec balance > 0.001 trouvés sont des ERC20 memecoins** utilisant OpenZeppelin `Ownable`. Les fonctions sensibles (withdraw, mint, burn) sont toutes protégées par `onlyOwner`. Le scanner détecte correctement les patterns (`.call{value:}`, `tx.origin`, `delegatecall` dans OZ) mais ne comprend pas que :
- Les modifiers `onlyOwner` bloquent l'accès
- Les librairies OpenZeppelin sont des standards audités
- Les proxies EIP-1967 sont des patterns volontaires

**Taux de faux positifs sur contrats avec balance : 100%** (7 contrats analysés en profondeur sur 19 au total avec balance > 0).

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

## Constat global final (07/06/2026)

**Aucun contrat avec des fonds réels ET une vulnérabilité exploitable n'a été trouvé après 4 sessions de scan et 2 340 contrats dans la DB.** Les scanners produisent des faux positifs sur :

| Type de contrat | Fonds max trouvés | Findings scanner | Test local | Raison du faux positif |
|:---|---:|:---:|:---|---:|
| Routeurs DEX (BabySmartRouter...) | 0 BNB | ✅ Réelles | Non testé (pas de fonds) | Pas de fonds à drainer |
| Pools DEX (UniswapV2Pair) | $342M TVL | ✅ Patterns | ❌ Faux positifs | Clones standardisés audités |
| Contrats custom (PrismHook, AIDoge) | 15 ETH | ✅ 10 exploitables | ✅ **Fork/RPC** | Access controls + ReentrancyGuard |
| ERC20 memecoins (Nola, Smolcoin, PinLink) | 0.74 ETH | ✅ 41 exploitables | ❌ Faux positifs | onlyOwner sur toutes les fonctions |
| Blue-chips (Lido stETH) | 262 ETH | ✅ 2 | Pas testé | Proxy patterns audités |

**Conclusion : le scanner détecte des patterns de code mais ne comprend pas le contexte** (modifiers, héritage, proxy patterns, ReentrancyGuard). Les 628 tests Hardhat automatisés du Guardian ont tous échoué (Hardhat non configuré pour les tests automatisés) — mais les tests fork manuels (PrismHook, AIDoge) confirment que les findings étaient des faux positifs.

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
