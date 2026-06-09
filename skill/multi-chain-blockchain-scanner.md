# Compétence : Scanner de Transactions Multi-Chain Blockchain (Python)

## 1. Architecture

### Pattern : Scanners asynchrones modulaires avec BaseScanner ABC
- `BaseScanner` (abstrait) : cycle de vie WebSocket, reconnexion automatique avec backoff exponentiel, statistiques, émission d'événements
- `EVMScanner` : Ethereum, Polygon, BSC, Arbitrum (web3.py v7 asynchrone)
- `BitcoinScanner` : Bitcoin via l'API WebSocket mempool.space
- `SolanaScanner` : Solana via WebSocket solana.py
- `ScannerOrchestrator` : Démarre/arrête tous les scanners, achemine les événements, gère l'affichage
- `DisplayManager` : Sortie terminal Rich (doit être compatible ASCII sur Windows)
- `TransactionFilter` : Filtrage par adresse/valeur/pattern
- `SourceCodeVerifier` : Vérification du code source des contrats via l'API Etherscan V2
- `VulnerabilityScanner` : Analyse des vulnérabilités du code source Solidity (**20 patterns**)
- `Guardian` : Scanner 24/7 persistant avec DB SQLite, auto-persistance, pipeline Hardhat
- `ForkTester` : Framework de test fork Hardhat autonome (`hardhat_fork_tester.py`)

### Structure étendue du projet
```
blockchain_scanner/
  config.yaml                        # Configuration YAML
  main.py                            # Point d'entrée CLI (argparse)
  guardian.py                        # Scanner 24/7 + persistance SQLite
  exploit_pipeline.py                # Pipeline automatisé de validation des vulnérabilités (20 types)
  hardhat_fork_tester.py             # Framework de test fork autonome
  pool_scanner.py                    # Scanner de pools DEX via l'API DEX Screener
  clean_hardhat.bat                 # Tueur sélectif de processus Hardhat (wmic + PS fallback)
  run_forever.bat                   # Boucle de redémarrage auto avec nettoyage Hardhat
  run_guardian.bat                  # Démarrer/Arrêter le Guardian avec nettoyage Hardhat
  scan_bsc_recent.py                 # Scanner les 100 derniers blocs BSC pour les nouveaux déploiements
  scan_bsc_500.py                    # Scanner 500 blocs BSC + pipeline d'exploit automatique
  scan_historical.py                 # Scanner des millions de blocs BSC historiques en concurrence
  scanner/
    base.py                          # BaseScanner ABC
    evm_scanner.py                   # Chaînes EVM
    bitcoin_scanner.py               # Bitcoin
    solana_scanner.py                # Solana
    orchestrator.py                  # Cycle de vie scanner + scan de vulnérabilités
  confirmators/
    __init__.py                      # Paquet confirmator
    mythril_confirmator.py           # Exécution symbolique Mythril (sous-processus, 0 dépendance d'import)
  .mythril-env/                      # Venv Python 3.12 + mythril 0.24.8
  analysis/
    vulnerability_scanner.py         # Scanner de vulnérabilités Solidity (20 patterns)
    __init__.py
  filters/
    filters.py                       # Filtres de transactions
  output/
    display.py                       # Affichage terminal (sortie des vulnérabilités ajoutée)
  verify.py                          # Vérification du code source via Etherscan V2
  exploit/                           # Démos d'exploitation Hardhat locales
    contracts/
      VulnerableBank.sol             # Banque délibérément vulnérable (reentrancy)
      Exploit.sol                    # Contrat d'attaque par reentrancy
      ExploitV2.sol                  # Version de débogage avec maxRounds configurable
      CampaignVulnerable.sol         # Reproduction de reentrancy CEI
      CampaignExploit.sol            # Exploit CEI avec garde-fou
      PrismReentrancyExploit.sol        # Exploit spécifique à PrismHook
      AIDogeExploit.sol                 # Exploit spécifique à AIDoge
      UniversalExploit.sol              # Exploit universel : 28 types d'attaque, 80+ signatures
      PredictionV2OracleManipulator.sol # Manipulation d'oracle PredictionV2
      PredictionV2ReentrancyExploit.sol # Reentrancy PredictionV2
      PredictionV2TXOriginExploit.sol   # Exploit tx.origin PredictionV2
      PredictionV2DelegatecallExploit.sol # Delegatecall PredictionV2
      PredictionV2TreasuryExploit.sol   # Drainage de trésorerie PredictionV2
    scripts/
      deploy_and_exploit.js                  # Démo complète d'attaque par reentrancy
      test_campaign_reentrancy.js            # Validation CEI CampaignWrapper
      test_cei_reentrancy.js                 # Suite de validation combinée
      test_simple_withdraw.js                # Vérification de base
      test_fork_exploit.js                   # Exploitation fork universelle (28 attaques)
      test_prediction_v2_all.js              # Suite maître PredictionV2
      test_prediction_v2_oracle_manipulation.js
      test_prediction_v2_reentrancy.js
      test_prediction_v2_delegatecall.js
      test_prediction_v2_txorigin.js
      test_prediction_v2_treasury.js
    generated/                               # Fichiers de test générés dynamiquement
    hardhat.config.js                # Configuration Hardhat (Solidity 0.8.20, allowUnlimitedContractSize)
    package.json
    .gitignore
```

## 2. API asynchrone web3.py v7 (Critique)

### Problème
`Web3.AsyncWebsocketProvider` n'existe PAS dans web3.py v7.

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

## 3. Compatibilité BSC (extraData) + Déconnexion WebSocketProvider

Utiliser le repli de polling RPC brut pour BSC :
```python
resp = await w3.provider.make_request("eth_getBlockByNumber", [hex(number), False])
block = resp["result"]
```

**Correctif d'arrêt :** Toujours appeler `provider.disconnect()` avant le nettoyage + **monkey-patch `put_nowait`** sur la file d'abonnement pour intercepter `asyncio.QueueFull` (supprimé pendant l'arrêt, journalisé comme avertissement pendant le fonctionnement normal) :
```python
async def _disconnect(self):
    if self.w3 and hasattr(self.w3, 'provider'):
        await self.w3.provider.disconnect()  # Arrêter d'abord l'écouteur de messages interne
    ...

# Dans _connect() : monkey-patch de la file pour survivre à QueueFull pendant l'arrêt
q = provider._request_processor._subscription_response_queue
_orig = q.put_nowait
q.put_nowait = lambda item: _orig(item) if not queue_full else ...
```

## 4. Encodage Windows cp1252

Toujours utiliser une sortie compatible ASCII :
```python
def _s(text: str) -> str:
    return text.encode('ascii', errors='replace').decode('ascii')
```

## 5. Endpoints RPC

| Chaîne | Endpoint | Fournisseur |
|:---|:---|:---|
| BSC HTTP | `https://bsc-dataseed1.binance.org` | Binance |
| BSC WS | `wss://bsc.publicnode.com` | PublicNode |

## 6. Code source des contrats via Etherscan API V2

```python
EXPLORER_API_V2_URL = "https://api.etherscan.io/v2/api"
# chainid=56 for BSC, 1 for Ethereum
```

## 7. Scanner de Vulnérabilités Solidity — 20 Types

### Tableau complet des vulnérabilités

| ID | Vulnérabilité | Sévérité | Description |
|:---|:---|---:|:---|
| `reentrancy` | Reentrancy (changement d'état APRÈS appel externe) | CRITIQUE | `.call{value:}` avant mise à jour d'état |
| `selfdestruct` | Le contrat peut être détruit | CRITIQUE | `selfdestruct`/`suicide` sans ACL |
| `delegatecall` | Exécution de code dans le contexte de l'appelant | CRITIQUE | Cible `delegatecall` dynamique |
| `tx-origin` | Autorisation tx.origin | ÉLEVÉE | `tx.origin` utilisé pour l'auth — phishing |
| `unprotected-withdraw` | Retrait sans ACL | ÉLEVÉE | Retrait/claim sans contrôle d'accès |
| `unprotected-init` | Initialiseur sans modificateur | ÉLEVÉE | `initialize()` appelable plusieurs fois |
| `unchecked-call` | Résultat d'appel externe non vérifié | MOYENNE | Valeur de retour `.call()` non vérifiée |
| `integer-overflow` | Arithmétique sans SafeMath (pre-0.8) | MOYENNE | Pas de protection contre les overflow |
| `gas-loop` | Boucle illimitée sur tableau dynamique | MOYENNE | DOS par épuisement de gas |
| `arbitrary-from` | transferFrom avec 'from' contrôlé par l'utilisateur | MOYENNE | Paramètre `from` non validé |
| `flash-loan` | Susceptibilité au flash loan | ÉLEVÉE | Swap DEX sans contrôle d'accès |
| `oracle-manipulation` | Manipulation du prix de l'oracle | ÉLEVÉE | Prix spot (getReserves) au lieu de TWAP |
| `slippage-deadline` | Slippage/deadline manquant | ÉLEVÉE | Slippage zéro ou pas de deadline — MEV |
| `force-feed-eth` | Manipulation par ETH forcé | MOYENNE | `address(this).balance` via selfdestruct |
| `erc20-return` | Valeur de retour ERC20 non vérifiée | MOYENNE | Retour de `transfer()` non vérifié (USDT) |
| `signature-replay` | Attaque par rejeu de signature | ÉLEVÉE | `ecrecover` sans chainId/nonce |
| `rounding-error` | Division avant multiplication | MOYENNE | Perte de précision due à l'arrondi |
| `storage-collision` | Collision de stockage dans un proxy | ÉLEVÉE | Upgradeable sans `__gap` |
| `timestamp-manipulation` | Manipulation du timestamp de bloc | MOYENNE | `block.timestamp` dans une logique critique |
| `ownership-renounce` | Renonciation à la propriété | MOYENNE | `renounceOwnership()` sans récupération |

### Stratégie de détection des reentrancy
- Trouver les appels externes avec valeur (`.call{value:...}()`, `.send()`)
- Ignorer `.transfer()` (limité à 2300 gas)
- Vérifier le modificateur `nonReentrant`
- Chercher les changements d'état AVANT l'appel externe (violation CEI)
- CRITIQUE si changement d'état avant l'appel, ÉLEVÉE si appel sans modificateur

### Limitation clé du scanner

Le scanner détecte les **patterns de code** mais ne **comprend pas** le contexte :
- Modificateurs `onlyOwner` : les fonctions sont signalées mais en fait protégées
- Patterns de proxy (EIP-1967) : `delegatecall` est intentionnel
- Librairies OpenZeppelin : `Ownable`, `ReentrancyGuard` sont des standards audités
- **Résultat :** ~85% de taux de faux positifs sur les contrats audités, **100% sur les memecoins ERC20 avec balance**

## 8. Pipeline d'Exploit

### Utilisation
```bash
python exploit_pipeline.py --address 0x... --chain bsc
python exploit_pipeline.py --live --chains bsc,ethereum
python exploit_pipeline.py --batch addresses.txt
```

### Validation d'exploitabilité (20 types) + Repli Proxy

Quand `SourceCode` est vide (courant avec les contrats proxy), le pipeline détecte maintenant les champs `Proxy`/`Implementation` de l'API Etherscan et récupère automatiquement le code source de l'implémentation.

| Type de finding | Exploitable ? | Condition |
|:---|:---|---:|
| Reentrancy | OUI | Solidity < 0.8 |
| Reentrancy | OUI | Solidity >= 0.8 AVEC unchecked {} |
| Reentrancy | PARTIEL | Solidity >= 0.8 (CEI sur bool — pas arithmétique) |
| Selfdestruct | OUI | Sans ACL |
| Delegatecall | OUI | Cible dynamique |
| Flash Loan | OUI | Fonction Swap sans contrôle d'accès |
| Oracle Manipulation | OUI | Utilise getReserves() sans TWAP |
| Slippage/Deadline | OUI | amountOutMin = 0 ou pas de deadline |
| ERC20 Return | OUI | Appel transfer() sans require(success) |
| Signature Replay | OUI | ecrecover sans chainId ni nonce |
| Storage Collision | OUI | Contrat Upgradeable sans __gap |

### Découverte clé : Solidity >=0.8 bloque la reentrancy par underflow
`balances[msg.sender] -= amount` revient avec `panic(0x11)` en cas d'underflow en 0.8+.
En < 0.8, il y a wrapping (0 - 1 = 2^256 - 1), ce qui permet l'exploit.

## 9. Framework de Test Fork Hardhat

### UniversalExploit.sol
Contrat unique testant **18 des 20** types d'attaque (exclut `tx-origin` et `signature-replay` qui nécessitent une configuration de phishing/scénario) :
- Reentrancy (CEI), Selfdestruct, Delegatecall, Retrait non protégé, Init non protégé
- Appel non vérifié, Overflow d'entier, Boucle gas, transferFrom arbitraire
- Flash Loan, Manipulation d'oracle, Slippage/Deadline, ETH forcé
- Retour ERC20, Erreur d'arrondi, Collision de stockage, Timestamp, Renonciation

### Flux du test fork
```
1. Forker la chaîne au dernier bloc
2. Usurper le propriétaire du contrat cible
3. Déployer UniversalExploit
4. Pour chaque type d'attaque : attaquer → vérifier le solde → journaliser le résultat
5. Reporter l'ETH drainé (si applicable)
```

### Utilisation
```bash
# Via l'orchestrateur Python
python hardhat_fork_tester.py --target 0x... --chain arbitrum

# Hardhat direct
cd exploit
npx hardhat compile
npx hardhat run scripts/test_fork_exploit.js --network hardhat 0x... https://rpc 0.05
```

## 10. Statistiques Guardian 24/7 (08/06/2026)

| Métrique | Valeur |
|:---|---|
| Contrats dans la DB | **24 945** |
| Contrats vérifiés | **985** |
| Findings totaux | **7 365** |
| Exploitables | **4 407** |
| Tests Hardhat exécutés | **116** (55 batch + 5 PredictionV2 + 1 dynamique + 55 backfill-force) |
| Exploits confirmés | **0** |
| Résultat du batch | 55 contrats, 0 confirmé |
| Chaînes actives | **6** (ETH, BSC, Arbitrum, Optimism, Avalanche, Polygon) |
| Vulnérabilités scannées | **29** (20 base + 9 OpenZeppelin) |

### Nouveaux outils (Session 5)

| Outil | Description | Commande |
|:---|---|:---|
| **`dynamic_test_generator.py`** | Génère des tests JS Hardhat depuis les findings DB | `python hardhat_fork_tester.py --dynamic` |
| **Exploits PredictionV2** | 5 contrats + 6 scripts pour PancakeSwap Prediction | `--specialized prediction-v2` |
| **UniversalExploit v2** | 28 attaques, 80+ signatures DeFi | Via `test_fork_exploit.js` |
| **Mode Batch** | Teste TOUS les contrats avec balance | `python hardhat_fork_tester.py --batch` |

### Types de findings les plus fréquents (exploitables)
1. Potential Reentrancy
2. Delegatecall to Variable Address
3. Unprotected Initializer
4. Unprotected Withdraw/Claim Function
5. TX Origin Authorization

### Mode Backfill-Hardhat
- `python guardian.py --backfill --backfill-hardhat` — pipeline complet de la DB à la confirmation Hardhat
- `python guardian.py --backfill --force` — forcer le re-scan (supprimer + recréer les findings)
- `python guardian.py --backfill --backfill-limit 10` — limiter à N contrats
- `python guardian.py --backfill --backfill-hardhat --backfill-feedback 10` — retour de progression toutes les N contrats
- `python guardian.py --backfill --force --backfill-hardhat` — pipeline complet avec re-scan forcé + validation Hardhat

### Modes d'arrêt automatique
- `--stop-on detected` — s'arrêter au premier HIGH/CRITICAL (défaut)
- `--stop-on confirmed` — s'arrêter uniquement après confirmation par le pipeline
- `--stop-on none` — ne jamais s'arrêter automatiquement (manuel)

### Performance : optimisation ×20
- `validate_contract()` regroupe tous les findings d'un contrat en 1 fork + 1 compile + 1 run Hardhat
- Avant : ~60s/finding → Nouveau : ~3s pour 1 contrat avec 1 finding exploitable
- `validate_for_addresses()` et `validate_all_pending()` groupent par contrat automatiquement
- `validate_finding()` préservée pour la rétrocompatibilité

### Correctifs : Filtre EOA, Cache source, URLs RPC
- **Filtre EOA** : `eth_getCode` avant analyse — évite les faux positifs sur les adresses EOA
- **Cache source** : passe `--cached-source` via fichier temporaire pour éviter les appels API Etherscan en double (incohérents entre appels)
- **URLs RPC** : utilise les URLs RPC de `config.yaml` (avec le secret Infura) au lieu de `CHAIN_REGISTRY` codé en dur
- **Correctif `getLatestBlock()`** : utilise `ethers.JsonRpcProvider(url)` directement au lieu de `hre.network.provider` avant l'initialisation du fork

### Mode --force-hardhat
- Option CLI `--force-hardhat` ajoutée pour contourner le seuil de balance (0.001)
- Validation Hardhat périodique toutes les 120s pour les contrats existants
- Redémarrage automatique `run_forever.sh` en cas de plantage (boucle infinie, pas de git push)

## 11. Évolution du projet

### Construit dans la Session 9 — Mythril + venv + hardhat_setBalance
1. **`confirmators/mythril_confirmator.py`** (nouveau) — appel Mythril en sous-processus, 0 import de la librairie
2. **Approche basée sur le bytecode** : `eth_getCode` → fichier temporaire → `myth analyze --bin <file> -o jsonv2` (plus fiable que `--rpc`)
3. **Auto-détection du venv** : `.mythril-env/Scripts/python.exe` avec Python 3.12 + mythril 0.24.8
4. **Options CLI** : `--with-mythril`, `--mythril-dir` sur `guardian.py`
5. **Correctif Hardhat** : `hardhat_setBalance` remplace l'usurpation de baleine, template d'exploit bas niveau `.call()`
6. **Code mort supprimé** : `WHALE_ADDRESSES`, `MythrilIssue` dataclass, imports inutilisés

### Construit dans la Session 8 — Gestion des processus + Nettoyage Hardhat
1. **Correctif `kill_all_node_processes()`** : Remplacé `taskkill /F /IM node.exe` (tue TOUS les node.exe y compris Codebuff) par `wmic` avec filtre `CommandLine LIKE '%hardhat%'` + `taskkill /F /T /PID` (ciblé et tree kill). Retourne maintenant un dict `{killed, error}`.
2. **`clean_hardhat.bat`** (nouveau) : script autonome avec 3 modes (kill, check, loop), double méthode wmic + PowerShell
3. **`run_forever.bat`** (modifié) : appelle `call clean_hardhat.bat` avant chaque redémarrage et en début de boucle
4. **`run_guardian.bat`** (modifié) : appelle `call clean_hardhat.bat` à l'arrêt (`--stop`)
5. **Option CLI `--cleanup`** sur `guardian.py` : `python guardian.py --cleanup` tue sélectivement les processus Hardhat depuis Python
6. **Auto-nettoyage dans validate_finding() et validate_contract()** : chaque test Hardhat commence par `kill_all_node_processes()` pour garantir un état propre
7. Tous les `.md` mis à jour

### Construit dans la Session 7
1. `--backfill --force --backfill-hardhat` : Pipeline complet avec re-scan forcé + validation Hardhat
2. `--backfill-feedback` : Suivi de progression (processed, findings, exploitables, errors, ETA)
3. **4 correctifs de bugs dans HardhatValidator** :
   - Correctif de financement par usurpation de baleine (`No FINDING_RESULT for idx X`)
   - Correctif du contrat d'exploit non-`pure` (`tx0.wait is not a function`)
   - Correctif de nommage par index (collision des noms)
   - Correctif `process.exit(0)` (script bloqué)
4. Backfill force + Hardhat validé sur WBNB : pipeline fonctionnel ✅
5. Statistiques Guardian mises à jour : 7 365 findings, 4 407 exploitables, 116 tests Hardhat, 0 confirmé
6. Tous les fichiers `.md` mis à jour avec les derniers changements

### Construit dans la Session 6
1. `--backfill-hardhat` : Pipeline complet de la DB à la confirmation Hardhat
2. `--stop-on detected|confirmed|none` : 3 modes d'arrêt automatique pour main.py
3. Mode `--backfill` dans guardian.py : re-scanner tous les contrats vérifiés de la DB
4. `validate_contract()` : Optimisation des performances ×20 (1 fork/contrat)
5. Filtre EOA : `eth_getCode` avant scan pour éviter les faux positifs cross-chain
6. Cache source : éviter les appels API Etherscan en double via fichier temporaire
7. Correctif URL RPC : utiliser les URLs config.yaml (avec le secret Infura) pour le fork Hardhat
8. Correctif `getLatestBlock()` : utiliser JsonRpcProvider direct au lieu du provider Hardhat
9. `validate_for_addresses()` : validation cadrée pour le mode backfill
10. Tous les fichiers `.md` mis à jour avec les derniers changements

### Construit dans la Session 5
1. UniversalExploit v2 : 28 types d'attaque, 80+ signatures
2. 5 contrats d'exploit PredictionV2 + 6 scripts JS
3. dynamic_test_generator.py
4. Mode Batch : 55 contrats testés, 0 confirmé
5. Configuration Hardhat : allowUnlimitedContractSize
6. Correctif TDZ dans test_fork_exploit.js

### Construit dans la Session 4
1. Scanner de vulnérabilités étendu de 10 à 20 patterns Solidity
2. UniversalExploit.sol — contrat unique pour 18/20 types d'attaque
3. test_fork_exploit.js — script d'exploitation fork générique
4. hardhat_fork_tester.py — orchestrateur Python pour les tests fork
5. scan_bsc_recent.py — scanner de déploiements BSC sur 100 blocs
6. scan_bsc_500.py — scanner BSC par lots de 500 blocs + pipeline d'exploit automatique
7. pool_scanner.py — scanner de pools DEX via DEX Screener
8. pool_scanner.py --all mode — scanner TOUS les pools
9. pool_scanner.py --audit-local — test fork Hardhat systématique
10. Premier scan --all : 136 pools, 126 scannés
11. Découverte : 100% de taux de faux positifs sur les contrats avec balance
12. Repli proxy dans exploit_pipeline

## Validation concrète vs Détection de patterns

Le scanner trouve des patterns, pas des vulnérabilités. Exemples clés :
- WETH9 : `withdraw()` sans onlyOwner signalé comme ÉLEVÉ — mais le pattern CEI est respecté, utilise `.transfer()`
- Nola/Smolcoin/PinLink : 41 exploitables signalés — mais toutes les fonctions derrière `onlyOwner`
- Lido stETH : `delegatecall` signalé comme CRITIQUE — mais c'est un proxy EIP-1967 intentionnel
- **~85% des findings sur les contrats audités sont des faux positifs**

### Modes du Scanner de Pools

| Option | Description |
|:---|:---|
| `--all` / `-a` | Scanner TOUS les pools retournés par DEX Screener (sans filtre TVL, sans limite) |
| `--min-tvl X` / `-t X` | Scanner uniquement les pools avec TVL >= X$ USD |
| `--audit-local` / `-l` | Exécuter un test fork Hardhat sur chaque contrat scanné avec des findings exploitables |
| `--top N` / `-n N` | Max de pools par DEX (défaut : 5, ignoré avec --all) |

**Retour en direct** : Chaque résultat de pool est affiché immédiatement avec le tag `[LIVE]`, le verdict et le nombre de findings.

**Intégration Hardhat** : La méthode `_audit_hardhat()` initialise paresseusement HardhatForkTester, pré-compile les contrats une fois, puis exécute les tests fork avec un délai d'attente de 240s par contrat. Ignore automatiquement les clones standard (UniswapV2Pair etc.).

**Premiers résultats du scan --all (07/06/2026) :** 136 pools trouvés, 126 scannés, 43 INTÉRESSANTS (Velodrome/Optimism), 60 faux positifs (QuickSwap/Polygon clones).

### Outils de scan spécifiques à BSC

| Outil | Description | RPC |
|:---|:---|:---|
| `scan_bsc_recent.py` | Scanner les 100 derniers blocs BSC pour les nouveaux déploiements | `bsc-dataseed1.binance.org` |
| `scan_bsc_500.py` | Scanner 500 blocs BSC, auto-vérification + pipeline d'exploit | `bsc-dataseed1.binance.org` |
| `pool_scanner.py` | Scanner les pools BSC PancakeSwap/Thena via l'API DEX Screener | Etherscan V2 chainid=56 |
| `hardhat_fork_tester.py` | Forker BSC au dernier bloc, tester les exploits | `bsc-dataseed1.binance.org` |

Tous les outils BSC utilisent un RPC public gratuit — aucune clé API requise pour le scan de blocs.

### Résultats de scan par chaîne
| Chaîne | Contrats | Vérifiés | Balance |
|:---|---:|---:|:---:|
| Ethereum | 1 257 | 112 | 261.47 ETH |
| Arbitrum | 572 | 254 | 3.27 ETH |

### Leçon clé
Toujours valider les findings empiriquement. Le pipeline donne une analyse théorique (version Solidity, blocs unchecked, contrôle d'accès), mais le test fork sur Hardhat est la seule façon de confirmer l'exploitabilité. Le scanner détecte des patterns de code — l'humain (ou une IA plus intelligente) doit interpréter le contexte.

### Validation CEI Reentrancy

**CampaignWrapper** (0x8a56c6be..) — 7 findings HAUTE, 1 MOYENNE. Validé empiriquement sur reproduction :
- Création de CampaignVulnerable.sol (reproduit `.call{value:}` AVANT la mise à jour d'état)
- Création de CampaignExploit.sol (rentre via `receive()` avant que `hasClaimed` soit défini)
- **5 rounds de reentrancy confirmés** — 5 ETH drainés de 5 ETH
- **Mais faux positif sur le contrat réel :** `_refund` est `private` + `nonReentrant` au niveau supérieur

**Découverte clé :** La reentrancy CEI sur les booléens fonctionne en Solidity >=0.8 car :
- `!hasClaimed[user]` n'est PAS arithmétique — aucune protection contre les underflows ne s'applique
- La mise à jour d'état (bool = true) a lieu APRÈS `.call{value:}`
- La vérification passe à chaque fois pendant la reentrancy car l'état n'a pas encore été mis à jour

**Correctif pour la reentrancy >=0.8 :** Utiliser le modificateur `ReentrancyGuard`, PAS seulement la protection contre les underflows.
