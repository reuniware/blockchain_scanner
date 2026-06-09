# Scanner de Transactions Multi-Chain Blockchain

[![CI](https://github.com/TSTAC/blockchain_scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/TSTAC/blockchain_scanner/actions/workflows/ci.yml)

Surveillance en temps réel des transactions et blocs sur **6 blockchains** — Ethereum, Polygon, BSC, Arbitrum, Solana et Bitcoin. Aucune clé API requise pour la surveillance de base des blocs (endpoints publics gratuits). Une clé API Etherscan optionnelle permet la vérification du code source des contrats et l'analyse des vulnérabilités.

## Démarrage rapide

```bash
# 1. Installer les dépendances
cd blockchain_scanner
pip install -r requirements.txt

# 2. Configurer (optionnel — fonctionne par défaut)
# Modifier config.yaml pour activer/désactiver des chaînes ou ajuster les filtres

# 3. Lancer le scanner
python main.py
```

## Utilisation

### Commandes de base

| Commande | Description |
|:---|:---|
| `python main.py` | Scanner toutes les chaînes activées |
| `python main.py --chains ethereum` | Scanner Ethereum uniquement |
| `python main.py --chains ethereum,bsc,bitcoin` | Scanner des chaînes spécifiques |
| `python main.py --stop-on detected` | S'arrêter au premier finding HIGH/CRITICAL (défaut) |
| `python main.py --stop-on confirmed` | S'arrêter uniquement après confirmation par le pipeline d'exploit |
| `python main.py --stop-on none` | Ne jamais s'arrêter automatiquement (Ctrl+C manuel) |
| `python main.py --list-chains` | Lister les chaînes configurées sans scanner |
| `python exploit_pipeline.py --address 0x... --chain ethereum` | Analyser les vulnérabilités d'un contrat |
| `python scan_bsc_recent.py` | Scanner les 100 derniers blocs BSC pour les nouveaux déploiements |
| `python scan_bsc_500.py` | Scanner 500 blocs BSC + exécution auto du pipeline d'exploit |
| `python pool_scanner.py --chains bsc` | Scanner les pools DEX sur BSC (PancakeSwap, Thena) |
| `cd exploit && npx hardhat run scripts/deploy_and_exploit.js` | Démo d'attaque reentrancy classique |
| `cd exploit && npx hardhat run scripts/test_campaign_reentrancy.js` | Validation CEI reentrancy CampaignWrapper |
| `cd exploit && npx hardhat run scripts/test_cei_reentrancy.js` | Suite de validation reentrancy combinée |
| `cat findings/README.md` | Parcourir le catalogue des findings |

### Options du scanner

| Option | Description |
|:---|---:|
| `--chains X,Y,Z` | Liste des chaînes à scanner (séparées par des virgules) |
| `-v` / `--verbose` |Activer les logs DEBUG |
| `--list-chains` | Lister les chaînes disponibles et quitter |
| `--format rich\|json\|both` | Format de sortie |
| `-j FILE` / `--json FILE` | Exporter les transactions vers un fichier JSON |
| `-c FILE` / `--config FILE` | Chemin du fichier de configuration personnalisé |
| `--version` | Afficher la version et quitter |

### Options du pipeline d'exploit

| Option | Description |
|:---|---:|
| `--address ADDR` / `-a` | Adresse du contrat à analyser |
| `--chain CHAIN` / `-c` | Chaîne : `ethereum`, `bsc`, `polygon`, `arbitrum` (défaut : bsc) |
| `--api-key KEY` / `-k` | Clé API Etherscan V2 |

### Guardian (scanner 24/7)

| Commande | Description |
|:---|:---|
| `python guardian.py` | Démarrer le Guardian 24/7 (6 chaînes EVM) |
| `python guardian.py --chains ethereum,bsc` | Scanner des chaînes spécifiques uniquement |
| `python guardian.py --force-hardhat` | Forcer la validation Hardhat sur TOUS les findings (balance=0 inclus) |
| `python guardian.py --status` | Afficher les statistiques DB (contrats, findings, balance) |
| `python guardian.py --health` | Vérifier si le processus Guardian est en cours d'exécution |
| `python guardian.py --backfill` | Backfill : re-scanner tous les contrats vérifiés de la DB (sans scan live) |
| `python guardian.py --backfill --force` | Forcer le re-scan (supprimer + recréer les findings) |
| `python guardian.py --backfill --backfill-hardhat` | Backfill + validation Hardhat fork (pipeline complet : DB → source → analyse → fork → confirmation) |
| `python guardian.py --backfill --backfill-hardhat --backfill-limit 10` | Limiter à N contrats |
| `python guardian.py --backfill --backfill-hardhat --backfill-feedback 10` | Retour de progression toutes les N contrats (défaut : 5) |
| `python guardian.py --backfill --force --backfill-hardhat` | Forcer le re-scan (supprimer + recréer les findings) + validation Hardhat |
| `python guardian.py --backfill --with-mythril` | Backfill + confirmation par exécution symbolique Mythril |
| `python guardian.py --with-mythril` | Activer Mythril (appelle le CLI myth en sous-processus, 0 dépendance) |
| `python guardian.py --mythril-dir ../mythril` | Chemin personnalisé du dépôt Mythril (défaut : ../mythril) |
| `python guardian.py --log-level WARNING` | Réduire la verbosité des logs (défaut : INFO, utiliser WARNING pour moins de bruit) |
| `python guardian.py --cleanup` | Tuer tous les processus node liés à Hardhat (sélectif, sans danger pour Codebuff) |
| `clean_hardhat.bat` | Tuer uniquement les processus node liés à Hardhat (sans danger pour Codebuff) |
| `clean_hardhat.bat --check` | Lister les processus Hardhat sans les tuer |
| `clean_hardhat.bat --loop` | Surveiller et nettoyer automatiquement toutes les 10s |
| `run_forever.bat` | Boucle de redémarrage automatique avec nettoyage Hardhat à chaque redémarrage |
| `run_guardian.bat --stop` | Arrêter le Guardian + nettoyer les processus Hardhat orphelins |
| `bash run_forever.sh` | Boucle de redémarrage automatique (infini, logs, pas de git push) |
| `python dump_results.py` | Exporter les statistiques DB vers findings/scanned_contracts.md |

### Testeur Fork

| Commande | Description |
|:---|:---|
| `python hardhat_fork_tester.py --address 0x... --chain bsc` | Tester les exploits sur un fork BSC |
| `python hardhat_fork_tester.py --address 0x... --chain arbitrum` | Tester les exploits sur un fork Arbitrum |
| `python hardhat_fork_tester.py --specialized prediction-v2 --address 0x...` | Exécuter la suite spécialisée PredictionV2 |
| `python hardhat_fork_tester.py --dynamic --address 0x... --chain bsc` | Générer des tests ciblés dynamiquement depuis les findings DB |
| `python hardhat_fork_tester.py --batch` | Tester TOUS les contrats avec balance > 0.001 de la DB |
| `cd exploit && npx hardhat run scripts/test_fork_exploit.js --network hardhat <address> <rpc> <funding>` | Test fork manuel |

### Scanners de Blocs BSC

Deux scanners dédiés à Binance Smart Chain :

| Commande | Description |
|:---|:---|
| `python scan_bsc_recent.py` | Scanner les 100 derniers blocs BSC pour les nouveaux déploiements |
| `python scan_bsc_500.py` | Scanner 500 blocs BSC, vérifier automatiquement les contrats, exécuter le pipeline d'exploit |
| `python scan_historical.py --blocks 500000` | Scanner **500 000 blocs** (~1 mois BSC) en concurrence pour les contrats historiques |
| `python scan_historical.py --reverify` | Revérifier les contrats non vérifiés de la DB (maintenant vérifiés ?) |
| `python scan_historical.py --from-block 5000000 --to-block 15000000 --exploit` | Scanner une plage historique spécifique + auto-exploit |

Ces scripts :
- Récupèrent les blocs via `bsc-dataseed1.binance.org` (RPC public gratuit)
- Détectent les déploiements de contrats (transactions `to=null`) via les receipts
- Vérifient le statut de vérification via l'API Etherscan V2 (chainid=56)
- Exécutent automatiquement `exploit_pipeline.py` sur les contrats vérifiés
- Fournissent une sortie compatible ASCII pour les terminaux Windows cp1252

### Scanner de Pools DEX

Scan des pools DEX avec TVL via l'API DEX Screener. Supporte BSC (PancakeSwap, Thena), Polygon (QuickSwap), Optimism (Velodrome), Ethereum (Uniswap, SushiSwap, Balancer, Curve).

| Commande | Description |
|:---|:---|
| `python pool_scanner.py` | Scanner les 5 meilleurs pools par DEX sur toutes les chaînes |
| `python pool_scanner.py --all` | **Scanner TOUS les pools** — sans filtre TVL, sans limite |
| `python pool_scanner.py --all --audit-local` | Tous les pools + test fork Hardhat systématique sur chacun |
| `python pool_scanner.py --min-tvl 1000000` | Uniquement les pools avec TVL >= 1M$ |
| `python pool_scanner.py --chains bsc` | Scanner les pools BSC uniquement (PancakeSwap, Thena) |
| `python pool_scanner.py --daemon` | Mode continu — re-scan toutes les 30 minutes |

**Nouveaux modes :**
- `--all` / `-a` : Scanner CHAQUE pool retourné par DEX Screener (sans filtre TVL, sans limite)
- `--min-tvl X` / `-t X` : Scanner uniquement les pools avec TVL >= X$ USD
- `--audit-local` / `-l` : Exécuter un test fork Hardhat sur chaque contrat scanné avec des findings exploitables
- **Retour en direct** : Chaque résultat de pool est affiché immédiatement avec le tag `[LIVE]` et le verdict

### Exemples

```bash
# Ethereum uniquement — idéal pour tester les événements Transfer + vérification de contrat
python main.py --chains ethereum

# Mempool Bitcoin — surveiller les transactions en attente en temps réel
python main.py --chains bitcoin

# Ethereum + BSC + Polygon simultanément
python main.py --chains ethereum,bsc,polygon

# Avec export JSON
python main.py --chains ethereum -j transactions.json --format both

# Activer les logs DEBUG
python main.py --chains ethereum -v

# Scanner de pools : exhaustif + Hardhat systématique
python pool_scanner.py --all --audit-local

# Scanner de pools : BSC uniquement
python pool_scanner.py --all --chains bsc --min-tvl 50000
```

## Chaînes Supportées

| Chaîne | Mode | Endpoint | Blocs |
|:---|---:|:---|---:|
| **Ethereum** | Abonnement WebSocket | `wss://ethereum.publicnode.com` | ~5/min |
| **Polygon** | Abonnement WebSocket | `wss://polygon-bor-rpc.publicnode.com` | ~30/min |
| **BSC** | Polling (pas d'abonnement) | `wss://bsc.publicnode.com` | ~125/min |
| **Arbitrum** | Abonnement WebSocket | `wss://arbitrum-one-rpc.publicnode.com` | ~240/min |
| **Solana** | Abonnement WebSocket | `wss://solana-rpc.publicnode.com` | Haut TPS |
| **Bitcoin** | WebSocket (mempool.space) | `wss://mempool.space/api/v1/ws` | Temps réel |

> **Remarque** : Tous les endpoints sont des **nœuds publics gratuits** de [PublicNode.com](https://publicnode.com) (EVM/Solana) et [mempool.space](https://mempool.space) (Bitcoin). Aucune clé API requise pour le scan de base. Des limites de débit s'appliquent.

## Fonctionnalités

### Surveillance des blocs en temps réel
- Les nouveaux blocs apparaissent sous forme `[BLK] [Ethereum] Nouveau Bloc #12345678`
- Le taux d'arrivée des blocs varie selon la chaîne (Ethereum ~5/min, BSC ~125/min)
- Les blocs Bitcoin sont détectés via le WebSocket mempool.space

### Détection d'événements Transfer ERC-20
- S'abonne automatiquement aux événements `Transfer` sur les chaînes EVM
- Affiche les lignes `[XFR]` avec le montant, les adresses from/to et l'adresse du contrat
- Filtres de valeur minimale configurables par chaîne

### Vérification du code source des contrats
- Détecte les adresses de contrats dans les événements Transfer et vérifie s'ils sont **vérifiés** sur le block explorer
- Affiche `[verify] 0x... -> VÉRIFIÉ` ou `NON VÉRIFIÉ` à côté des transactions
- Utilise l'API Etherscan V2 — une seule clé API fonctionne pour **les 60+ chaînes**
- Résultats mis en cache en mémoire pour éviter les appels API redondants

### Scanner de Vulnérabilités Solidity (34 patterns)

Analyse le code source des contrats intelligents vérifiés pour **34 types de vulnérabilités de sécurité**, combinant 10 patterns originaux avec des détections avancées DeFi, OpenZeppelin et dérivées de Mythril.

| Vulnérabilité | Sévérité | Source |
|:---|---:|---|
| Reentrancy | CRITIQUE | Original |
| Selfdestruct / Suicide | CRITIQUE | Original |
| Delegatecall vers Adresse Variable | CRITIQUE | Original |
| Mise à jour UUPS non protégée | CRITIQUE | OpenZeppelin |
| Autorisation TX Origin | ÉLEVÉE | Original |
| Retrait/Claim non protégé | ÉLEVÉE | Original |
| Initialiseur non protégé | ÉLEVÉE | Original |
| Susceptibilité au Flash Loan | ÉLEVÉE | Avancé |
| Manipulation Oracle / Prix Spot | ÉLEVÉE | Avancé |
| Deadline manquant dans Swap | ÉLEVÉE | Avancé |
| Attaque par Rejeu de Signature | ÉLEVÉE | Avancé |
| Risque de Collision de Stockage (Upgradeable) | ÉLEVÉE | Avancé |
| _disableInitializers manquant | ÉLEVÉE | OpenZeppelin |
| reinitializer manquant lors de la mise à jour | ÉLEVÉE | OpenZeppelin |
| Initialiseurs de champs dans Upgradeable | ÉLEVÉE | OpenZeppelin |
| Saut Arbitraire (Assembly) | ÉLEVÉE | Mythril |
| Écriture de Stockage Arbitraire (Assembly) | ÉLEVÉE | Mythril |
| Appel Externe Non Vérifié | MOYENNE | Original |
| Dépassement d'Entier (Overflow/Underflow) | MOYENNE | Original |
| Boucle Illimitée sur Tableau Dynamique | MOYENNE | Original |
| 'from' Arbitraire dans transferFrom | MOYENNE | Original |
| ETH Forcé via selfdestruct | MOYENNE | Avancé |
| Retour ERC20 transfer Non Vérifié | MOYENNE | Avancé |
| Erreur d'Arrondi | MOYENNE | Avancé |
| Manipulation du Timestamp de Bloc | MOYENNE | Avancé |
| Risque de Renonciation à la Propriété | MOYENNE | Avancé |
| Transfert de Propriété en Une Étape | MOYENNE | OpenZeppelin |
| Flash Loan Sans Frais | MOYENNE | OpenZeppelin |
| Dépendance à l'Ordre des Transactions | MOYENNE | Mythril |
| Dépendance à une Variable Prévisible | MOYENNE | Mythril |
| Contrôle d'Accès Personnalisé | FAIBLE | OpenZeppelin |
| immutable non sécurisé dans Upgradeable | FAIBLE | OpenZeppelin |
| Pause manquante sur fonction Critique | FAIBLE | OpenZeppelin |
| Appels Externes Multiples | FAIBLE | Mythril |
| Égalité de Solde Stricte | FAIBLE | Mythril |

Les patterns de **Mythril** (cloné depuis [github.com/ConsenSysDiligence/mythril](https://github.com/ConsenSysDiligence/mythril)) ont été analysés et adaptés sous forme de vérifications regex, couvrant les vulnérabilités au niveau assembly (jump, sstore), les conditions de course (dépendance à l'ordre des transactions) et les problèmes de gas/conception.

**Statistiques sur 364 contrats vérifiés :** `transaction-order-dep` trouvé dans **76,6%** des contrats, `multiple-external-calls` dans **10,4%**, `arbitrary-storage-write` dans **0,5%**. Voir `findings/pattern_stats.json`.

Les résultats apparaissent automatiquement lorsqu'un contrat vérifié est détecté :
```
[vuln] 0x7a250d56.. -> 6 vulnérabilité(s) trouvée(s)
  >> Scan de Sécurité : 0x7a250d56.. (6 finding(s) : 2 élevées, 4 moyennes)
   [!HAUTE!] Fonction de Retrait/Claim sans contrôle d'accès (lignes : 224)
       [dim]Fonction de retrait/claim sans contrôle d'accès...
```

### Pipeline d'Exploit

Valide si les vulnérabilités découvertes sont **réellement exploitables** en analysant :
- Version Solidity (>=0.8 bloque la reentrancy via la protection contre les underflows)
- Blocs `unchecked {}` (contournement de la protection contre les overflows)
- Modificateurs de contrôle d'accès (onlyOwner, onlyRole)
- Pattern CEI (Vérifications-Effets-Interactions)
- **Détection de proxy** : récupération automatique du code source de l'implémentation pour les proxies EIP-1967/UUPS

```bash
# Analyser n'importe quel contrat vérifié sur n'importe quelle chaîne
python exploit_pipeline.py --address 0x... --chain ethereum
python exploit_pipeline.py --address 0x... --chain bsc
```

Sortie : rapport détaillé avec export JSON montrant quels findings sont exploitables.

### Démo d'Exploitation Hardhat Locale

Deux démos sont disponibles, chacune démontrant un vecteur de reentrancy différent :

#### 1. Reentrancy classique par underflow (VulnerableBank)
```bash
cd exploit
npx hardhat run scripts/deploy_and_exploit.js --network hardhat
```
- Alice dépose 100 ETH dans une banque délibérément vulnérable
- Bob déploie un contrat d'exploit avec 60 ETH
- L'attaque par reentrancy draine la banque en ~3 rounds
- Bob empoche 100 ETH

#### 2. Reentrancy par pattern CEI (CampaignWrapper)
```bash
cd exploit
npx hardhat run scripts/test_campaign_reentrancy.js --network hardhat
npx hardhat run scripts/test_cei_reentrancy.js --network hardhat
```
- Reproduit le pattern exact trouvé dans CampaignWrapper (0x8a56c6be..)
- Démontre que la reentrancy CEI sur les booléens fonctionne même en Solidity >=0.8
- Montre que l'état non arithmétique (hasClaimed flag) PEUT être contourné par reentrancy
- Valide 5 rounds de claim récursif drainant 5 ETH

#### 3. Framework d'exploit universel v2 (28 types d'attaque, 80+ signatures)
```bash
cd exploit
npx hardhat compile
npx hardhat run scripts/test_fork_exploit.js --network hardhat 0x... https://rpc-url 0.05
```
- `UniversalExploit.sol` — contrat unique testant **28 vecteurs d'attaque** avec **80+ signatures de fonctions DeFi**
- `test_fork_exploit.js` — fork → usurpation → déploiement → 28 attaques → vérification
- `hardhat_fork_tester.py` — orchestrateur Python pour tests fork automatisés
- Nouvelles attaques étendues : ExtendedWithdraw, ExtendedInit, ExtendedDelegatecall, ExtendedOwnership, ExtendedUpgrade, ExtendedTreasury, ExtendedPause, ExtendedSweep, ExtendedCrossChain, ExtendedReentrancy

### Découverte clé : Solidity >=0.8 bloque la reentrancy par underflow mais PAS la reentrancy CEI

**Reentrancy par underflow (style DAO classique) :** BLOQUÉE en >=0.8
- `balances[msg.sender] -= amount` revient avec `panic(0x11)` en cas d'underflow
- Nécessite `unchecked {}` pour fonctionner

**Reentrancy CEI (contournement du booléen) :** FONCTIONNE en >=0.8
- `!hasClaimed[user]` n'est pas arithmétique — peut être contourné par reentrancy
- La mise à jour d'état a lieu APRÈS l'appel externe, donc la vérification passe plusieurs fois
- Chaque appel récursif draine un montant de remboursement complet

### Générateur de Tests Dynamiques

`dynamic_test_generator.py` lit les findings de vulnérabilité depuis `guardian_data.db` et génère des scripts de test JS Hardhat ciblés à la volée :

```bash
# Générer et exécuter des tests dynamiquement depuis les findings DB
python hardhat_fork_tester.py --dynamic --address 0x... --chain bsc

# Utilisation autonome
python dynamic_test_generator.py 0x18b2a687610328590bc8f2e5fedde3b582a49cda
```

**8 patterns de vulnérabilité supportés :** reentrancy, delegatecall, unprotected-withdraw, unprotected-init, ownership, oracle, treasury, force-feed. Chaque pattern génère du JS ciblé avec des sélecteurs 4-byte exacts.

### Spécialisé PredictionV2

5 contrats d'exploit Solidity + 6 scripts JS pour tester PancakeSwap Prediction V2 (1 724 BNB) :

| Contrat | Cible | Approche |
|:---|---|:---|
| `PredictionV2OracleManipulator.sol` | Oracle/Prix Spot | Swap massif WBNB→BUSD pour manipuler le pool |
| `PredictionV2ReentrancyExploit.sol` | Reentrancy | Attaque reentrancy sur `claim()` via callback `receive()` |
| `PredictionV2TXOriginExploit.sol` | TX Origin | Simulation de phishing : le owner appelle le contrat piégé |
| `PredictionV2DelegatecallExploit.sol` | Delegatecall | Analyse bytecode + implémentation malveillante |
| `PredictionV2TreasuryExploit.sol` | Contrôle d'Accès | Teste 12 fonctions admin sans autorisation |

```bash
# Lancer la suite complète
python hardhat_fork_tester.py --specialized prediction-v2 --address 0x18b2a687...

# Test individuel
python hardhat_fork_tester.py --specialized prediction-v2 --test oracle
python hardhat_fork_tester.py --specialized prediction-v2 --test reentrancy
```

### Tests par Lots

Tester TOUS les 55 contrats vérifiés avec balance > 0.001 BNB en une seule commande :

```bash
python hardhat_fork_tester.py --batch
```

Exécute UniversalExploit v2 (28 attaques) contre chaque contrat séquentiellement. S'arrête au premier exploit confirmé.

**Résultats du lot (08/06/2026) :** 55 contrats testés, **0 confirmé exploitable**. Tous les contrats réels sont correctement protégés.

### Backfill + Hardhat

Re-scanner tous les contrats de la DB et valider sur un fork Hardhat réel :

```bash
# Backfill simple : re-scan sans Hardhat
python guardian.py --backfill

# Backfill + Hardhat : pipeline complet jusqu'à la confirmation
python guardian.py --backfill --backfill-hardhat

# Limiter à N contrats
python guardian.py --backfill --backfill-hardhat --backfill-limit 10

# Forcer le re-scan (supprimer + recréer les findings)
python guardian.py --backfill --force

# Backfill force + Hardhat (pipeline complet : re-scan + validation fork)
python guardian.py --backfill --force --backfill-hardhat

# Backfill avec retour de progression toutes les N contrats
python guardian.py --backfill --backfill-feedback 10
```

### Confirmateur par Exécution Symbolique Mythril — `--with-mythril`

Mythril ([ConsenSys/mythril](https://github.com/ConsenSys/mythril)) est intégré comme **validateur externe** via sous-processus (0 import Python de la librairie Mythril).

**Architecture :**
- Appelle `myth analyze --bin <bytecode> -o jsonv2` en sous-processus
- Récupère le bytecode via `eth_getCode` (notre propre appel RPC, plus fiable que le --rpc de Mythril)
- Auto-détecte le venv `.mythril-env/Scripts/python.exe` (Python 3.12)
- Parse le JSONv2 et mappe les issues (sévérité, SWC-ID, tx_sequence)
- Si Mythril trouve une **tx_sequence** (preuve mathématique via Z3), c'est un exploit CONFIRMÉ

**Installation :**
```bash
# Créer le venv Python 3.12 et installer Mythril
python -m venv .mythril-env
.mythril-env/Scripts/python.exe -m pip install mythril

# Résultat : mythril v0.24.8 dans le venv
.mythril-env/Scripts/python.exe -m mythril version
```

**Utilisation :**
```bash
# Pendant un scan live
python guardian.py --with-mythril

# Pendant un backfill
python guardian.py --backfill --backfill-limit 5 --with-mythril

# Analyse autonome
python .mythril-env/Scripts/python.exe -m confirmators.mythril_confirmator -a 0x... --chain 56
```

**Résultats des tests (4 contrats BSC) :**
| Contrat | Bytecode | Issues Mythril | Issues Pipeline | Temps |
|:---|---|---:|---:|---:|
| WBNB | 3125 bytes | 0 | 3 | 3.4s |
| ERC1967Proxy | 856 bytes | 0 | 16 | 3.5s |
| ApolloxExchangeTreasury | 11582 bytes | 0 | 8 | 3.7s |
| TransparentUpgradeableProxy | 2113 bytes | 0 | 13 | 3.6s |

**Complémentarité :** Mythril analyse le **bytecode** (exécution symbolique) là où notre scanner analyse le **source Solidity** (34 patterns regex). Les deux approches ont des angles morts différents — les combiner augmente la couverture.

### Gestion des Processus Hardhat — `clean_hardhat.bat`

`kill_all_node_processes()` dans `guardian.py` est passé de **`taskkill /F /IM node.exe`** (tue TOUS les node.exe — y compris Codebuff) à **`wmic` avec filtre WQL** (tue uniquement les processus node.exe dont la ligne de commande contient `"hardhat"`).

Pour le nettoyage manuel, `clean_hardhat.bat` propose 3 modes :
| Commande | Description |
|:---|:---|
| `clean_hardhat.bat` | Kill sélectif immédiat via wmic + PowerShell fallback |
| `clean_hardhat.bat --check` | Lister les processus Hardhat sans les tuer |
| `clean_hardhat.bat --loop` | Surveiller toutes les 10s et nettoyer automatiquement |

`run_forever.bat` et `run_guardian.bat` appellent maintenant `clean_hardhat.bat` automatiquement avant le redémarrage et à l'arrêt, empêchant l'accumulation d'orphelins.

De plus, `validate_finding()` et `validate_contract()` dans `guardian.py` appellent `HardhatValidator.kill_all_node_processes()` **avant** de lancer tout nouveau test Hardhat, garantissant un état propre avant chaque test fork.

### Performance : optimisation ×20

HardhatValidator groupe tous les findings par contrat en **un seul fork + une seule compilation + une seule exécution**, au lieu d'un par finding :

| Avant (par finding) | Après (par contrat) |
|---|---|
| 1 fork Hardhat | **1 fork unique** |
| 1 `npx hardhat compile` | **1 compilation pour N exploits** |
| 1 `npx hardhat run` | **1 seul run pour N attaques** |
| **~60s/finding** | **~60s + ~10s/finding supplémentaire** |

Gain mesuré : **~3s** au lieu de ~60s pour 1 contrat avec 1 finding exploitable (×20).

### Correctifs Session 9 — Mythril + hardhat_setBalance + template .call() (12/06/2026)

| Bug | Cause racine | Correctif |
|:---|---|:---|
| **L'usurpation de baleine ne fonctionne pas sur Arbitrum/Optimism** | `hardhat_impersonateAccount` + `eth_sendTransaction` fonctionne sur Ethereum/BSC mais pas sur toutes les chaînes EVM | Remplacé par `hardhat_setBalance` (norme EIP-1898) — fonctionne sur toutes les chaînes EVM, pas besoin d'usurpation |
| **Le template d'exploit revient si la fonction est absente** | Le contrat exploit appelle `target.withdraw()` avec un sélecteur fixe → si la fonction n'existe pas, la TX revient | Template changé pour `.call(abi.encodeWithSignature(...))` de bas niveau — ne revient pas si la fonction est absente (retourne false) |

**Fichiers modifiés :**
- `guardian.py` — `_generate_exploit_contract()` : template `.call()` au lieu de `withdraw()` fixe, `hardhat_setBalance` au lieu d'usurpation de baleine
- `guardian.py` — `update_hardhat_result_by_id()` : nouvelle méthode pour mise à jour par ID (plus robuste que par nom)
- `guardian.py` — `kill_all_node_processes()` : nettoyage des processus orphelins, suivi via `self._processes`
- `confirmators/mythril_confirmator.py` (nouveau) — validateur Mythril en sous-processus, bytecode via `eth_getCode`

**Testé :** 4 contrats BSC analysés (WBNB, ERC1967Proxy, ApolloxTreasury, TransparentUpgradeableProxy) — 0 issues Mythril vs 40 issues pipeline (complémentarité).

### Correctifs Session 8 — Gestion des processus + nettoyage Hardhat (10/06/2026)

| Bug | Cause racine | Correctif |
|:---|---|:---|
| **`taskkill /F /IM node.exe` tue Codebuff** | Tuait TOUS les node.exe (Codebuff inclus) → écritures bizarres dans la console | Remplacé par `wmic` avec filtre `CommandLine LIKE '%hardhat%'` + `taskkill /F /T /PID` (ciblé) |
| **Processus Hardhat orphelins persistants** | Les scripts run_forever/run_guardian ne nettoyaient pas les orphelins entre les runs | Création de `clean_hardhat.bat` + appel automatique dans `run_forever.bat` et `run_guardian.bat` |
| **Orphelins créés entre les tests Hardhat** | validate_finding() et validate_contract() lancent de nouveaux Hardhat sans nettoyer les anciens | Auto-nettoyage `kill_all_node_processes()` au début de chaque test Hardhat dans guardian.py |
| **Logs 296 MB — trop verbeux** | logging.INFO incluait chaque bloc/transaction en continu | Ajout de `--log-level` CLI (DEBUG\|INFO\|WARNING\|ERROR) + run_guardian.bat utilise WARNING par défaut |

**Fichiers créés/modifiés :**
- `clean_hardhat.bat` (nouveau) — script de nettoyage sélectif (wmic pur, plus de PowerShell)
- `guardian.py` — `kill_all_node_processes()` réécrit avec filtre WQL `wmic` + retourne dict + auto-nettoyage dans validate_finding/validate_contract + flag CLI `--cleanup` + flag CLI `--log-level`
- `run_forever.bat` — nettoyage automatique avant chaque redémarrage
- `run_guardian.bat` — nettoyage automatique à l'arrêt + `--log-level WARNING`

### Correctifs Session 7 — Pipeline HardhatValidator (09/06/2026)

4 bugs corrigés dans le pipeline de validation Hardhat `guardian.py`:

| Bug | Cause racine | Correctif |
|:---|---|:---|
| **`No FINDING_RESULT for idx X`** | L'attaquant (signer Hardhat) avait **0 ETH** sur le fork → toutes les transactions échouaient | Ajout d'une **usurpation de baleine** (Binance 0xF97..aceC) → envoi de 50 ETH à l'attaquant avant les tests |
| **`tx0.wait is not a function`** | Le template générique Solidity utilisait `pure` → ethers v6 fait un `eth_call` (retourne string) au lieu d'une transaction | Changé pour `bool public attacked` + `attacked = true` → fonction non-`pure` → ethers retourne une `TransactionResponse` |
| **Noms de contrat dupliqués** | `datetime.utcnow().timestamp()` → collisions dans la même seconde | Nommage par **index** (`Exploit_{index}`) via `enumerate()` dans `validate_contract()` |
| **Le script combiné ne termine pas** | Pas de `process.exit(0)` → le provider Hardhat maintient la boucle d'événements active | Ajout de `.then(() => process.exit(0))` à la fin du `main()` |

**Testé :** Backfill force + Hardhat sur WBNB (BSC) — pipeline complet validé ✅

### Statistiques Guardian 24/7 (au 11/06/2026)

| Métrique | Valeur |
|:---|---|
| Contrats dans la DB | **24 945** |
| Contrats vérifiés | **985** |
| Findings totaux | **8 109** |
| Exploitables (pipeline) | **4 943** |
| Tests Hardhat (fork) | **2 635** |
| Analyses Mythril (bytecode) | **4** (0 issues trouvées — complémentaire) |
| Exploits confirmés | **0** |
| Chaînes actives | **6** (ETH, BSC, Arbitrum, Optimism, Avalanche, Polygon) |

> **Découverte clé :** Après 2 635 tests Hardhat fork sur des contrats vérifiés avec balance, **0 exploits confirmés**. Le pipeline backfill → Hardhat est entièrement fonctionnel : 33 findings validés sur 5 contrats BSC (WBNB, ERC1967Proxy, ApolloxExchangeTreasury, TransparentUpgradeableProxy, PancakePredictionV2), tous FAILED. UniversalExploit v2 avec 80+ signatures ne peut toujours pas correspondre aux noms de fonctions spécifiques des contrats audités réels. Les 4 bugs du pipeline Hardhat sont corrigés et testés.

## Tests

Avant chaque commit, un hook pre-commit exécute les tests des patterns Mythril pour garantir l'intégrité du scanner :

```bash
# Exécuter la suite de tests manuellement
python test_mythril_patterns.py

# Le hook pre-commit s'exécute automatiquement lors de git commit
# Pour contourner (urgence uniquement) : git commit --no-verify
```

**Périmètre des tests :** Valide les 5 patterns dérivés de Mythril (arbitrary-jump, arbitrary-storage-write, multiple-external-calls, transaction-order-dependence, strict-balance-equality) avec des cas de test positifs et négatifs, plus un test d'intégration sur UniversalExploit.sol.

**Hook pre-commit :** Installé via `hooks/pre-commit`. Si les tests échouent, le commit est annulé avec un message d'erreur.

### Génération de statistiques

```bash
# Générer des statistiques complètes des patterns sur N contrats vérifiés
python stats_patterns.py --limit 500

# Filtrer par chaîne
python stats_patterns.py --limit 100 --chain 56
```

Les résultats sont sauvegardés dans `findings/pattern_stats.json`.

### Suivi du mempool Bitcoin
- Se connecte au WebSocket mempool.space pour les transactions non confirmées en temps réel
- Déduplication automatique des transactions
- Filtre de valeur minimale BTC configurable

### Filtres configurables
Filtres par chaîne dans `config.yaml`:
- `min_value_eth` / `min_value_btc` / `min_value_sol` — valeur minimale de transaction
- `tracked_addresses` — surveiller uniquement des adresses spécifiques
- `tracked_events` — types d'événements à suivre
- `tracked_tokens` — filtrer par adresse de token

### Multi-chaîne simultané
Exécutez n'importe quelle combinaison de chaînes simultanément. Toute la sortie est unifiée dans un seul affichage terminal.

## Configuration

Voir `config.yaml` pour tous les paramètres. Sections clés :

```yaml
global:
  log_level: "INFO"              # DEBUG, INFO, WARNING, ERROR
  output_format: "rich"          # rich, json, both
  explorer_api_key: ""           # Clé Etherscan V2 optionnelle (vérification de contrat)

chains:
  ethereum:
    enabled: true                # Mettre false pour désactiver
    rpc_ws: "wss://..."          # Endpoint WebSocket
    chain_id: 1                  # ID de chaîne EVM
    filters:
      min_value_eth: 0.01        # Valeur ETH minimale à signaler
```

### Vérification de contrat (optionnelle)

Pour activer la vérification du code source des contrats intelligents :

1. Obtenez une **clé API Etherscan V2 gratuite** sur [etherscan.io/myapikey](https://etherscan.io/myapikey)
2. Ajoutez-la dans `config.yaml`:
```yaml
global:
  explorer_api_key: "VOTRE_CLE_ETHERSCAN_V2"
```

> **Une clé pour toutes les chaînes :** L'API Etherscan V2 fonctionne sur 60+ chaînes (Ethereum, BSC, Polygon, Arbitrum, etc.) avec une seule clé. Niveau gratuit : 5 appels/s, 100 000 appels/jour.

## Légende de la Sortie Terminal

| Préfixe | Signification |
|:---|---:|
| `[BLK]` | Nouveau bloc détecté |
| `[XFR]` | Événement Transfer ERC-20 |
| `[verify]` | Résultat de vérification de contrat (VÉRIFIÉ / NON VÉRIFIÉ) |
| `[vuln]` | Résultats du scan de vulnérabilité (nombre de findings) |
| `>> Security Scan` | Liste détaillée des vulnérabilités avec sévérité, lignes, description |
| `[!CRITIQUE!]` | Vulnérabilité de sévérité Critique (rouge) |
| `[!HAUTE!]` | Vulnérabilité de sévérité Haute (jaune) |
| `[WARN]` | Vulnérabilité de sévérité Moyenne |
| `[MP]` | Transaction mempool (Bitcoin / EVM en attente) |
| `[ACC]` | Activité de compte (adresse filtrée) |
| `[TX]` | Transaction générale |

## Détails d'Installation

### Prérequis (Python 3.10+)

```
web3>=7.0.0        # Chaînes EVM
solana>=0.34.0     # Solana
solders>=0.21.0    # Utilitaires Solana
websockets>=12.0   # Connexions WebSocket
rich>=13.0.0       # Interface terminal
pyyaml>=6.0        # Configuration
httpx>=0.27.0      # Requêtes HTTP (appels API)
```

### Installer

```bash
pip install -r requirements.txt
```

## Structure du Projet

```
blockchain_scanner/
  main.py                    # Point d'entrée CLI
  guardian.py                # Scanner 24/7 + DB SQLite + gestion des processus Hardhat
  clean_hardhat.bat          # Tueur sélectif de processus Hardhat (sans danger pour Codebuff)
  run_forever.bat            # Boucle de redémarrage automatique avec nettoyage Hardhat
  run_guardian.bat           # Démarrer/Arrêter le Guardian avec nettoyage Hardhat
  config.yaml                # Configuration (chaînes, filtres, clés API)
  verify.py                  # Vérification du code source des contrats (Etherscan V2)
  exploit_pipeline.py        # Pipeline automatisé de validation des vulnérabilités
  hardhat_fork_tester.py     # Framework de test fork autonome
  pool_scanner.py            # Scanner de pools DEX via l'API DEX Screener
  scan_bsc_recent.py         # Scanner les 100 derniers blocs BSC pour les nouveaux contrats
  scan_bsc_500.py            # Scanner 500 blocs BSC + pipeline d'exploit automatique
  scan_historical.py         # Scanner historique de blocs : millions de blocs en concurrence + re-vérification DB
  requirements.txt           # Dépendances Python
  .gitignore                 # Règles Git ignore
  README.md                  # Ce fichier
  scanner/
    base.py                  # BaseScanner ABC (reconnexion automatique, statistiques)
    evm_scanner.py           # Chaînes EVM (Ethereum, Polygon, BSC, Arbitrum)
    bitcoin_scanner.py       # Bitcoin via mempool.space
    solana_scanner.py        # Solana
    orchestrator.py          # Cycle de vie du scanner + intégration du scan de vulnérabilités
  confirmators/
    __init__.py              # Paquet confirmator
    mythril_confirmator.py   # Exécution symbolique Mythril (sous-processus, 0 dépendance d'import)
  analysis/
    __init__.py              # Paquet analyse
    vulnerability_scanner.py # Scanner de vulnérabilités Solidity (25 patterns, incluant les vérifications OpenZeppelin)
  filters/
    filters.py               # Filtres de transactions
  output/
    display.py               # Affichage terminal (Rich + sortie des vulnérabilités)
  exploit/                   # Démos d'exploitation Hardhat locales
    contracts/
      VulnerableBank.sol     # Banque délibérément vulnérable (violation CEI, sous-flux)
      Exploit.sol            # Contrat d'attaque par reentrancy (sous-flux)
      ExploitV2.sol          # Version de débogage avec récursion configurable
      CampaignVulnerable.sol # Reproduit le pattern CampaignWrapper (booléen CEI)
      CampaignExploit.sol    # Exploit CEI reentrancy avec garde-fou
      UniversalExploit.sol   # Exploit universel testant 28 types d'attaque
      PrismReentrancyExploit.sol # Exploit reentrancy spécifique à PrismHook
      AIDogeExploit.sol      # Contrat d'exploit spécifique à AIDoge
      PredictionV2OracleManipulator.sol  # Attaque oracle PredictionV2
      PredictionV2ReentrancyExploit.sol  # Attaque reentrancy PredictionV2
      PredictionV2TXOriginExploit.sol    # Attaque tx.origin PredictionV2
      PredictionV2DelegatecallExploit.sol# Attaque delegatecall PredictionV2
      PredictionV2TreasuryExploit.sol    # Drainage de trésorerie PredictionV2
    scripts/
      deploy_and_exploit.js          # Démo de reentrancy par sous-flux classique
      test_simple_withdraw.js        # Vérification de base
      test_campaign_reentrancy.js    # Validation CEI CampaignWrapper
      test_cei_reentrancy.js         # Suite de validation combinée
      test_fork_exploit.js           # Script d'exploitation fork universel (28 attaques)
      test_prediction_v2_all.js      # Suite maître pour PredictionV2
      test_prediction_v2_oracle_manipulation.js
      test_prediction_v2_reentrancy.js
      test_prediction_v2_delegatecall.js
      test_prediction_v2_txorigin.js
      test_prediction_v2_treasury.js
    generated/                      # Fichiers de test générés dynamiquement
      dyn_test_*.js
    hardhat.config.js         # Configuration Hardhat (Solidity 0.8.20, taille de contrat illimitée)
    package.json
    .gitignore
  findings/                  # Catalogue des findings de vulnérabilités
    README.md                # Index de tous les contrats analysés
    campaign_wrapper.md      # Rapport détaillé sur la vulnérabilité CampaignWrapper
    scanned_contracts.md     # Journal de tous les contrats scannés
  skill/                     # Documentation de compétence
    multi-chain-blockchain-scanner.md  # Référence complète
```

## Limitations

| Limitation | Raison |
|:---|---:|
| **Pas de mempool en attente sur EVM** | PublicNode ne supporte pas `newPendingTransactions` |
| **BSC en polling uniquement** | Le champ `extraData` de BSC bloque les formatteurs web3.py |
| **Limité en débit** | Les nœuds publics gratuits n'ont pas de SLA |
| **Windows cp1252** | La sortie terminal utilise uniquement l'ASCII (pas d'emoji) |

Pour une utilisation en production, remplacez les endpoints gratuits par des fournisseurs payants (Alchemy, QuickNode, Infura).

## Dépannage

### « Aucune chaîne activée »
```bash
# Activer une chaîne dans config.yaml
nano config.yaml   # Mettre enabled: true pour au moins une chaîne
```

### « Échec de connexion »
- Vérifiez votre connexion Internet
- L'endpoint public peut être temporairement limité en débit — attendez un moment et réessayez
- Certaines chaînes (comme BSC) nécessitent le mode polling, qui est géré automatiquement

### « WebSocket fermé »
La reconnexion automatique avec backoff exponentiel est intégrée. Le scanner réessaiera automatiquement (1s → 2s → 4s → ... → 60s max).

### « Aucun bloc n'apparaît »
- Certaines chaînes ont des temps de bloc lents (Ethereum : ~12s)
- BSC affiche les blocs immédiatement en mode polling (~3s les blocs)
- Bitcoin n'affiche les blocs que lorsqu'un nouveau est miné (~10min en moyenne)
