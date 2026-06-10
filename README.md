# Blockchain Scanner 🔍

[![CI](https://github.com/reuniware/blockchain_scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/reuniware/blockchain_scanner/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/blockchain-scanner)](https://pypi.org/project/blockchain-scanner/)
[![Python versions](https://img.shields.io/pypi/pyversions/blockchain-scanner)](https://pypi.org/project/blockchain-scanner/)
[![License](https://img.shields.io/pypi/l/blockchain-scanner)](LICENSE)

**Surveillance en temps réel de 10 blockchains EVM + détection de vulnérabilités Solidity + validation d'exploits sur fork Hardhat.**

Analysez des milliers de contrats intelligents par jour, détectez des failles de sécurité avec 34 patterns de détection, et validez si elles sont réellement exploitables — le tout depuis votre terminal, sans clé API pour la surveillance de base.

---

## 📦 Installation

### Option 1 — Depuis PyPI (recommandé)

```bash
pip install blockchain-scanner
```

Puis créez un fichier `config.yaml` (modèle ci-dessous ou utilisez le `config.yaml` complet du dépôt) et lancez :

```bash
blockchain-scanner
```

> **Note** : Les fonctionnalités avancées (validation d'exploits sur fork Hardhat) nécessitent **Node.js 18+** installé séparément.

### Option 2 — Depuis les sources

```bash
# Cloner le dépôt
git clone https://github.com/reuniware/blockchain_scanner.git
cd blockchain_scanner

# Installer les dépendances
pip install -r requirements.txt

# Lancer le scanner
python main.py
```

### Vérifier l'installation

```bash
blockchain-scanner --version
# Blockchain Scanner v1.0.1
```

---

## 🚀 Démarrage rapide

```bash
# Scanner toutes les chaînes activées par défaut
blockchain-scanner

# Scanner uniquement Ethereum et BSC
blockchain-scanner --chains ethereum,bsc

# Activer les logs détaillés
blockchain-scanner --chains ethereum -v
```

**Ce que vous allez voir :**

```
[BLK] [Ethereum] Nouveau Bloc #12345678
[BLK] [BSC] Nouveau Bloc #98765432
[XFR] [Ethereum] 42.5 ETH de 0xabc..123 à 0xdef..456 (contrat: 0x7a25..)
[XFR] [BSC] 1000 BUSD de 0x111..222 à 0x333..444 (contrat: 0x1B1d..)
[verify] 0x7a250d56.. -> VÉRIFIÉ
[vuln] 0x7a250d56.. -> 6 vulnérabilité(s) trouvée(s)
```

---

## 🎯 Guide utilisateur

### Pourquoi ce scanner est puissant

| Ce que vous pouvez faire | En une commande |
|---|---|
| Surveiller 10 blockchains EVM en temps réel | `blockchain-scanner` |
| Détecter des failles dans des smart contracts | Automatique sur les contrats vérifiés |
| Valider si une faille est réellement exploitable | `exploit-pipeline --address 0x... --chain ethereum` |
| Scanner 24/7 avec base de données SQLite | `guardian` |
| Tester les exploits sur un fork réel Hardhat | `hardhat_fork_tester --address 0x... --chain bsc` |
| Scanner des pools DEX avec TVL | `pool-scanner --chains bsc` |

### En temps réel — Surveillance multi-chaîne

Lancez le scanner et regardez les blocs défiler en direct. Le scanner s'abonne aux WebSocket publics et affiche chaque nouveau bloc, transaction et événement Transfer ERC-20 :

```bash
blockchain-scanner --chains ethereum,bsc,polygon
```

Les préfixes vous aident à lire rapidement :

| Préfixe | Signification |
|:---|---:|
| `[BLK]` | Nouveau bloc détecté |
| `[XFR]` | Événement Transfer ERC-20 |
| `[verify]` | Vérification de contrat |
| `[vuln]` | Résultat du scan de vulnérabilité |
| `[!CRITIQUE!]` | Vulnérabilité Critique |
| `[!HAUTE!]` | Vulnérabilité Haute |
| `[MP]` | Transaction mempool |

### Détection de vulnérabilités — 34 patterns

Dès qu'un contrat vérifié est détecté, le scanner analyse automatiquement son code source Solidity et détecte 34 types de vulnérabilités :

```bash
# Le scanner détecte automatiquement les contrats vérifiés
# Mais vous pouvez aussi analyser un contrat spécifique :
exploit-pipeline --address 0x7a250d56... --chain ethereum
```

**Exemple de sortie :**

```
>> Security Scan : 0x7a250d56... (6 finding(s) : 2 élevées, 4 moyennes)
  [!HAUTE!] Fonction de Retrait/Claim sans contrôle d'accès (lignes : 224)
  [!HAUTE!] Utilisation de tx.origin pour l'authentification (lignes : 89)
  [WARN] Appel externe non vérifié (lignes : 156)
  [WARN] Boucle potentiellement illimitée (lignes : 42)
```

**Principales vulnérabilités détectées :**

| Sévérité | Patterns |
|:---|---|
| 🔴 **CRITIQUE** | Reentrancy (underflow & CEI), Selfdestruct, Delegatecall vers adresse variable, UUPS non protégée |
| 🟠 **HAUTE** | TX Origin, Retrait/Claim non protégé, Initialiseur non protégé, Flash Loan, Manipulation Oracle, Deadline manquant, Rejeu de signature |
| 🟡 **MOYENNE** | Appel externe non vérifié, Dépassement d'entier, Boucle illimitée, ERC20 transfer non vérifié, Manipulation de timestamp, Erreur d'arrondi |

**34 patterns au total**, incluant des détections avancées DeFi, OpenZeppelin et Mythril.

### Pipeline d'exploit — Faux positif ou vrai danger ?

Une vulnérabilité détectée n'est pas toujours exploitable. Le pipeline d'exploit analyse le contexte :

```bash
exploit-pipeline --address 0x... --chain bsc
```

Il vérifie :
- **Version Solidity** (>=0.8 bloque la reentrancy par underflow)
- **Blocs `unchecked {}`** (contournement de la protection)
- **Modificateurs d'accès** (onlyOwner, onlyRole)
- **Pattern CEI** (Vérifications-Effets-Interactions)
- **Détection de proxy** (redirection vers l'implémentation)

Sortie :

```
[1/3] Fetching source code...
[2/3] Scanning for vulnerabilities...
  6 finding(s)
[3/3] Validating exploitability...
  -- Finding #1: Reentrancy [CRITIQUE] --
     [GREEN] NOT exploitable -- Solidity >=0.8 underflow protection
  -- Finding #2: Unprotected withdraw [HAUTE] --
     [RED] THEORETICALLY EXPLOITABLE
```

### Guardian 24/7 — L'usine à détection automatique

Mode autonome qui tourne en continu, stocke tout dans une base SQLite, et ne s'arrête jamais :

```bash
# Démarrer le Guardian (tourne jusqu'à Ctrl+C)
guardian

# Voir les statistiques
guardian --status

# Mode backfill : re-scanner tous les contrats de la DB
guardian --backfill

# Backfill + validation Hardhat
guardian --backfill --backfill-hardhat --backfill-limit 10
```

**Fonctionnement en temps réel :**

```
WebSocket BSC (~3s/bloc)
  → Nouveau bloc détecté
  → Vérification des contrats (Etherscan V2)
  → Si vérifié : scan 34 patterns de vulnérabilité
  → Pipeline d'exploitabilité (version, unchecked, proxy)
  → Si CRITICAL/HIGH avec balance > 0 : test Hardhat fork IMMÉDIAT
  → Si CONFIRMÉ : alerte Discord + fichier alarme

Boucle périodique (120s) : test les findings exploitables en attente
Boucle stats (60s) : affiche les compteurs
```

**Statistiques réelles (au 11/06/2026) :**
- **24 945** contrats dans la base
- **985** contrats vérifiés scannés
- **8 109** findings de vulnérabilité
- **4 943** exploitables (théoriquement)
- **2 635** tests Hardhat fork exécutés
- **0** exploits confirmés (les contrats réels sont bien protégés)

### Pool Scanner — Trouver des failles dans les pools DEX

Scanne les pools les plus liquides via l'API DEX Screener et les analyse automatiquement :

```bash
# Top 5 pools par DEX
pool-scanner

# TOUS les pools sans filtre
pool-scanner --all

# Uniquement les pools avec TVL > 1M$
pool-scanner --min-tvl 1000000

# Sur BSC uniquement
pool-scanner --chains bsc

# Mode continu (re-scan toutes les 30 min)
pool-scanner --daemon
```

DEX supportés : PancakeSwap, Uniswap, SushiSwap, QuickSwap, Velodrome, Balancer, Curve, Thena.

### Tests sur fork Hardhat — Validation réelle

Pour valider si un exploit fonctionne **vraiment**, le scanner peut forker une blockchain réelle avec Hardhat et exécuter l'attaque :

```bash
hardhat_fork_tester --address 0x... --chain bsc

# Ou tester TOUS les contrats de la DB avec balance > 0.001
hardhat_fork_tester --batch
```

Le testeur déploie un contrat d'exploit sur le fork, tente 28 types d'attaque différents, et vérifie si des fonds ont été drainés.

---

## 📋 Référence des commandes

### Scanner principal (`blockchain-scanner` / `python main.py`)

| Commande | Description |
|:---|:---|
| `blockchain-scanner` | Scanner toutes les chaînes activées |
| `--chains ethereum` | Scanner une chaîne spécifique |
| `--chains ethereum,bsc,bitcoin` | Scanner des chaînes spécifiques |
| `--stop-on detected` | S'arrêter au premier finding HIGH/CRITICAL (défaut) |
| `--stop-on confirmed` | S'arrêter après confirmation par le pipeline |
| `--stop-on none` | Ne jamais s'arrêter automatiquement |
| `--list-chains` | Lister les chaînes configurées |
| `-v` / `--verbose` | Activer les logs DEBUG |
| `--format rich\|json\|both` | Format de sortie |
| `-j FILE` / `--json FILE` | Exporter vers JSON |
| `-c FILE` / `--config FILE` | Configuration personnalisée |
| `--version` | Afficher la version |

### Guardian (`guardian` / `python guardian.py`)

| Commande | Description |
|:---|:---|
| `guardian` | Démarrer le Guardian 24/7 |
| `--chains ethereum,bsc` | Chaînes spécifiques uniquement |
| `--force-hardhat` | Forcer la validation Hardhat sur TOUS les findings |
| `--status` | Statistiques DB |
| `--health` | Vérifier si le processus tourne |
| `--backfill` | Re-scanner tous les contrats de la DB |
| `--backfill --force` | Forcer le re-scan |
| `--backfill --backfill-hardhat` | Backfill + validation Hardhat fork |
| `--backfill --backfill-limit 10` | Limiter à 10 contrats |
| `--with-mythril` | Activer Mythril (exécution symbolique) |
| `--cleanup` | Tuer les processus Hardhat orphelins |
| `--log-level WARNING` | Réduire la verbosité |

### Pipeline d'exploit (`exploit-pipeline` / `python exploit_pipeline.py`)

| Commande | Description |
|:---|:---|
| `exploit-pipeline --address 0x... --chain ethereum` | Analyser un contrat |
| `--api-key KEY` | Clé API Etherscan V2 |
| `--cached-source FILE` | Source pré-récupérée (évite doublon API) |

### Pool Scanner (`pool-scanner` / `python pool_scanner.py`)

| Commande | Description |
|:---|:---|
| `pool-scanner` | Top 5 pools par DEX |
| `--all` / `-a` | Scanner TOUS les pools |
| `--min-tvl X` / `-t X` | TVL minimum en USD |
| `--audit-local` / `-l` | Test Hardhat fork systématique |
| `--chains bsc,polygon` | Chaînes spécifiques |
| `--daemon` / `-d` | Mode continu (30 min) |

### Testeur Hardhat fork (`python hardhat_fork_tester.py`)

| Commande | Description |
|:---|:---|
| `python hardhat_fork_tester.py --address 0x... --chain bsc` | Tester un contrat |
| `--batch` | Tester TOUS les contrats avec balance > 0.001 |
| `--specialized prediction-v2 --address 0x...` | Suite spécialisée PredictionV2 |
| `--dynamic --address 0x...` | Tests générés dynamiquement |

### Utilitaires

| Commande | Description |
|:---|:---|
| `python scan_bsc_recent.py` | Scanner les 100 derniers blocs BSC |
| `python scan_bsc_500.py` | Scanner 500 blocs BSC + pipeline d'exploit |
| `python scan_historical.py --blocks 500000` | Scanner historique de blocs |
| `python stats_patterns.py --limit 500` | Statistiques des patterns |
| `python dump_results.py` | Exporter les stats DB en Markdown |
| `clean_hardhat.bat` | Tuer les processus Hardhat (sélectif) |
| `run_forever.bat` | Boucle de redémarrage automatique |

---

## ⚙️ Configuration

Créez un fichier `config.yaml` à la racine :

```yaml
global:
  log_level: "INFO"
  output_format: "rich"
  explorer_api_key: ""  # Optionnel : clé Etherscan V2

chains:
  ethereum:
    enabled: true
    rpc_ws: "wss://ethereum.publicnode.com"
    currency: "ETH"
    chain_id: 1
    filters:
      min_value_eth: 0.01
```

**Chaînes supportées :**

| Chaîne | Endpoint public | Gratuit |
|:---|---|:---:|
| Ethereum | `wss://ethereum.publicnode.com` | ✅ |
| BSC | `wss://bsc.publicnode.com` | ✅ |
| Polygon | `wss://polygon-bor-rpc.publicnode.com` | ✅ |
| Arbitrum | `wss://arbitrum-one-rpc.publicnode.com` | ✅ |
| Optimism | `wss://optimism-rpc.publicnode.com` | ✅ |
| Avalanche | `wss://avalanche-c-chain-rpc.publicnode.com` | ✅ |
| Base | `wss://base-rpc.publicnode.com` | ✅ |
| Fantom | `wss://wsapi.fantom.network/` (officiel) | ✅ |
| Gnosis | `wss://rpc.gnosischain.com/wss` | ✅ |
| Celo | `wss://forno.celo.org/ws` (polling) | ✅ |
| Solana | Désactivé (non-EVM) | ❌ |
| Bitcoin | Désactivé (non-EVM) | ❌ |

> Tous les endpoints sont des **nœuds publics gratuits**. Aucune clé API requise pour la surveillance de base.

> **Note** : Fantom utilise désormais `wsapi.fantom.network` (endpoint officiel Fantom Foundation). Gnosis nécessite le path `/wss` (corrigé).

### Clé API optionnelle

Pour la vérification du code source des contrats, une clé **Etherscan V2** est optionnelle :
- Obtenez-la gratuitement sur [etherscan.io/myapikey](https://etherscan.io/myapikey)
- **Une seule clé** fonctionne pour les 60+ chaînes (Ethereum, BSC, Polygon, etc.)
- Sans clé : 1 requête/seconde
- Avec clé : ~5 requêtes/seconde

---

## 🔧 Dépannage

| Problème | Solution |
|:---|---|
| **Aucune chaîne activée** | Activer `enabled: true` dans config.yaml |
| **Échec de connexion** | Vérifier la connexion Internet ; les endpoints publics peuvent être temporairement limités |
| **WebSocket fermé** | Reconnexion automatique avec backoff exponentiel (1s → 60s max) |
| **Aucun bloc n'apparaît** | Ethereum : ~12s par bloc ; Bitcoin : ~10min par bloc |

---

## 📚 Structure du projet

```
blockchain_scanner/
├── main.py              # Point d'entrée CLI
├── guardian.py          # Scanner 24/7 + DB SQLite
├── exploit_pipeline.py  # Validation de vulnérabilités
├── pool_scanner.py      # Scanner de pools DEX
├── hardhat_fork_tester.py # Testeur fork Hardhat
├── scanner/             # Scanner multi-chaîne
├── analysis/            # Analyse de vulnérabilités (34 patterns)
├── filters/             # Filtres de transactions
├── output/              # Affichage terminal
├── confirmators/        # Validateurs (Mythril, etc.)
├── exploit/             # Démos Hardhat
└── findings/            # Catalogue des findings
```

---

## 📖 Voir aussi

- [CHANGELOG.md](https://github.com/reuniware/blockchain_scanner/blob/master/CHANGELOG.md) — Notes de versions techniques détaillées
- [findings/README.md](https://github.com/reuniware/blockchain_scanner/tree/master/findings) — Catalogue des contrats analysés
- [skill/multi-chain-blockchain-scanner.md](https://github.com/reuniware/blockchain_scanner/tree/master/skill) — Documentation complète
