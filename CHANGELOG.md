# Changelog

> Notes techniques détaillées des sessions de développement, correctifs et améliorations.

---

## Session 10 — Fix kill_all_node_processes + 4 nouvelles chaînes EVM + anti-OOM + endpoints WS (10/06/2026)

| Bug | Cause racine | Correctif |
|:---|---|:---|
| **`kill_all_node_processes`: WinError 2 (wmic introuvable)** | `wmic` est déprécié sur Windows 11 — la commande WQL échoue | Remplacé par `Get-CimInstance` PowerShell (moderne, fiable) |
| **Base, Fantom ignorées** | `_create_scanner()` n'avait que 6 chaînes EVM — Base et Fantom passaient dans le `else` | Ajoutées au tuple : `base, fantom, gnosis, celo` |
| **Gnosis (100), Celo (42220) absentes** | Pas de RPC, pas de CHAIN_REGISTRY, pas de config | Ajoutées dans orchestrator, CONFIG_REGISTRY, config.yaml, hardhat_fork_tester |
| **Fantom WS `wss://fantom-rpc.publicnode.com` mort** | Le noeud public PublicNode ne répond plus | Remplacé par `wss://wsapi.fantom.network/` (officiel Fantom Foundation) |
| **Gnosis WS `wss://rpc.gnosischain.com` mort** | L'URL n'avait pas le path `/wss` nécessaire | Corrigé : `wss://rpc.gnosischain.com/wss` |
| **OOM sur longues runs** | Logs non rotatés, GC non forcé, pas de monitoring mémoire | Anti-OOM : rotation logs >50 Mo, `gc.collect()` toutes les 10 min, RSS Windows/Linux, détection fuite tâches asyncio |

**Fichiers modifiés :**
- `guardian.py` — `kill_all_node_processes()` : PowerShell Get-CimInstance au lieu de wmic ; nouvel anti-OOM `memory_cleanup_loop()`
- `scanner/orchestrator.py` — `_create_scanner()` : +base, +fantom, +gnosis, +celo
- `config.yaml` — Nouveaux endpoints WS Fantom/Gnosis ; sections gnosis + celo complètes
- `exploit_pipeline.py` — CHAIN_REGISTRY : +Gnosis (100), +Celo (42220)
- `hardhat_fork_tester.py` — RPC_URLS, CHAIN_NAMES, chain_ids : +Gnosis, +Celo
- `scanner/evm_scanner.py` — `_connect()` : support HTTPProvider pour les chaînes sans WS ; `_listen()` : fallback polling direct
- `findings/README.md` — session 10 documentée, stats mises à jour

| Bug | Cause racine | Correctif |
|:---|---|:---|
| **zkSync Era (324) absente** | Pas de RPC/CHAIN_REGISTRY/config | Ajoutée avec WS public `wss://mainnet.era.zksync.io/ws` |
| **Scroll (534352) absente** | Pas de WS public gratuit | Ajoutée en HTTP polling via `rpc_http` |
| **Linea (59144) absente** | Pas de WS public gratuit | Ajoutée en HTTP polling via `rpc_http` |
| **Polygon zkEVM (1101) absente** | Pas de WS public gratuit | Ajoutée en HTTP polling via `rpc_http` |
| **EVMScanner refuse `rpc_ws: ""`** | `_connect()` lève `ValueError` si `rpc_ws` vide → boucle de reconnexion infinie | `_connect()` utilise `HTTPProvider` ; `_listen()` bascule en `_poll_blocks()` direct si pas de socket WS |
| **chain_ids dict non mis à jour** | Dict `chain_ids` dans `main()` manquait gnosis, celo + les 4 nouvelles | Ajout de toutes les 14 chaînes dans le dict ; help CLI mis à jour |

**Fichiers modifiés :**
- `config.yaml` — +zksync, +scroll, +linea, +polygon_zkevm (sections complètes)
- `scanner/orchestrator.py` — tuple EVM : +zksync, +scroll, +linea, +polygon_zkevm
- `scanner/evm_scanner.py` — `_connect()` : HTTPProvider fallback ; `_listen()` : polling direct si pas de socket
- `exploit_pipeline.py` — CHAIN_REGISTRY + CLI help + chain_ids : +zksync, scroll, linea, polygon_zkevm
- `hardhat_fork_tester.py` — RPC_URLS, CHAIN_NAMES, chain_ids, help : +zksync, scroll, linea, polygon_zkevm
- `README.md` — table des chaînes mise à jour (14 EVM)

**Résultat :** Guardian tourne sur **14 chaînes EVM** (10 WS temps réel + 4 HTTP polling).

## Session 9 — Mythril + hardhat_setBalance + template .call() (12/06/2026)

| Bug | Cause racine | Correctif |
|:---|---|:---|
| **L'usurpation de baleine ne fonctionne pas sur Arbitrum/Optimism** | `hardhat_impersonateAccount` + `eth_sendTransaction` fonctionne sur Ethereum/BSC mais pas sur toutes les chaînes EVM | Remplacé par `hardhat_setBalance` (norme EIP-1898) — fonctionne sur toutes les chaînes EVM, pas besoin d'usurpation |
| **Le template d'exploit revient si la fonction est absente** | Le contrat exploit appelle `target.withdraw()` avec un sélecteur fixe → si la fonction n'existe pas, la TX revient | Template changé pour `.call(abi.encodeWithSignature(...))` de bas niveau — ne revient pas si la fonction est absente (retourne false) |

**Fichiers modifiés :**
- `guardian.py` — `_generate_exploit_contract()` : template `.call()` au lieu de `withdraw()` fixe, `hardhat_setBalance` au lieu d'usurpation de baleine
- `guardian.py` — `update_hardhat_result_by_id()` : nouvelle méthode pour mise à jour par ID (plus robuste que par nom)
- `guardian.py` — `kill_all_node_processes()` : nettoyage des processus orphelins, suivi via `self._processes`
- `confirmators/mythril_confirmator.py` (nouveau) — validateur Mythril en sous-processus, bytecode via `eth_getCode`

## Session 8 — Gestion des processus + nettoyage Hardhat (10/06/2026)

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

## Session 7 — Pipeline HardhatValidator (09/06/2026)

4 bugs corrigés dans le pipeline de validation Hardhat `guardian.py`:

| Bug | Cause racine | Correctif |
|:---|---|:---|
| **`No FINDING_RESULT for idx X`** | L'attaquant (signer Hardhat) avait **0 ETH** sur le fork → toutes les transactions échouaient | Ajout d'une **usurpation de baleine** (Binance 0xF97..aceC) → envoi de 50 ETH à l'attaquant avant les tests |
| **`tx0.wait is not a function`** | Le template générique Solidity utilisait `pure` → ethers v6 fait un `eth_call` (retourne string) au lieu d'une transaction | Changé pour `bool public attacked` + `attacked = true` → fonction non-`pure` → ethers retourne une `TransactionResponse` |
| **Noms de contrat dupliqués** | `datetime.utcnow().timestamp()` → collisions dans la même seconde | Nommage par **index** (`Exploit_{index}`) via `enumerate()` dans `validate_contract()` |
| **Le script combiné ne termine pas** | Pas de `process.exit(0)` → le provider Hardhat maintient la boucle d'événements active | Ajout de `.then(() => process.exit(0))` à la fin du `main()` |

## Sessions 1–6 — Développement initial du scanner

- Mise en place du scanner multi-chaînes (EVM, Bitcoin, Solana)
- 34 patterns de détection de vulnérabilités Solidity
- Pipeline d'exploit automatisé
- Guardian 24/7 avec base SQLite
- Pool Scanner via DEX Screener API
- Tests Hardhat fork pour validation d'exploits
- Intégration Mythril (exécution symbolique)
- CI/CD avec GitHub Actions + publication PyPI
