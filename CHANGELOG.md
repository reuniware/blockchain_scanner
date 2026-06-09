# Changelog

> Notes techniques détaillées des sessions de développement, correctifs et améliorations.

---

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
