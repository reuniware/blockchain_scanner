# Guardian Auto-Report
> **manual** — 2026-06-12 12:00:00 UTC

## Statistiques globales

| Métrique | Valeur |
|----------|--------|
| Contrats dans la DB | 24945 |
| Vérifiés (source disponible) | 985 |
| Findings totaux | 8109 |
| Findings exploitables | 4943 |
| Analyses Mythril (bytecode) | 4 (0 issues, complémentaire) |
| Exploits confirmés Hardhat | 0 |
| Échecs tests Hardhat | 2635 |

## Session 9 — Nouveautés (12/06/2026)

| Fonctionnalité | Description |
|---------------|------------|
| `--with-mythril` | Confirmateur Mythril par exécution symbolique (sous-processus, 0 dépendance d'import) |
| `confirmators/mythril_confirmator.py` | Nouveau module — bytecode via eth_getCode + `myth analyze --bin` |
| `.mythril-env` | Venv Python 3.12 + mythril 0.24.8 auto-détecté |
| 4 contrats BSC testés | 0 issues Mythril vs 40 issues pipeline (complémentarité bytecode vs source) |
| Hardhat fix: hardhat_setBalance | Remplace whale impersonation, marche sur toutes les chaînes |

## Session 7 — Nouveautés (09/06/2026)

| Fonctionnalité | Description |
|---------------|------------|
| `--backfill --force --backfill-hardhat` | Backfill force + validation Hardhat fork — testé sur 5 contrats BSC |
| `--backfill-feedback N` | Affiche la progression toutes les N contrats (processed, findings, ETA) |
| 5 contrats BSC testés | WBNB, ERC1967Proxy, ApolloxExchangeTreasury, TransparentUpgradeableProxy, PancakePredictionV2 |
| 33 findings validés | **0 confirmé** — tous FAILED sur Hardhat fork |

## Session 6 — Nouveautés

| Fonctionnalité | Description |
|---------------|------------|
| `--backfill-hardhat` | Pipeline complet DB → source → analyse → **Hardhat fork → confirmation** |
| `--stop-on confirmed` | Auto-stop après validation par le pipeline (pas juste la détection) |
| Filtre EOA | `eth_getCode` avant analyse — évite les faux positifs cross-chain |
| Cache source | Pas de double appel API incohérent Etherscan |
| **Performance ×20** | `validate_contract()` : 1 fork/contrat au lieu de 1/finding (~3s au lieu de ~60s) |

## Répartition par chaîne

| Chaîne | Contrats | Vérifiés |
|-------|-----------|----------|
| Binance Smart Chain | 18322 | 131 |
| Ethereum | 2742 | 201 |
| Arbitrum | 1911 | 584 |
| Polygon | 917 | 2 |
| Avalanche C-Chain | 783 | 32 |
| Optimism | 270 | 35 |

## Top 15 des findings exploitables

| Contract | Chain | Severity | Balance | Contract Name | Finding |
|----------|-------|----------|---------|---------------|---------|
| 0x0c880f6761f1.. | Arbitrum | CRITICAL | 0 | Unknown | Delegatecall to Variable Address |
| 0x7f9fbf9bdd3f.. | Arbitrum | CRITICAL | 0 | Unknown | Delegatecall to Variable Address |
| 0x4c749d097832.. | Arbitrum | CRITICAL | 0 | Unknown | Delegatecall to Variable Address |
| 0x33b49f2264e8.. | Arbitrum | CRITICAL | 0 | Unknown | Delegatecall to Variable Address |
| 0x25118290e6a5.. | Arbitrum | CRITICAL | 0 | Unknown | Delegatecall to Variable Address |
| 0x9623063377ad.. | Arbitrum | CRITICAL | 0 | Unknown | Delegatecall to Variable Address |
| 0x9623063377ad.. | Arbitrum | CRITICAL | 0 | Unknown | Delegatecall to Variable Address |
| 0x4cb9a7ae498c.. | Arbitrum | CRITICAL | 0 | Unknown | Delegatecall to Variable Address |
| 0xe50fa9b3c56f.. | Arbitrum | CRITICAL | 0 | Unknown | Delegatecall to Variable Address |
| 0xae7ab96520de.. | Ethereum | CRITICAL | 223.6169 | Unknown | Delegatecall to Variable Address |
| 0x2c5d06f591d0.. | Arbitrum | CRITICAL | 0 | Unknown | Delegatecall to Variable Address |
| 0x2c5d06f591d0.. | Arbitrum | CRITICAL | 0 | Unknown | Delegatecall to Variable Address |
| 0x7f1fa204bb70.. | Arbitrum | CRITICAL | 0 | Unknown | Delegatecall to Variable Address |
| 0x2a5e22b32b3e.. | Arbitrum | CRITICAL | 0 | Unknown | Delegatecall to Variable Address |
| 0xe93307b8faa1.. | Arbitrum | CRITICAL | 0 | Unknown | Delegatecall to Variable Address |
