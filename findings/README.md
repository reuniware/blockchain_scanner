# Findings — Contrats analysés et vulnérabilités

Ce répertoire répertorie tous les contrats analysés par le scanner de vulnérabilités, avec les résultats détaillés de chaque analyse.

## Résumé

| Statut | Nombre |
|:---|---:|
| Contrats scannés | ~15 |
| Haute sévérité trouvées | 10 |
| Exploitables (théorique - pipeline) | 8 |
| Exploitables (validé empiriquement) | 1 pattern (CEI reentrancy) |
| Faux positifs (contrats audités) | ~85% |

## Derniers contrats analysés

| Contrat | Chaîne | Findings | Expl. (Théorique) | Expl. (Empirique) | Rapport |
|:---|---|:---:|:---:|:---:|:---:|
| **CampaignWrapper** (`0x8a56c6be..`) | Ethereum | 8 (7 HIGH, 1 MED) | **7/8** | Pattern validé ✅ | [Détail](campaign_wrapper.md) |
| **CZ Token** (`0xfe61a573..`) | BSC | 0 | - | - | Token standard |
| **Token** (`0xff9a0457..`) | BSC | 0 | - | - | Token standard |
| **WETH9** (`0xc02aaa39..`) | Ethereum | 2 (1 HIGH, 1 MED) | 1/2 | Faux positif | CEI respecté |
| **DAI** (`0x6b175474..`) | Ethereum | 0 | - | - | Propre |
| **USDC** (`0xa0b86991..`) | Ethereum | 0 | - | - | Propre |
| **UNI** (`0x1f9840a8..`) | Ethereum | 0 | - | - | Propre |

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
