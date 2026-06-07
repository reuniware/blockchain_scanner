# Findings — Contrats analysés et vulnérabilités

Ce répertoire répertorie tous les contrats analysés par le scanner de vulnérabilités, avec les résultats détaillés de chaque analyse.

## Résumé

| Statut | Nombre |
|:---|---:|
| Contrats scannés | ~60 |
| Contrats vérifiés analysés | 20+ |
| DEX non-bluechip analysés | 5 |
| Nouveaux déploiements (non vérifiés) | 40+ |
| Findings totaux | **28** |
| Exploitables (théorique - pipeline) | **19** (12 DEX + 7 CampaignWrapper) |
| Exploitables (validé empiriquement) | 1 pattern (CEI reentrancy CampaignWrapper) |
| Faux positifs (blue-chips audités) | ~85% |
| Faux positifs (non-bluechip DEX) | **~50%** (Init protégés par require custom) |

## Derniers contrats analysés

| Contrat | Chaîne | Findings | Expl. (Théorique) | Expl. (Empirique) | Rapport |
|:---|---|:---:|:---:|:---:|:---:|
| **CampaignWrapper** (`0x8a56c6be..`) | Ethereum | 8 (7 HIGH, 1 MED) | **7/8** | Pattern validé ✅ | [Détail](campaign_wrapper.md) |
| **CZ Token** (`0xfe61a573..`) | BSC | 0 | - | - | Token standard |
| **Token** (`0xff9a0457..`) | BSC | 0 | - | - | Token standard |
| **DigitalToken** (`0xab1e5f6b..`) | BSC | 0 | - | - | Token standard |
| **BabySwap BabySmartRouter** (`0x8317c460..`) | BSC | **6** (1 CRIT, 3 HIGH, 2 MED) | **4** | 🔴 Delegatecall + Reentrancy |
| **BiSwap SmartRouter** (`0x0eB6949e..`) | BSC | **5** (3 HIGH, 2 MED) | **3** | Withdraw ×2 + Init |
| **ApeSwap ApeRouter** (`0xcF0feBd3..`) | BSC | **4** (3 HIGH, 1 MED) | **3** | Reentrancy + Withdraw + Init |
| **BiSwap Factory** (`0x858e3312..`) | BSC | **3** (2 HIGH, 1 MED) | **2** | Init ×2 |
| **WETH9** (`0xc02aaa39..`) | Ethereum | 2 (1 HIGH, 1 MED) | 1/2 | Faux positif | CEI respecté |
| **DAI** (`0x6b175474..`) | Ethereum | 0 | - | - | Propre |
| **USDC** (`0xa0b86991..`) | Ethereum | 0 | - | - | Propre |
| **UNI** (`0x1f9840a8..`) | Ethereum | 0 | - | - | Propre |

### Nouveaux déploiements (juin 2026)

| Contrat | Chaîne | Statut | Verdict |
|:---|---|:---:|:---:|
| `0xb3e1d10577d185f0e9ae3b8821d7a5e35b8db5f9` | Ethereum | ❌ Non vérifié | Impossible d'analyser |
| `0xb4b9dc1c5a6a044b19b283d1e1a6c10030c3a35` | Ethereum | ❌ Non vérifié | Impossible d'analyser |
| +8 autres nouveaux déploiements ETH | Ethereum | ❌ Non vérifié | Impossible d'analyser |

**Leçon :** Les contrats fraîchement déployés ne sont presque jamais vérifiés. Pour analyser des contrats non audités, il faut soit scanner des contrats vérifiés plus anciens, soit attendre la vérification post-déploiement.

### DEX Routers — Soldes vérifiés

**Tous les routeurs DEX testés ont 0 BNB de solde.** Les fonds sont dans les Pair contracts (pools), pas dans les routeurs.

| Contrat | Balance BNB | TVL | Verdict |
|:---|---:|:---:|:---|
| BabySmartRouter | 0.00000000 | - | Routeur — pas de fonds |
| BabyPair (WBNB-USDT) | 0.00000000 | **$27M** 📍 | Pair — fonds présents mais clone UniswapV2 protégé |
| BiSwap SmartRouter | 0.00000000 | - | Routeur — pas de fonds |
| ApeRouter | 0.00000000 | - | Routeur — pas de fonds |
| BiSwap Factory | 0.00000000 | - | Factory — pas de fonds |

**Conclusion :** Les vulnérabilités sont dans les routeurs (0 BNB), les fonds sont dans les pairs (protégés). Aucun contrat avec **à la fois** des fonds ET une faille exploitable n'a été trouvé.

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
