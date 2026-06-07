# Registre des contrats scannés

Tous les contrats analysés par le scanner de vulnérabilités, classés par chaîne.

---

## Ethereum (Chain ID: 1)

| Date | Contrat | Type | Findings | Exploitables | Notes |
|:---|---|:---:|:---:|:---:|:---|
| Juin 2026 | **CampaignWrapper** (`0x8a56c6be..06bea`) | Complexe | **8** (7 HIGH, 1 MED) | **7** | Reentrancy + TX Origin + Unprotected Init |
| Juin 2026 | **WETH9** (`0xc02aaa39..6cc2`) | Token | 2 (1 HIGH, 1 MED) | 0 | Faux positif withdraw (CEI + .transfer) |
| Juin 2026 | **USDC** (`0xa0b86991..eb48`) | Token | 0 | 0 | Blue-chip audité |
| Juin 2026 | **WBTC** (`0x2260fac5..c599`) | Token | 0 | 0 | Blue-chip audité |
| Juin 2026 | **USDT** (`0xdac17f95..1ec7`) | Token | 0 | 0 | Blue-chip audité |
| Juin 2026 | **DAI** (`0x6b175474..1d0f`) | Token | 0 | 0 | Blue-chip audité |
| Juin 2026 | **UNI** (`0x1f9840a8..f984`) | Token | 0 | 0 | Blue-chip audité |
| Juin 2026 | **PEPE** (`0x69825081..1933`) | Token | 0 | 0 | Token standard |

### Autres contrats vérifiés (0 findings)

| Adresse | Nom |
|:---|---:|
| `0xef0ced5d..d78` | Non vérifié |
| `0x7bf9a821..f68` | Non vérifié |
| `0xa373fbac..95b` | Non vérifié |
| `0xf8da8dc6..005` | Non vérifié |

## Binance Smart Chain (Chain ID: 56)

| Date | Contrat | Type | Findings | Exploitables | Notes |
|:---|---|:---:|:---:|:---:|:---|
| Juin 2026 | **Token** (`0xff9a0457..ed4c`) | BEP-20 | 0 | 0 | Token standard |
| Juin 2026 | **CZ** (`0xfe61a573..2a5`) | BEP-20 | 0 | 0 | Token standard |
| Juin 2026 | `0xcc4881fa..082` | - | - | - | Non vérifié |
| Juin 2026 | `0x4e5356ef..5b5` | - | - | - | Non vérifié |
| Juin 2026 | `0x84858cd7..c69` | - | - | - | Non vérifié |

## Statistiques globales

| Métrique | Valeur |
|:---|---:|
| Total contrats scannés | ~15 |
| Contrats avec findings | 2 (WETH9, CampaignWrapper) |
| Findings totaux | 10 |
| Exploitables (théoriques) | 8 |
| Exploitables (empiriques) | ✅ Reentrancy CEI validée |
| Taux de faux positifs (audités) | ~85% |
| Taux de faux positifs (non audités) | ~0% (pas encore testé) |

## Méthodologie

1. **Détection** : Scanner live des blocs (Ethereum Infura) ou scan RPC direct
2. **Vérification** : Appel API Etherscan V2 pour vérifier le code source
3. **Analyse** : `analysis/vulnerability_scanner.py` — 10 patterns de vulnérabilités
4. **Validation** : `exploit_pipeline.py` — validation théorique (version Solidity, unchecked, ACL)
5. **Confirmation** : Tests Hardhat locaux pour les patterns validés
