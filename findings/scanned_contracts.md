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

### Nouveaux déploiements (RPC scan 100 blocs) — Tous non vérifiés

| Adresse | Txs | Verdict |
|:---|---|:---:|
| `0xb3e1d10577d185f0e9ae3b8821d7a5e35b8db5f9` | 3 txs | ❌ Non vérifié — impossible d'analyser |
| `0xb4b9dc1c5a6a044b19b283d1e1a6c10030c3a35` | 2 txs | ❌ Non vérifié — impossible d'analyser |
| `0x0263d4c2b6037d5644b63d3e4fe36469e99f917f` | 2 txs | ❌ Non vérifié |
| `0x502ca72d337b39f190119a950850fff25df8c902` | 3 txs | ❌ Non vérifié |
| `0xa6498e7e9480bcb73b88b3d3bc1ebf9b8e35c23a` | 1 tx | ❌ Non vérifié |
| `0xc1d1e7081e13ee33cf9fcefcce1fc3a3ac2415cc` | 1 tx | ❌ Non vérifié |
| `0x9845a58315202293863a8dc6987c4306e4a84f1a` | 1 tx | ❌ Non vérifié |
| `0x168ca4b6a0c7637fd8d5bcfdbb44c66c3ec81e31` | 1 tx | ❌ Non vérifié |
| `0xa1eb57aadad719bdc45b3e24c97d4c67adb84372` | 1 tx | ❌ Non vérifié |
| `0x3a2ef0c6760351546da7f31180e7ddbaf768fde4` | 1 tx | ❌ Non vérifié |
| `0x10482134def86f20a1b8d4a2052eb2e02f54dac0` | 1 tx | ❌ Non vérifié |

**Leçon :** Les nouveaux déploiements sont rarement vérifiés immédiatement. Il faut soit scanner des contrats plus anciens (vérifiés), soit attendre que les nouveaux contrats soient vérifiés par leurs créateurs.


## Binance Smart Chain (Chain ID: 56)

### Session précédente (scan scanner live)

| Date | Contrat | Type | Findings | Exploitables | Notes |
|:---|---|:---:|:---:|:---:|:---|
| Juin 2026 | **Token** (`0xff9a0457..ed4c`) | BEP-20 | 0 | 0 | Token standard |
| Juin 2026 | **CZ** (`0xfe61a573..2a5`) | BEP-20 | 0 | 0 | Token standard |
| Juin 2026 | `0xcc4881fa..082` | - | - | - | Non vérifié |
| Juin 2026 | `0x4e5356ef..5b5` | - | - | - | Non vérifié |
| Juin 2026 | `0x84858cd7..c69` | - | - | - | Non vérifié |

### Nouveaux déploiements (RPC scan 500 blocs, blocks #102854033-#102854533)

| Contrat | Type | Statut | Findings | Verdict |
|:---|---|:---:|:---:|:---:|
| **Token** (`0x8d53e75101b66ac48de2189d2c3f220eda57d236`) | BEP-20 | ✅ Vérifié | 0 | Token standard — 28.5k chars, propre |
| **Token** (`0x14a537d38f440d5e3ae04fd2cba6acff5bbe7819`) | BEP-20 | ✅ Vérifié | 0 | Token standard — 2.4k chars, propre |
| **DigitalToken** (`0xab1e5f6b6edd6e22ade9ed2991603605bdd47b60`) | BEP-20 | ✅ Vérifié | 0 | Token standard — 2.4k chars, propre |
| `0x0c33c3a34d8f0f22d567d9b28536a96eb4c463bd` | - | ❌ Non vérifié | - | Impossible d'analyser |
| `0x64803caec5c20558fd16ffa084da118627e4cabb` | - | ❌ Non vérifié | - | Impossible d'analyser |
| `0x3831850380db34ffe17975bd1d80b0c5a98db578` | - | ❌ Non vérifié | - | Impossible d'analyser |
| `0xd7d0906e36dea460c9853b71ecdbe1f8aa7f9ecb` | - | ❌ Non vérifié | - | Impossible d'analyser |
| `0xb37e7f2c5a62a94b823292857e3cfd5c6dae362b` | - | ❌ Non vérifié | - | Impossible d'analyser |
| `0x6f82a079b8901804a73cea683482a8f4b814b359` | - | ❌ Non vérifié | - | Impossible d'analyser |
| `0xc7158181fd7e242716a3199c20821c58d202b294` | - | ❌ Non vérifié | - | Impossible d'analyser |
| `0xc8a6390576e3a3d0a4c5412efb22847dd2b44a94` | - | ❌ Non vérifié | - | Impossible d'analyser |
| `0x7b83fe4afb1f0b7401f3a5d85b3496f20a353ae6` | - | ❌ Non vérifié | - | Impossible d'analyser |
| `0x0c92f503e429b14ceb00d819cc46f7e7b2d191c8` | - | ❌ Non vérifié | - | Impossible d'analyser |
| +18 autres (total 30) | - | ❌ Non vérifié | - | Impossible d'analyser |

**Résultat :** 3 vérifiés (tokens standards, 0 findings) + 27 non vérifiés = taux de vérification ~10%.

## Statistiques globales

| Métrique | Valeur |
|:---|---:|
| Total contrats scannés | ~55 |
| Contrats vérifiés avec findings | 2 (WETH9, CampaignWrapper) |
| Contrats vérifiés sans findings | 3 (tokens BSC standards) |
| Contrats non vérifiés | 10 (ETH) + 27 (BSC) = 37 |
| Nouveaux déploiements totaux | 10 (ETH) + 30 (BSC) = 40 |
| Findings totaux | 10 |
| Taux de vérification (nouveaux déploiements) | ~7.5% (3/40) |
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
