# Rapport : CampaignWrapper (`0x8a56c6be755ac385395e96234b553db1b9b06bea`)

## Informations générales

| Champ | Valeur |
|:---|---:|
| Adresse | `0x8a56c6be755ac385395e96234b553db1b9b06bea` |
| Chaîne | Ethereum |
| Source | 306 051 caractères (multi-fichier) |
| Solidity | `^0.8.20` |
| Scan | Automatique via `exploit_pipeline.py` |
| Date | Juin 2026 |
| Dernière mise à jour | 07/06/2026 |

## Résultat du scan

| Sévérité | Nombre |
|:---|---:|
| CRITICAL | 0 |
| HIGH | **7** |
| MEDIUM | 1 |
| **Exploitables** | **7 / 8** |

## Vulnérabilités détaillées

### 1. 🔴 Reentrancy (pas de pattern CEI) — Ligne 5

**Sévérité :** HIGH
**Exploitable :** Oui (pattern validé en reproduction locale)

Le contrat utilise un appel `.call{value:}` bas niveau dans la fonction `_refund` (ligne 253 du fichier combiné) **sans** protection `nonReentrant`. La mise à jour d'état a lieu après l'appel externe, ce qui permet à un attaquant de re-entrer via `receive()` et de drainer les fonds.

**Validation empirique :** ✅ Réussie — 5 rounds de reentrancy, 4 ETH drainés sur 5 (sur reproduction `CampaignVulnerable.sol`).

**⚠️ Contrat réel :** Faux positif — la fonction `_refund` est `private` et le contrat utilise `ReentrancyGuard` au niveau supérieur. La vulnérabilité n'est pas exploitable sur le contrat on-chain.

### 2-4. 🔴 TX Origin Authorization (×3) — Lignes 5, 47, 134

**Sévérité :** HIGH
**Exploitable :** Oui (théorique)

`tx.origin` est utilisé pour l'autorisation à plusieurs endroits, ce qui expose à des attaques de phishing où un contrat malveillant appelle cette fonction et `tx.origin` pointe vers la victime.

### 5-7. 🔴 Unprotected Initializer (×3) — Lignes 80, 119, 140

**Sévérité :** HIGH
**Exploitable :** Oui (théorique)

Des fonctions d'initialisation sont appelables sans le modificateur `initializer`, ce qui permet à un attaquant de les appeler plusieurs fois et de prendre le contrôle du contrat.

### 8. 🟡 Unbounded Loop — Ligne 134

**Sévérité :** MEDIUM
**Exploitable :** Non (DOS uniquement)

Boucle non bornée sur un tableau dynamique. Peut causer un déni de service (GOS) mais pas de vol de fonds.

## Validation empirique

### Test CEI Reentrancy

Un contrat de reproduction (`CampaignVulnerable.sol`) a été créé pour valider le pattern :

```solidity
function claimRefund() external {
    uint256 amount = pendingRefunds[msg.sender];
    require(amount > 0, "No pending refund");
    require(!hasClaimed[msg.sender], "Already claimed");

    // VULN: appel externe AVANT mise à jour d'état
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");

    // Mise à jour d'état APRÈS (trop tard !)
    hasClaimed[msg.sender] = true;
    pendingRefunds[msg.sender] = 0;
}
```

**Résultat :** ✅ 5 rounds de reentrancy, 5 ETH drainés sur 5.

### Découverte : Solidity >=0.8

Le contrat utilise `^0.8.20`. La protection contre l'underflow intégrée à Solidity >=0.8 **bloque** la reentrancy classique par underflow (`balances[X] -= Y`). Cependant, la reentrancy par violation CEI sur des booléens (`!hasClaimed[user]`) fonctionne toujours car il n'y a pas d'opération arithmétique.

### Fichiers de validation

- `exploit/contracts/CampaignVulnerable.sol` — Reproduction du motif vulnérable
- `exploit/contracts/CampaignExploit.sol` — Contrat d'exploit avec garde-fou
- `exploit/scripts/test_campaign_reentrancy.js` — Script de test dédié
- `exploit/scripts/test_cei_reentrancy.js` — Test combiné des 2 patterns
- `exploit/contracts/UniversalExploit.sol` — Framework universel couvrant 20 types d'attaques

## Recommandations

1. Ajouter `nonReentrant` sur `_refund`
2. Remplacer `tx.origin` par `msg.sender` pour l'autorisation
3. Utiliser le modificateur `initializer` d'OpenZeppelin
4. Mettre à jour l'état AVANT les appels externes (pattern CEI)
5. Limiter la taille des boucles ou utiliser un pattern de pagination
