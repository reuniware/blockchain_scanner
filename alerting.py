#!/usr/bin/env python3
"""
Alerting — Webhook notifications pour exploits confirmés
=========================================================
Envoie des alertes en temps réel via Discord et/ou Telegram
quand un exploit est confirmé par le pipeline Hardhat.

Configuration (config.yaml):
    alerting:
      discord_webhook_url: "https://discord.com/api/webhooks/..."
      telegram_bot_token: "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
      telegram_chat_id: "-1001234567890"
      min_severity: "HIGH"  # Minimum severity to alert on (CRITICAL, HIGH, MEDIUM, LOW)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger("alerting")

# Rich emoji prefixes for different event types
SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}

EVENT_EMOJI = {
    "EXPLOIT_CONFIRMED": "🚨",
    "EXPLOIT_REJECTED": "✅",
    "VULN_FOUND": "⚠️",
    "GUARDIAN_START": "🛡️",
    "GUARDIAN_STOP": "🛑",
    "BACKFILL_DONE": "📊",
    "HARDHAT_START": "🔧",
    "HARDHAT_DONE": "⚙️",
}


@dataclass
class AlertEvent:
    """An alert event to be sent via webhooks."""

    event_type: str  # EXPLOIT_CONFIRMED, VULN_FOUND, etc.
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str = ""
    contract_address: str = ""
    chain_name: str = ""
    contract_balance: float = 0.0
    evidence: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    extra_fields: dict = field(default_factory=dict)


class DiscordWebhook:
    """Sends alerts to a Discord channel via webhook URL.

    Uses Discord's rich embed format for clean, readable alerts.
    """

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self._http: Any = None

    async def _get_http(self):
        if self._http is None:
            import httpx
            self._http = httpx.AsyncClient(timeout=10)
        return self._http

    async def send(self, event: AlertEvent) -> bool:
        """Send an alert as a Discord embed.

        Returns True if sent successfully, False on failure.
        """
        if not self.webhook_url:
            return False

        emoji = EVENT_EMOJI.get(event.event_type, "📢")
        severity_icon = SEVERITY_EMOJI.get(event.severity, "⚪")

        embed = {
            "title": f"{emoji} {event.title}",
            "color": self._severity_color(event.severity),
            "timestamp": event.timestamp,
            "fields": [],
            "footer": {"text": f"Blockchain Scanner • {event.severity}"},
        }

        if event.description:
            embed["description"] = event.description[:2000]

        if event.contract_address:
            addr = event.contract_address[:14] + ".."
            explorer_url = (
                f"https://etherscan.io/address/{event.contract_address}"
                if event.chain_name == "ethereum" or "eth" in event.chain_name.lower()
                else f"https://bscscan.com/address/{event.contract_address}"
            )
            embed["fields"].append({
                "name": "📄 Contract",
                "value": f"[{addr}]({explorer_url})",
                "inline": True,
            })

        if event.chain_name:
            embed["fields"].append({
                "name": "⛓️ Chain",
                "value": event.chain_name,
                "inline": True,
            })

        if event.contract_balance > 0:
            embed["fields"].append({
                "name": "💰 Balance",
                "value": f"{event.contract_balance:.4f}",
                "inline": True,
            })

        if event.evidence:
            # Discord embed field values max 1024 chars
            evidence_trimmed = event.evidence[:1024]
            embed["fields"].append({
                "name": "🔍 Evidence",
                "value": f"```{evidence_trimmed[:1000]}```",
                "inline": False,
            })

        if event.extra_fields:
            for k, v in event.extra_fields.items():
                embed["fields"].append({
                    "name": str(k),
                    "value": str(v)[:1024],
                    "inline": True,
                })

        payload = {
            "username": "Blockchain Scanner",
            "avatar_url": "https://i.imgur.com/4M7bFp6.png",
            "embeds": [embed],
        }

        try:
            http = await self._get_http()
            resp = await http.post(self.webhook_url, json=payload)
            if resp.status_code in (200, 204):
                logger.debug(f"[DISCORD] Alert sent: {event.title[:50]}..")
                return True
            else:
                logger.warning(f"[DISCORD] HTTP {resp.status_code}: {resp.text[:200]}")
                return False
        except Exception as e:
            logger.warning(f"[DISCORD] Failed to send alert: {e}")
            return False

    @staticmethod
    def _severity_color(severity: str) -> int:
        """Map severity to Discord embed color (decimal)."""
        colors = {
            "CRITICAL": 0xED4245,  # Red
            "HIGH": 0xFEE75C,      # Yellow/Orange
            "MEDIUM": 0xFEE75C,    # Yellow
            "LOW": 0x5865F2,       # Blue
            "INFO": 0x808080,      # Gray
        }
        return colors.get(severity, 0x808080)

    async def close(self):
        if self._http:
            await self._http.aclose()
            self._http = None


class TelegramAlert:
    """Sends alerts to a Telegram chat via bot API.

    Uses Telegram's HTML parse_mode for rich formatting.
    """

    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self._http: Any = None
        self._api_base = f"https://api.telegram.org/bot{bot_token}"

    async def _get_http(self):
        if self._http is None:
            import httpx
            self._http = httpx.AsyncClient(timeout=10, base_url=self._api_base)
        return self._http

    async def send(self, event: AlertEvent) -> bool:
        """Send an alert as a Telegram HTML message.

        Returns True if sent successfully, False on failure.
        """
        if not self.bot_token or not self.chat_id:
            return False

        emoji = EVENT_EMOJI.get(event.event_type, "📢")
        severity_icon = SEVERITY_EMOJI.get(event.severity, "⚪")

        # Build HTML message
        parts = [
            f"<b>{emoji} {severity_icon} {event.title}</b>",
        ]

        if event.description:
            parts.append(f"\n{event.description[:500]}")

        if event.contract_address:
            parts.append(f"\n📄 <b>Contract:</b> <code>{event.contract_address[:20]}..</code>")

        if event.chain_name:
            parts.append(f"\n⛓️ <b>Chain:</b> {event.chain_name}")

        if event.contract_balance > 0:
            parts.append(f"\n💰 <b>Balance:</b> {event.contract_balance:.4f}")

        if event.evidence:
            evidence_trimmed = event.evidence[:500]
            parts.append(f"\n🔍 <b>Evidence:</b>\n<pre>{evidence_trimmed[:400]}</pre>")

        if event.extra_fields:
            for k, v in event.extra_fields.items():
                parts.append(f"\n<b>{k}:</b> {str(v)[:200]}")

        message = "".join(parts)

        # Telegram max message length: 4096 chars
        if len(message) > 4000:
            message = message[:3997] + "..."

        try:
            http = await self._get_http()
            resp = await http.post(
                "/sendMessage",
                json={
                    "chat_id": self.chat_id,
                    "text": message,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                },
            )
            if resp.status_code == 200:
                logger.debug(f"[TELEGRAM] Alert sent: {event.title[:50]}..")
                return True
            else:
                data = resp.json()
                logger.warning(f"[TELEGRAM] API error: {data.get('description', resp.text)[:200]}")
                return False
        except Exception as e:
            logger.warning(f"[TELEGRAM] Failed to send alert: {e}")
            return False

    async def close(self):
        if self._http:
            await self._http.aclose()
            self._http = None


class AlertManager:
    """Manages multiple alert channels (Discord + Telegram).

    Reads configuration from config.yaml's alerting section.
    Routes events to all configured channels based on severity filter.
    """

    def __init__(self, config: Optional[dict] = None):
        """
        Args:
            config: Config dict with alerting section. If None, no alerts sent.
        """
        self.config = config or {}
        alert_cfg = self.config.get("alerting", {})

        # Discord
        discord_url = alert_cfg.get("discord_webhook_url", "")
        self.discord = DiscordWebhook(discord_url) if discord_url else None

        # Telegram
        telegram_token = alert_cfg.get("telegram_bot_token", "")
        telegram_chat = alert_cfg.get("telegram_chat_id", "")
        self.telegram = (
            TelegramAlert(telegram_token, telegram_chat)
            if telegram_token and telegram_chat
            else None
        )

        # Severity filter
        min_sev = alert_cfg.get("min_severity", "HIGH").upper()
        self._severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self._min_severity_level = self._severity_order.get(min_sev, 1)

    def _should_alert(self, event: AlertEvent) -> bool:
        """Check if event meets the minimum severity threshold."""
        event_level = self._severity_order.get(event.severity, 99)
        return event_level <= self._min_severity_level

    async def send(self, event: AlertEvent) -> dict[str, bool]:
        """Send an alert to all configured channels.

        Args:
            event: AlertEvent to send.

        Returns:
            Dict of channel_name -> success_status.
        """
        if not self._should_alert(event):
            return {}

        results = {}

        if self.discord:
            ok = await self.discord.send(event)
            results["discord"] = ok

        if self.telegram:
            ok = await self.telegram.send(event)
            results["telegram"] = ok

        if not results:
            logger.debug(f"[ALERT] No channels configured for: {event.title[:50]}..")
        else:
            ok_count = sum(1 for v in results.values() if v)
            logger.info(
                f"[ALERT] Sent '{event.title[:50]}..' "
                f"({ok_count}/{len(results)} channels)"
            )

        return results

    async def send_exploit_confirmed(
        self,
        contract_address: str,
        chain_name: str,
        finding_name: str,
        severity: str,
        evidence: str = "",
        balance: float = 0.0,
        extra: Optional[dict] = None,
    ) -> dict[str, bool]:
        """Convenience: send an EXPLOIT_CONFIRMED alert."""
        return await self.send(AlertEvent(
            event_type="EXPLOIT_CONFIRMED",
            severity=severity,
            title=f"🚨 EXPLOIT CONFIRMÉ: {finding_name}",
            description=f"L'exploit {finding_name} a été confirmé sur le contrat {contract_address[:14]}..",
            contract_address=contract_address,
            chain_name=chain_name,
            contract_balance=balance,
            evidence=evidence,
            extra_fields=extra or {},
        ))

    async def send_vuln_found(
        self,
        contract_address: str,
        chain_name: str,
        finding_name: str,
        severity: str,
        balance: float = 0.0,
        extra: Optional[dict] = None,
    ) -> dict[str, bool]:
        """Convenience: send a VULN_FOUND alert."""
        return await self.send(AlertEvent(
            event_type="VULN_FOUND",
            severity=severity,
            title=f"{SEVERITY_EMOJI.get(severity, '⚠️')} Vulnérabilité détectée: {finding_name}",
            description=f"Finding [{severity}] sur {contract_address[:14]}.. ({chain_name})",
            contract_address=contract_address,
            chain_name=chain_name,
            contract_balance=balance,
            extra_fields=extra or {},
        ))

    async def close(self):
        if self.discord:
            await self.discord.close()
        if self.telegram:
            await self.telegram.close()
