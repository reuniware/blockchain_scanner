"""Transaction filtering system for multi-chain scanner."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from scanner.base import TransactionEvent


@dataclass
class FilterResult:
    """Result of filtering a transaction."""

    passed: bool
    reason: Optional[str] = None


class TransactionFilter:
    """Multi-chain transaction filter.

    Applies global and per-chain filtering rules to TransactionEvents.
    Filters can be configured to allow/block based on:
    - Address (from, to, contract)
    - Value thresholds
    - Transaction type
    - Custom patterns in tx data
    """

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self._address_whitelist: set[str] = set()
        self._address_blacklist: set[str] = set()
        self._min_value: dict[str, float] = {}
        self._max_value: dict[str, float] = {}
        self._event_type_filters: list[str] = []
        self._custom_patterns: list[re.Pattern] = []

    def configure_from_config(self, chain_config: dict) -> None:
        """Load filter settings from a chain configuration dict."""
        filters = chain_config.get("filters", {})

        min_val = filters.get("min_value_eth") or filters.get("min_value_btc")
        if min_val is not None:
            self._min_value[chain_config.get("name", "unknown")] = float(min_val)

        max_val = filters.get("max_value_eth") or filters.get("max_value_btc")
        if max_val is not None:
            self._max_value[chain_config.get("name", "unknown")] = float(max_val)

        for addr in filters.get("tracked_addresses", []):
            self._address_whitelist.add(addr.lower())

    def add_address_whitelist(self, addresses: list[str]) -> None:
        """Add addresses to the whitelist (only these will pass)."""
        for addr in addresses:
            self._address_whitelist.add(addr.lower())

    def add_address_blacklist(self, addresses: list[str]) -> None:
        """Add addresses to the blacklist (these will be blocked)."""
        for addr in addresses:
            self._address_blacklist.add(addr.lower())

    def add_custom_pattern(self, pattern: str) -> None:
        """Add a regex pattern to match against transaction data."""
        self._custom_patterns.append(re.compile(pattern, re.IGNORECASE))

    def passes(self, event: TransactionEvent) -> FilterResult:
        """Check if a transaction event passes all filters."""
        # Always pass block events (they're informational)
        if event.event_type in ("block",):
            return FilterResult(passed=True)

        # Check address blacklist
        if self._address_blacklist:
            event_addrs = {
                addr.lower()
                for addr in [event.from_address, event.to_address]
                if addr
            }
            if event_addrs & self._address_blacklist:
                return FilterResult(
                    passed=False,
                    reason="Address in blacklist",
                )

        # Check address whitelist (if non-empty, only whitelisted addresses pass)
        if self._address_whitelist:
            event_addrs = {
                addr.lower()
                for addr in [event.from_address, event.to_address]
                if addr
            }
            if not (event_addrs & self._address_whitelist):
                return FilterResult(
                    passed=False,
                    reason="Address not in whitelist",
                )

        # Check min value
        if event.value is not None and event.value_currency:
            lower_key = f"{event.chain}_{event.value_currency}".lower()
            min_val = self._min_value.get(lower_key) or self._min_value.get(
                event.chain
            )
            if min_val is not None and event.value < min_val:
                return FilterResult(
                    passed=False,
                    reason=f"Value {event.value} below minimum {min_val}",
                )

            max_val = self._max_value.get(lower_key) or self._max_value.get(
                event.chain
            )
            if max_val is not None and event.value > max_val:
                return FilterResult(
                    passed=False,
                    reason=f"Value {event.value} above maximum {max_val}",
                )

        # Check custom patterns
        if self._custom_patterns:
            event_str = str(event)
            for pattern in self._custom_patterns:
                if pattern.search(event_str):
                    return FilterResult(passed=True)  # Pattern matched → passes

            # If custom patterns exist and none matched → don't pass
            return FilterResult(
                passed=False,
                reason="No custom pattern matched",
            )

        return FilterResult(passed=True)

    def reset(self) -> None:
        """Reset all filters."""
        self._address_whitelist.clear()
        self._address_blacklist.clear()
        self._min_value.clear()
        self._max_value.clear()
        self._custom_patterns.clear()
