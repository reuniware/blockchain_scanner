"""Rich terminal display manager for the blockchain scanner."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Optional

from scanner.base import TransactionEvent

logger = logging.getLogger("scanner.display")

# Try to import Rich
try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.text import Text
    from rich.panel import Panel
    from rich.layout import Layout
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    Console = None  # type: ignore
    Live = None  # type: ignore


class DisplayManager:
    """Manages output display — Rich terminal UI or JSON export."""

    def __init__(self, format: str = "rich", json_path: Optional[str] = None):
        self.format = format
        self.json_path = json_path
        self.json_file: Optional[Any] = None

        # Rich console
        self.console: Optional[Any] = None
        self.live: Optional[Any] = None
        self._recent_events: list[TransactionEvent] = []
        self._max_recent = 10
        self._scanner_status: dict[str, dict] = {}

        if HAS_RICH:
            self.console = Console()

    def show_header(self, scanners: list) -> None:
        """Display the initial header with scanner status."""
        if not self.console or self.format != "rich":
            return

        self.console.clear()
        grid = Table.grid(expand=True)
        grid.add_column(justify="center")
        grid.add_row(
            Panel(
                "[bold cyan][ Multi-Chain Blockchain Scanner ][/]\n"
                "[dim]Real-time transaction monitoring[/]",
                box=box.ROUNDED,
            )
        )
        self.console.print(grid)

        # Show chain status
        status_table = Table(
            title="[bold]Chain Status[/]",
            box=box.SIMPLE,
            show_header=True,
            header_style="bold cyan",
        )
        status_table.add_column("Chain", style="cyan")
        status_table.add_column("Status", style="bold")
        status_table.add_column("Currency", style="yellow")
        status_table.add_column("Mode", style="dim")

        for scanner in scanners:
            status = "[ON] Enabled" if scanner._running else "[OFF] Disabled"
            currency = getattr(scanner, "currency", "?")
            mode = []
            if getattr(scanner, "track_mempool", False):
                mode.append("Mempool")
            if getattr(scanner, "track_blocks", False):
                mode.append("Blocks")
            status_table.add_row(
                scanner.name,
                status,
                currency,
                " + ".join(mode) or "-",
            )

        self.console.print(status_table)
        self.console.print(
            "[dim]Waiting for transactions... (Ctrl+C to stop)[/]\n"
        )

    def show_status(self, stats: dict[str, Any]) -> None:
        """Update the status bar with scanner statistics."""
        self._scanner_status = stats

        if not self.console or self.format != "rich":
            return

        # Simple status line update using Rich markup
        status_parts = []
        for chain_key, stat in stats.items():
            name = stat.get("name", chain_key)
            status_colors = {
                "connected": "green",
                "connecting": "yellow",
                "reconnecting": "yellow",
                "disconnected": "red",
            }
            status_icons = {
                "connected": "[ON]",
                "connecting": "[..]",
                "reconnecting": "[..]",
                "disconnected": "[OFF]",
            }
            cur_status = stat.get("status", "disconnected")
            icon = status_icons.get(cur_status, "[?]")
            color = status_colors.get(cur_status, "red")
            txs = stat.get("txs_matched", 0)
            status_parts.append(
                f"[{color}]{icon} {name}[/] ({txs} txs)"
            )

        if status_parts:
            self.console.print(
                "  ".join(status_parts), highlight=False, end="\r"
            )

    async def show_event(self, event: TransactionEvent) -> None:
        """Display a transaction event."""
        self._recent_events.append(event)
        if len(self._recent_events) > self._max_recent:
            self._recent_events.pop(0)

        if self.format == "json":
            await self._write_json(event)

        if self.format in ("rich", "both") and self.console:
            self._display_rich(event)

    def _display_rich(self, event: TransactionEvent) -> None:
        """Display a single event in Rich format."""
        # Choose icon based on event type (ASCII-safe for Windows cp1252)
        icons = {
            "transaction": "[TX]",
            "mempool": "[MP]",
            "block": "[BLK]",
            "transfer": "[XFR]",
            "account_update": "[ACC]",
        }
        icon = icons.get(event.event_type, "[TX]")

        # Color based on chain
        chain_colors = {
            "Ethereum": "blue",
            "Polygon": "magenta",
            "Binance Smart Chain": "yellow",
            "Arbitrum": "cyan",
            "Solana": "cyan",
            "Bitcoin": "orange3",
        }
        chain_color = chain_colors.get(event.chain, "white")

        # Format value
        value_str = ""
        if event.value is not None and event.value_currency:
            value_str = f"[bold green]{event.value} {event.value_currency}[/]"

        # Format gas/fee
        extra = ""
        if event.gas_price:
            gwei = event.gas_price / 1e9
            extra += f" [dim]Gas: {gwei:.1f} Gwei[/]"
        if event.fee:
            extra += f" [dim]Fee: {event.fee} BTC[/]"

        # Format addresses (truncate long hex addresses)
        from_addr = event.from_address
        to_addr = event.to_address
        if from_addr and len(from_addr) > 12:
            from_addr = f"{from_addr[:6]}..{from_addr[-4:]}"
        if to_addr and len(to_addr) > 12:
            to_addr = f"{to_addr[:6]}..{to_addr[-4:]}"

        # Block events are special
        if event.event_type == "block":
            text = Text.assemble(
                (f" {icon} ", "bold"),
                (f"[{event.chain}] ", chain_color),
                ("New Block", "bold white"),
                (f"  #{event.block_number}", "cyan"),
                (f"  {event.data.get('tx_count', '?')} txs", "dim"),
            )

            # Use a separator line
            self.console.print("-" * 60, style="dim")
            self.console.print(text)
            return

        # Regular transaction
        tx_hash_short = event.tx_hash[:12] + "..." if len(event.tx_hash) > 12 else event.tx_hash

        self.console.print("-" * 60, style="dim")

        # Chain + Type line
        self.console.print(
            f"[bold {chain_color}] {icon} {event.chain}[/] "
            f"[dim]{event.event_type.upper()}[/] "
            f"[dim]{tx_hash_short}[/]"
        )

        # From → To line
        if from_addr or to_addr:
            self.console.print(
                f"   [bold]From:[/] {from_addr or '?'}  "
                f"[bold]->  To:[/] {to_addr or '?'}"
            )

        # Value line
        if value_str:
            extra_parts = []
            if event.data and event.data.get("fee_rate_sat_vb"):
                extra_parts.append(
                    f"Rate: {event.data['fee_rate_sat_vb']} sat/vB"
                )
            extra_str = f"  [dim]({', '.join(extra_parts)})[/]" if extra_parts else ""
            self.console.print(f"   {value_str}{extra_str}")

        # Extra data
        if extra:
            self.console.print(f"   {extra}")

        # Contract address involved (for EVM transfers/transactions)
        if event.contract_address:
            c_addr = event.contract_address
            c_short = f"{c_addr[:10]}..{c_addr[-4:]}" if len(c_addr) > 14 else c_addr
            if event.contract_verified is True:
                verification = " [bold green](VERIFIED)[/]"
            elif event.contract_verified is False:
                verification = " [bold red](NOT VERIFIED)[/]"
            else:
                verification = " [dim](checking..)[/]"
            self.console.print(
                f"   [bold]Contract:[/] {c_short}{verification}"
            )

        # Block number
        if event.block_number:
            self.console.print(
                f"   [dim]Block: #{event.block_number}[/]"
            )

    async def show_verification(self, event: TransactionEvent) -> None:
        """Re-display an event with updated verification info."""
        if self.format in ("rich", "both") and self.console:
            c_addr = event.contract_address or ""
            c_short = f"{c_addr[:10]}..{c_addr[-4:]}" if len(c_addr) > 14 else c_addr
            if event.contract_verified is True:
                status = "[bold green]VERIFIED[/]"
            elif event.contract_verified is False:
                status = "[bold red]NOT VERIFIED[/]"
            else:
                status = "[dim]unknown[/]"
            self.console.print(
                f"   [dim]> Contract {c_short}: source {status}[/]"
            )

    async def _write_json(self, event: TransactionEvent) -> None:
        """Write event to JSON file."""
        try:
            if not self.json_file and self.json_path:
                self.json_file = open(self.json_path, "a")

            event_dict = {
                "chain": event.chain,
                "type": event.event_type,
                "tx_hash": event.tx_hash,
                "block_number": event.block_number,
                "timestamp": event.timestamp.isoformat(),
                "from": event.from_address,
                "to": event.to_address,
                "value": event.value,
                "currency": event.value_currency,
                "status": event.status,
                "data": event.data,
            }

            if self.json_file:
                self.json_file.write(json.dumps(event_dict) + "\n")
                self.json_file.flush()
        except Exception as e:
            logger.error(f"Error writing JSON: {e}")

    def close(self) -> None:
        """Clean up resources."""
        if self.json_file:
            self.json_file.close()
            self.json_file = None
