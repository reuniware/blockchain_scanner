#!/usr/bin/env python3
"""
Multi-Chain Blockchain Transaction Scanner
===========================================
Real-time monitoring of transactions across multiple blockchains
(Ethereum, Polygon, BSC, Arbitrum, Bitcoin, Solana).

Usage:
    python main.py                          # Use default config.yaml
    python main.py --config my-config.yaml  # Custom config
    python main.py --json output.json       # Export to JSON
    python main.py --chains ethereum,bitcoin # Only specific chains
    python main.py --version                # Show version
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
from typing import Any

import yaml

from scanner.orchestrator import ScannerOrchestrator

VERSION = "1.0.0"


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="[Multi-Chain Blockchain Transaction Scanner]",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py
  python main.py -c my-config.yaml
  python main.py --chains ethereum,bitcoin
  python main.py -j output.json --format both
        """,
    )

    parser.add_argument(
        "-c",
        "--config",
        default="config.yaml",
        help="Path to YAML configuration file (default: config.yaml)",
    )
    parser.add_argument(
        "-j",
        "--json",
        default=None,
        metavar="FILE",
        help="Export transactions to JSON file",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["rich", "json", "both"],
        default=None,
        help="Output format (default: from config)",
    )
    parser.add_argument(
        "--chains",
        default=None,
        help="Comma-separated list of chains to enable (e.g., ethereum,bitcoin)",
    )
    parser.add_argument(
        "--list-chains",
        action="store_true",
        help="List available chains from config and exit",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable DEBUG logging",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show version and exit",
    )

    args = parser.parse_args()
    return args


def setup_logging(verbose: bool = False) -> None:
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def load_config(path: str) -> dict[str, Any]:
    """Load YAML configuration file."""
    if not os.path.exists(path):
        print(f"[ERROR] Configuration file not found: {path}")
        print(f"  Create one or use the default config.yaml template.")
        sys.exit(1)

    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    if not config:
        print("[ERROR] Empty configuration file")
        sys.exit(1)

    return config


def list_chains(config: dict) -> None:
    """List available chains from config."""
    chains = config.get("chains", {})
    print(f"\n== Available chains ({len(chains)} configured) ==")
    print("=" * 50)

    for key, chain_cfg in chains.items():
        name = chain_cfg.get("name", key.capitalize())
        enabled = "[ON]" if chain_cfg.get("enabled", False) else "[OFF]"
        currency = chain_cfg.get("currency", "?")
        rpc = chain_cfg.get("rpc_ws", "") or chain_cfg.get("ws_url", "")
        rpc_short = rpc[:40] + "..." if len(rpc) > 40 else rpc
        print(f"\n  {enabled} {name} ({key})")
        print(f"     Currency: {currency}")
        print(f"     RPC:      {rpc_short or 'N/A'}")

    print()
    sys.exit(0)


def apply_cli_overrides(
    config: dict[str, Any], args: argparse.Namespace
) -> dict[str, Any]:
    """Apply CLI arguments as overrides to config."""
    # Chain selection
    if args.chains:
        selected = set(c.strip().lower() for c in args.chains.split(","))
        for chain_key in config.get("chains", {}):
            config["chains"][chain_key]["enabled"] = chain_key in selected

    # Output format
    if args.format:
        if "global" not in config:
            config["global"] = {}
        config["global"]["output_format"] = args.format

    # JSON output path
    if args.json:
        if "global" not in config:
            config["global"] = {}
        config["global"]["json_output_file"] = args.json

    return config


def validate_config(config: dict) -> bool:
    """Basic config validation."""
    if "chains" not in config:
        print("[ERROR] Config must have a 'chains' section")
        return False

    has_enabled = False
    for key, chain_cfg in config["chains"].items():
        if chain_cfg.get("enabled", False):
            has_enabled = True
            # Check for RPC endpoint
            rpc = chain_cfg.get("rpc_ws") or chain_cfg.get("ws_url") or ""
            if "VOTRE_CLE" in rpc or "YOUR_KEY" in rpc:
                print(f"[WARN] {chain_cfg.get('name', key)}: RPC endpoint has placeholder key!")
                print(f"  Edit config.yaml to add your API key.\n")

    if not has_enabled:
        print("[WARN] No chains are enabled in the configuration.")
        print("  Edit config.yaml and set enabled: true for the chains you want.\n")

    return True


async def main_async(args: argparse.Namespace) -> None:
    """Async main entry point."""
    # Load configuration
    config = load_config(args.config)
    config = apply_cli_overrides(config, args)

    # Validate
    validate_config(config)

    # Setup global config
    global_cfg = config.get("global", {})
    json_file = global_cfg.get("json_output_file")

    # Update format if JSON export requested
    if json_file:
        current_format = global_cfg.get("output_format", "rich")
        if current_format == "rich":
            global_cfg["output_format"] = "both"

    # Create orchestrator
    orchestrator = ScannerOrchestrator(config)

    # Handle graceful shutdown (cross-platform: Windows + Unix)
    stop_event = asyncio.Event()

    def shutdown():
        print("\n\n[!] Shutting down...")
        stop_event.set()

    # Set up signal handlers (Unix only; Windows falls back to KeyboardInterrupt)
    try:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, shutdown)
    except (NotImplementedError, AttributeError):
        # Windows or restricted environments — use polling loop instead
        pass

    try:
        # Start scanning
        await orchestrator.start()

        # Wait for shutdown — poll in a loop so KeyboardInterrupt can fire
        while not stop_event.is_set():
            try:
                await asyncio.wait_for(
                    asyncio.shield(stop_event.wait()), timeout=0.5
                )
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user...")
    finally:
        await orchestrator.stop()
        print("\n[DONE] Scanner stopped. Goodbye!")


def main() -> None:
    """Entry point."""
    args = parse_args()

    if args.version:
        print(f"Blockchain Scanner v{VERSION}")
        sys.exit(0)

    setup_logging(verbose=args.verbose)

    if args.list_chains:
        config = load_config(args.config)
        list_chains(config)

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
