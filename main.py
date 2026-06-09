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
import json
import logging
import os
import signal
import subprocess
import sys
import tempfile
from typing import Any

import yaml

from scanner.orchestrator import ScannerOrchestrator

VERSION = "1.0.2"

# Prevent console windows from popping up on Windows during subprocess calls
_CREATION_FLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0


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
    parser.add_argument(
        "--stop-on",
        default="detected",
        choices=["detected", "confirmed", "none"],
        help="Auto-stop mode: 'detected' (stop on first HIGH/CRITICAL finding), "
             "'confirmed' (stop only after pipeline confirms exploit), "
             "'none' (never auto-stop, manual only)",
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

    # Create orchestrator with the configured stop mode
    orchestrator = ScannerOrchestrator(config, stop_on=args.stop_on)

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
        pass

    chain_names = {1: "ethereum", 56: "bsc", 137: "polygon",
                   10: "optimism", 42161: "arbitrum",
                   43114: "avalanche", 8453: "base", 250: "fantom"}

    async def _run_pipeline(addr: str, chain_id: int, source_code: Optional[str]) -> str:
        """Launch exploit pipeline subprocess and return stdout."""
        api_key = global_cfg.get("explorer_api_key", "")
        chain_name = chain_names.get(chain_id, "ethereum")

        # Write cached source to temp file to avoid a second Etherscan API call
        cached_source_path = None
        if source_code:
            try:
                tmp = tempfile.NamedTemporaryFile(
                    mode="w", suffix=".sol", delete=False, encoding="utf-8"
                )
                tmp.write(source_code)
                cached_source_path = tmp.name
                tmp.close()
            except Exception as e:
                print(f"    [WARN] Could not write cached source: {e}")

        script_dir = os.path.dirname(os.path.abspath(__file__))
        pipeline_script = os.path.join(script_dir, "exploit_pipeline.py")
        cmd = [
            sys.executable, pipeline_script,
            "--address", addr,
            "--chain", chain_name,
            "--api-key", api_key,
        ]
        if cached_source_path:
            cmd.extend(["--cached-source", cached_source_path])

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            creationflags=_CREATION_FLAGS,
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode("utf-8", errors="replace")

        # Clean up temp file
        if cached_source_path:
            try:
                os.unlink(cached_source_path)
            except Exception:
                pass

        return output

    async def _parse_pipeline_result(output: str) -> bool:
        """Parse pipeline JSON output to check if exploit was confirmed."""
        # Look for the JSON report block
        try:
            # Find JSON between markers
            lines = output.split("\n")
            in_json = False
            json_lines = []
            for line in lines:
                if line.strip() == "[JSON REPORT]":
                    in_json = True
                    continue
                if in_json:
                    json_lines.append(line)
            if json_lines:
                report = json.loads("\n".join(json_lines))
                exploitable = report.get("exploitable", 0)
                return exploitable > 0
        except Exception:
            pass
        # Fallback: check for keywords in output
        has_exploitable = "[RED] EXPLOITABLE" in output or "[RED] THEORETICALLY EXPLOITABLE" in output
        has_not_exploitable = "NOT exploitable" in output or "Non exploitable" in output
        if has_exploitable and not has_not_exploitable:
            return True
        return False

    try:
        # Start scanning
        await orchestrator.start()

        if args.stop_on == "detected":
            # Mode detected: stop immediately on first HIGH/CRITICAL (current behavior)
            stop_task = asyncio.create_task(stop_event.wait())
            vuln_task = asyncio.create_task(orchestrator.vulnerability_found_event.wait())
            done, pending = await asyncio.wait(
                [stop_task, vuln_task],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()

            if orchestrator.vulnerability_found_event.is_set():
                vuln = orchestrator.found_vulnerability
                addr = orchestrator.last_vuln_address
                chain_id = orchestrator.last_vuln_chain_id
                chain_name = chain_names.get(chain_id, "ethereum")
                print(f"\n{'=' * 60}")
                print(f"  [!] VULNERABILITE DETECTEE — Arret automatique")
                print(f"  [!] {vuln.name} [{vuln.severity}]")
                print(f"  [!] Contrat: {addr}")
                print(f"  [!] Chaine: {chain_name}")
                print(f"{'=' * 60}")

                # Stop the orchestrator first to free WebSocket/HTTP resources
                await orchestrator.stop()

                # Then launch exploit pipeline to validate the finding
                if addr:
                    print(f"\n[!] Lancement du pipeline d'exploitation sur {addr[:14]}..")
                    output = await _run_pipeline(addr, chain_id, orchestrator.last_source_code)
                    print(output)

                return

        elif args.stop_on == "confirmed":
            # Mode confirmed: keep scanning, validate via pipeline before stopping
            print("\n  [!] Mode confirme: les scanners continuent pendant la validation pipeline")
            while True:
                stop_task = asyncio.create_task(stop_event.wait())
                vuln_task = asyncio.create_task(orchestrator.pending_vuln_event.wait())
                done, pending = await asyncio.wait(
                    [stop_task, vuln_task],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in pending:
                    task.cancel()

                if stop_event.is_set():
                    break

                # A vulnerability is pending pipeline validation
                # Clear the event immediately so new vulns can queue up
                orchestrator.pending_vuln_event.clear()

                pending_vuln = orchestrator.next_pending_vuln
                if not pending_vuln:
                    continue

                vuln = pending_vuln["finding"]
                addr = pending_vuln["address"]
                chain_id = pending_vuln["chain_id"]
                chain_name = chain_names.get(chain_id, "ethereum")
                source_code = pending_vuln["source_code"]

                print(f"\n{'=' * 60}")
                print(f"  [!] VULNERABILITE DETECTEE — Validation en cours")
                print(f"  [!] {vuln.name} [{vuln.severity}]")
                print(f"  [!] Contrat: {addr}")
                print(f"  [!] Chaine: {chain_name}")
                print(f"  [!] Les scanners continuent de tourner...")
                print(f"{'=' * 60}")

                # Launch pipeline WITHOUT stopping scanners
                print(f"\n[!] Pipeline d'exploitation sur {addr[:14]}.. (scanners actifs)")
                output = await _run_pipeline(addr, chain_id, source_code)
                print(output)

                # Parse result
                confirmed = await _parse_pipeline_result(output)
                orchestrator.confirm_vulnerability(addr, chain_id, confirmed)

                if confirmed:
                    print(f"\n{'=' * 60}")
                    print(f"  [!] EXPLOIT CONFIRME — Arret automatique")
                    print(f"{'=' * 60}")
                    await orchestrator.stop()
                    return
                else:
                    print(f"\n  [!] Faux positif — reprise du scan...")
                    # Loop back to wait for next vulnerability

            # If we get here, stop_event was set (manual shutdown)
            await orchestrator.stop()

        else:  # stop_on == "none"
            # Mode none: never auto-stop, just wait for manual shutdown
            print("\n  [!] Mode sans arret: les scanners tournent jusqu'a CTRL+C")
            await stop_event.wait()
            await orchestrator.stop()

    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user...")
        await orchestrator.stop()
    finally:
        if orchestrator.found_vulnerability:
            print(f"\n[VULN] Trouvee: {orchestrator.found_vulnerability.name} [{orchestrator.found_vulnerability.severity}]")
            print(f"[VULN] Lines: {orchestrator.found_vulnerability.line_numbers}")
            print(f"[VULN] {orchestrator.found_vulnerability.description[:150]}...")
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
