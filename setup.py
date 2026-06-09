"""Setup script for blockchain-scanner.

pyproject.toml handles metadata, dependencies, and entry points.
This file lists the root-level Python modules that pyproject.toml's
package discovery doesn't cover (only finds packages/directories).
"""
from setuptools import setup

setup(
    py_modules=[
        "main",
        "guardian",
        "exploit_pipeline",
        "pool_scanner",
        "verify",
        "hardhat_fork_tester",
        "scan_bsc_recent",
        "scan_bsc_500",
        "scan_historical",
        "stats_patterns",
        "dump_results",
        "dynamic_test_generator",
    ],
)
