"""Source code verification checker for EVM smart contracts.

Uses the Etherscan API V2 single endpoint for ALL chains.
A single API key works for Ethereum, BSC, Polygon, Arbitrum, 60+ chains.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

import httpx

logger = logging.getLogger("verify")

# ---------------------------------------------------------------------------
# Etherscan API V2: single endpoint for ALL chains (Ethereum, BSC, Polygon...)
# V1 endpoints (api.bscscan.com/api, api.etherscan.io/api) are DEPRECATED
# and return errors for V2 API keys.
# ---------------------------------------------------------------------------
EXPLORER_API_V2_URL = "https://api.etherscan.io/v2/api"

# Block explorer web URLs (for displaying clickable links in the terminal)
EXPLORER_WEB_URLS: dict[int, str] = {
    1: "https://etherscan.io",
    56: "https://bscscan.com",
    137: "https://polygonscan.com",
    42161: "https://arbiscan.io",
    10: "https://optimistic.etherscan.io",
    43114: "https://snowtrace.io",
}


class SourceCodeVerifier:
    """Checks if smart contracts have verified source code on block explorers.

    Uses the Etherscan API V2 endpoint which works for ALL chains with a single key.
    Results are cached in-memory to avoid re-checking the same address.

    API key (from https://etherscan.io/myapikey):
    - REQUIRED - V1 endpoints are deprecated, V2 requires a key
    - Free tier: 5 calls/second, 100,000 calls/day
    - A single key works for all 60+ supported chains
    """

    def __init__(self, api_key: Optional[str] = None):
        """Initialize the verifier.

        Args:
            api_key: A single Etherscan API V2 key (required for V2 endpoint).
                     Get one free at: https://etherscan.io/myapikey
        """
        self._api_key = api_key or ""
        self._cache: dict[str, Optional[bool]] = {}  # "chain:address" -> verified or None
        self._http: Optional[httpx.AsyncClient] = None
        self._last_request_time: float = 0.0
        self._rate_limit_delay: float = 0.25  # 5 calls/sec (free tier V2)

    async def _get_client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=15.0)
        return self._http

    async def _rate_limit(self) -> None:
        """Simple rate limiter to avoid exceeding the free tier limit."""
        import time
        now = time.monotonic()
        elapsed = now - self._last_request_time
        if elapsed < self._rate_limit_delay:
            await asyncio.sleep(self._rate_limit_delay - elapsed)
        self._last_request_time = time.monotonic()

    def _get_api_url(self, _chain_id: int) -> Optional[str]:
        """Return the Etherscan API V2 base URL (works for ALL chains)."""
        return EXPLORER_API_V2_URL

    def _get_web_url(self, chain_id: int) -> Optional[str]:
        """Get the block explorer web URL for display."""
        return EXPLORER_WEB_URLS.get(chain_id)

    async def is_verified(
        self, address: str, chain_id: int
    ) -> Optional[bool]:
        """Check if a contract's source code is verified on the block explorer.

        Args:
            address: The contract address (hex string).
            chain_id: The EVM chain ID (1=Ethereum, 56=BSC, 137=Polygon, etc.)

        Returns:
            True if verified, False if not verified, None if check failed.
        """
        addr_key = f"{chain_id}:{address.lower()}"

        # Check cache first
        if addr_key in self._cache:
            return self._cache[addr_key]

        # API key is required for V2 endpoint
        if not self._api_key:
            logger.warning(
                "[verify] Etherscan API V2 key required. "
                "Add 'explorer_api_key' in config.yaml "
                "(get one free at https://etherscan.io/myapikey)"
            )
            self._cache[addr_key] = None
            return None

        api_url = self._get_api_url(chain_id)

        # Build query parameters for V2 endpoint
        params = {
            "chainid": str(chain_id),
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": self._api_key,
        }

        try:
            await self._rate_limit()

            client = await self._get_client()
            resp = await client.get(api_url, params=params)
            resp.raise_for_status()
            data = resp.json()

            # Parse V2 response
            status = data.get("status", "0")
            message = data.get("message", "")
            result = data.get("result", [])

            if status == "1" and isinstance(result, list) and len(result) > 0:
                contract_data = result[0]
                source_code = contract_data.get("SourceCode", "")
                is_verified = bool(source_code and source_code.strip())
                self._cache[addr_key] = is_verified
                return is_verified
            else:
                # Log unexpected responses for debugging
                if status == "0" and message != "NOTOK":
                    logger.debug(f"[verify] Unexpected API response for {address}: {data}")
                self._cache[addr_key] = False
                return False

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                logger.warning(
                    f"[verify] API key invalid or rate-limited. "
                    "Check your Etherscan API V2 key at https://etherscan.io/myapikey"
                )
            else:
                logger.debug(f"[verify] HTTP error checking {address}: {e}")
            self._cache[addr_key] = None
            return None
        except Exception as e:
            logger.debug(f"[verify] Error checking {address}: {e}")
            self._cache[addr_key] = None
            return None

    async def get_contract_info(
        self, address: str, chain_id: int
    ) -> Optional[dict]:
        """Get full contract info (source code, ABI, compiler version, etc.)

        Only available if the contract is verified.
        """
        if not self._api_key:
            return None

        params = {
            "chainid": str(chain_id),
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": self._api_key,
        }

        try:
            await self._rate_limit()
            client = await self._get_client()
            resp = await client.get(EXPLORER_API_V2_URL, params=params)
            resp.raise_for_status()
            data = resp.json()

            if data.get("status") == "1" and data.get("result"):
                result = data["result"]
                if isinstance(result, list) and len(result) > 0:
                    return result[0]
                return result
            return None
        except Exception as e:
            logger.debug(f"[verify] Error fetching contract info: {e}")
            return None

    def get_contract_url(self, address: str, chain_id: int) -> Optional[str]:
        """Get the block explorer URL for a contract's source code page."""
        web_url = self._get_web_url(chain_id)
        if web_url:
            return f"{web_url}/address/{address}#code"
        return None

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http:
            await self._http.aclose()
            self._http = None

    def is_cached(self, address: str, chain_id: int) -> Optional[bool]:
        """Check if a contract verification result is already cached."""
        return self._cache.get(f"{chain_id}:{address.lower()}")

    def cache_size(self) -> int:
        return len(self._cache)
