#!/usr/bin/env python3
"""Test AIDoge vulnerabilities directly via eth_call (no fork needed)."""
import asyncio
import httpx

TARGET = "0x09e18590e8f76b6cf471b3cd75fe1a1a9d2b2c2b"
RPC = "https://arb1.arbitrum.io/rpc"

# Common function selectors
SELECTORS = {
    "owner()": "0x8da5cb5b",
    "initialize(address)": "0xcf756fdf",  # keccak("initialize(address)")[:4]
    "initialize()": "0x8129fc1c",
    "withdraw(uint256)": "0x2e1a7d4d",
    "withdrawAll()": "0x853828b6",
    "delegatecallToTarget(bytes)": "0x8b3f8088",
    "transferOwnership(address)": "0xf2fde38b",
    "renounceOwnership()": "0x715018a6",
    "balanceOf(address)": "0x70a08231",
    "totalSupply()": "0x18160ddd",
}


# Selecteurs derives de keccak256("signature")[:4]:
# initialize(address)     -> 0xcf756fdf
# initialize()            -> 0x8129fc1c
# withdraw(uint256)       -> 0x2e1a7d4d
# withdrawAll()           -> 0x853828b6
# delegatecallToTarget(bytes) -> 0x8b3f8088
# owner()                 -> 0x8da5cb5b


async def test_function(c: httpx.AsyncClient, name: str, sel: str,
                        params: str = "", sender: str = "") -> dict:
    """Test if a function is callable (doesn't revert)."""
    data = sel + params
    payload = {
        "jsonrpc": "2.0", "method": "eth_call", "id": 1,
        "params": [{"to": TARGET, "data": data, "from": sender or "0x0000000000000000000000000000000000000001"}, "latest"]
    }
    try:
        r = await c.post(RPC, json=payload, timeout=15)
        result = r.json().get("result", "")
        error = r.json().get("error", {})

        if error:
            return {"name": name, "status": "REVERT", "error": str(error.get("message", ""))[:80]}
        elif result and result != "0x" and result[:2] == "0x":
            # Success - decode if it's a short result (address)
            if len(result) == 66:  # 32 bytes
                val = int(result, 16)
                return {"name": name, "status": "OK", "result": str(val)}
            return {"name": name, "status": "OK", "result": result[:42]}
        else:
            return {"name": name, "status": "OK", "result": f"empty ({result})"}
    except Exception as e:
        return {"name": name, "status": "ERROR", "error": str(e)[:60]}


async def main():
    async with httpx.AsyncClient(timeout=20) as c:
        print(f"=== AIDOGE ({TARGET[:14]}..) DIRECT RPC TEST ===")
        print(f"RPC: {RPC}\n")

        # 1. Check contract existence
        r = await c.post(RPC, json={
            "jsonrpc": "2.0", "method": "eth_getCode", "id": 1,
            "params": [TARGET, "latest"]
        })
        code = r.json().get("result", "0x")
        print(f"Code length: {max(0, len(code)-2)//2} bytes (0=EOA)")
        if len(code) <= 2:
            print("NOT A CONTRACT! Aborting.")
            return

        # 2. Get balance
        r = await c.post(RPC, json={
            "jsonrpc": "2.0", "method": "eth_getBalance", "id": 1,
            "params": [TARGET, "latest"]
        })
        bal = int(r.json().get("result", "0"), 16) / 1e18
        print(f"Balance: {bal:.4f} ETH\n")

        # 3. Test functions from different senders
        print("--- Testing with EOA (random sender) ---")
        sender_eoa = "0x1234567890123456789012345678901234567890"
        tests = [
            ("owner()", SELECTORS["owner()"]),
            ("initialize(address)", "0xcf756fdf0000000000000000000000001234567890123456789012345678901234567890"),
            ("initialize()", SELECTORS["initialize()"]),
            ("withdraw(uint256=1e17)", "0x2e1a7d4d000000000000000000000000000000000000000000000000016345785d8a0000"),
            ("withdrawAll()", SELECTORS["withdrawAll()"]),
            ("delegatecallToTarget(b'')", "0x8b3f808800000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000"),
            ("totalSupply()", SELECTORS["totalSupply()"]),
            ("balanceOf(signer)", "0x70a082310000000000000000000000001234567890123456789012345678901234567890"),
        ]
        for name, data in tests:
            result = await test_function(c, name, data, sender=sender_eoa)
            icon = {"OK": "  OK", "REVERT": "REVERT", "ERROR": "ERROR"}.get(result["status"], "?")
            detail = result.get("result", "") or result.get("error", "")
            print(f"  [{icon}] {name:40s} | {result['status']:8s} | {detail[:60]}")

        # 4. Test key functions from different sender types
        print("\n--- Access control check: initialize(address) ---")
        for sender_label, sender_addr in [
            ("Zero address", "0x0000000000000000000000000000000000000000"),
            ("Random EOA", "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            ("Contract address", "0x1111111111111111111111111111111111111111"),
        ]:
            result = await test_function(c, f"init from {sender_label}",
                "0xcf756fdf0000000000000000000000001234567890123456789012345678901234567890",
                sender=sender_addr)
            icon = {"OK": "  OK", "REVERT": "REVERT"}.get(result["status"], "?")
            print(f"  [{icon}] {sender_label:20s} -> {result['status']}")

        # 5. Check if delegatecallToTarget exists and is callable
        print("\n--- Access control check: delegatecallToTarget ---")
        result = await test_function(c, "delegatecallToTarget",
            "0x8b3f808800000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000",
            sender=sender_eoa)
        icon = {"OK": "  OK", "REVERT": "REVERT"}.get(result["status"], "?")
        print(f"  [{icon}] delegatecallToTarget from EOA -> {result['status']}: {result.get('result','') or result.get('error','')[:80]}")

        print("\n=== DONE ===")


if __name__ == "__main__":
    asyncio.run(main())
