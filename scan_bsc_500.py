"""Scan 500 recent BSC blocks for verified contracts and run exploit pipeline."""
import asyncio
import httpx
import subprocess
import sys

BSC_RPC = "https://bsc-dataseed1.binance.org"
ETHERSCAN_V2 = "https://api.etherscan.io/v2/api"
API_KEY = "47JTF3MC7RJ24NSZGTIXNT84KFBQDHWY8E"

# Prevent console windows from popping up on Windows during subprocess calls
_CREATION_FLAGS = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

def _s(text: str) -> str:
    """ASCII-safe output for Windows cp1252."""
    return text.encode('ascii', errors='replace').decode('ascii')

async def check_verified(address: str) -> tuple:
    async with httpx.AsyncClient(timeout=15) as c:
        params = {
            "chainid": "56", "module": "contract",
            "action": "getsourcecode", "address": address, "apikey": API_KEY,
        }
        try:
            resp = await c.get(ETHERSCAN_V2, params=params)
            data = resp.json()
            if data.get("status") == "1" and data.get("result"):
                result = data["result"][0]
                name = result.get("ContractName", "")
                src = result.get("SourceCode", "")
                is_verified = bool(name and src and src != "0x")
                return (name, is_verified, len(src) if src else 0)
        except Exception:
            pass
    return ("", False, 0)


async def main():
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(BSC_RPC, json={
            "jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1
        })
        latest = int(resp.json()["result"], 16)
        print(f"BSC Latest Block: #{latest}")
        print(f"Scanning 500 blocks: #{latest-500} to #{latest}")

        all_contracts = []
        for block_num in range(latest, max(latest - 500, 0), -1):
            resp = await client.post(BSC_RPC, json={
                "jsonrpc": "2.0", "method": "eth_getBlockByNumber",
                "params": [hex(block_num), True], "id": 1
            })
            data = resp.json()
            if "result" not in data or data["result"] is None:
                continue
            for tx in data["result"].get("transactions", []):
                if tx.get("to") is None or tx.get("to", "").lower() == "0x":
                    try:
                        r_resp = await client.post(BSC_RPC, json={
                            "jsonrpc": "2.0", "method": "eth_getTransactionReceipt",
                            "params": [tx["hash"]], "id": 1
                        })
                        r_data = r_resp.json()
                        if "result" in r_data and r_data["result"]:
                            addr = r_data["result"].get("contractAddress")
                            if addr and addr != "0x":
                                all_contracts.append({
                                    "address": addr, "block": block_num,
                                })
                    except Exception:
                        pass
            if block_num % 100 == 0:
                print(f"  Progress: {latest - block_num}/500 blocks...")

        print(f"\nTotal contracts: {len(all_contracts)}")

        # Check verification
        verified_list = []
        for i, c in enumerate(all_contracts):
            name, verified, src_len = await check_verified(c["address"])
            c["name"], c["verified"], c["src_len"] = name, verified, src_len
            status = "[OK]" if verified else "[NO]"
            n = f" ({name})" if name else ""
            print(f"  {i+1}/{len(all_contracts)} {status} {c['address']}{n} ({src_len}c)")
            if verified:
                verified_list.append(c)

        print(f"\n=== SUMMARY ===")
        print(f"Total: {len(all_contracts)} | Verified: {len(verified_list)} | Unverified: {len(all_contracts)-len(verified_list)}")

        if verified_list:
            print(f"\n=== RUNNING EXPLOIT PIPELINE ON VERIFIED CONTRACTS ===")
            for c in verified_list:
                print(f"\n--- {c['name']} ({c['address']}) ---")
                try:
                    result = subprocess.run(
                        [sys.executable, "exploit_pipeline.py", "--address", c['address'], "--chain", "bsc"],
                        capture_output=True, text=True, timeout=60,
                        creationflags=_CREATION_FLAGS,
                    )
                    print(_s(result.stdout))
                except subprocess.TimeoutExpired:
                    print("TIMEOUT")
                except Exception as e:
                    print(f"ERROR: {e}")
        else:
            print("\nNo verified contracts found.")

if __name__ == "__main__":
    asyncio.run(main())
