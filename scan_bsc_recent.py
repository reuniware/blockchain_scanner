"""Scan recent BSC blocks for new contract deployments."""
import asyncio
import httpx
import json

BSC_RPC = "https://bsc-dataseed1.binance.org"
ETHERSCAN_V2 = "https://api.etherscan.io/v2/api"
API_KEY = "47JTF3MC7RJ24NSZGTIXNT84KFBQDHWY8E"

async def check_verified(address: str, chain_id: int) -> tuple:
    """Check if contract is verified. Returns (name, is_verified)."""
    async with httpx.AsyncClient(timeout=15) as c:
        params = {
            "chainid": str(chain_id),
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": API_KEY,
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
        except Exception as e:
            return ("", False, 0)
    return ("", False, 0)


async def scan_bsc():
    async with httpx.AsyncClient(timeout=30) as client:
        # Get latest block
        payload = {"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1}
        resp = await client.post(BSC_RPC, json=payload)
        latest = int(resp.json()["result"], 16)
        print(f"BSC Latest Block: #{latest}")
        print(f"Scanning 100 blocks: #{latest-100} to #{latest}")
        print("=" * 80)

        all_contracts = []
        verified_found = 0

        for block_num in range(latest, max(latest - 100, 0), -1):
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_getBlockByNumber",
                "params": [hex(block_num), True],
                "id": 1,
            }
            resp = await client.post(BSC_RPC, json=payload)
            data = resp.json()
            if "result" not in data or data["result"] is None:
                continue

            block = data["result"]
            txs = block.get("transactions", [])

            for tx in txs:
                # Contract creation: to is None/0x and has contractAddress in receipt
                if tx.get("to") is None or tx.get("to", "").lower() == "0x":
                    # We don't have receipt, but to=null means contract creation
                    # Let's get receipt to find contract address
                    receipt_payload = {
                        "jsonrpc": "2.0",
                        "method": "eth_getTransactionReceipt",
                        "params": [tx["hash"]],
                        "id": 1,
                    }
                    try:
                        receipt_resp = await client.post(BSC_RPC, json=receipt_payload)
                        receipt_data = receipt_resp.json()
                        if "result" in receipt_data and receipt_data["result"]:
                            receipt = receipt_data["result"]
                            contract_addr = receipt.get("contractAddress")
                            if contract_addr and contract_addr != "0x":
                                all_contracts.append({
                                    "address": contract_addr,
                                    "block": block_num,
                                    "tx_hash": tx["hash"],
                                    "from": tx.get("from", "?"),
                                })
                                print(f"[{block_num}] New contract: {contract_addr}")
                                print(f"  From: {tx.get('from', '?')[:42]}")
                                print(f"  Tx: {tx['hash'][:42]}")
                    except Exception:
                        pass

            if block_num % 20 == 0:
                print(f"  Progress: scanned {latest - block_num}/{100} blocks...")

        print(f"\n{'=' * 80}")
        print(f"Total contracts found: {len(all_contracts)}")

        # Now check verification for each
        if all_contracts:
            print(f"\nChecking verification status...")
            for c in all_contracts:
                name, verified, src_len = await check_verified(c["address"], 56)
                c["name"] = name
                c["verified"] = verified
                c["src_len"] = src_len
                status = "VERIFIED" if verified else "NOT VERIFIED"
                name_str = f" ({name})" if name else ""
                print(f"  {c['address']}{name_str} -> {status} ({src_len} chars)")

            # Show summary
            total = len(all_contracts)
            verified_count = sum(1 for c in all_contracts if c["verified"])
            print(f"\nSummary:")
            print(f"  Total contracts: {total}")
            print(f"  Verified: {verified_count}")
            print(f"  Unverified: {total - verified_count}")

            # Print verified contracts for pipeline
            print(f"\nVerified contracts (ready for exploit_pipeline.py):")
            for c in all_contracts:
                if c["verified"]:
                    print(f"  python exploit_pipeline.py --address {c['address']} --chain bsc")
        else:
            print("No contract deployments found in the last 100 blocks.")

if __name__ == "__main__":
    asyncio.run(scan_bsc())
