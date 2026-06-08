"""Test the 5 new Mythril-derived vulnerability patterns (30-34)."""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from analysis.vulnerability_scanner import (
    analyze_contract,
    _find_arbitrary_jump,
    _find_arbitrary_storage_write,
    _find_multiple_external_calls,
    _find_transaction_order_dependence,
    _find_strict_balance_equality,
)

PASS = 0
FAIL = 0

def check(name, findings, expected_id=None, min_count=1):
    global PASS, FAIL
    ids = [f.id for f in findings]
    if expected_id:
        count = ids.count(expected_id)
        if count >= min_count:
            print(f"  [PASS] {name} -> found {count}x '{expected_id}'")
            PASS += 1
        else:
            print(f"  [FAIL] {name} -> expected '{expected_id}' x{min_count}, got {count}")
            FAIL += 1
    else:
        if len(findings) == 0:
            print(f"  [FAIL] {name} -> expected findings, got none")
            FAIL += 1
        else:
            print(f"  [PASS] {name} -> {len(findings)} finding(s): {ids}")
            PASS += 1


# === 30. Arbitrary Jump ====================================================

def test_arbitrary_jump():
    print()
    print("--- Test 30: Arbitrary Jump ---")

    source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Test {
    function foo(uint x) public pure returns (uint) {
        assembly {
            let dest := add(0x10, x)
            jump(dest)
        }
    }
}"""
    findings = _find_arbitrary_jump(source)
    check("Dynamic JUMP in assembly", findings, "arbitrary-jump")

    source2 = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Test2 {
    function bar(bytes32 sig) public {
        assembly {
            let target := sig
            jumpi(target, gt(target, 0))
        }
    }
}"""
    findings2 = _find_arbitrary_jump(source2)
    check("Dynamic JUMPI in assembly", findings2, "arbitrary-jump")

    source3 = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Test3 {
    function baz() public pure {
        assembly {
            jump(0x42)
        }
    }
}"""
    findings3 = _find_arbitrary_jump(source3)
    check("Constant jump(0x42) (should be clean)", findings3, "arbitrary-jump", min_count=0)

    source4 = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Test4 {
    function qux() public pure {
        uint x = 42;
    }
}"""
    findings4 = _find_arbitrary_jump(source4)
    check("No assembly (should be clean)", findings4, "arbitrary-jump", min_count=0)


# === 31. Arbitrary Storage Write ===========================================

def test_arbitrary_storage_write():
    print()
    print("--- Test 31: Arbitrary Storage Write ---")

    source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Test {
    function foo(uint slot, uint val) public {
        assembly {
            sstore(slot, val)
        }
    }
}"""
    findings = _find_arbitrary_storage_write(source)
    check("Dynamic SSTORE in assembly", findings, "arbitrary-storage-write")

    source2 = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Test2 {
    function bar(uint val) public {
        assembly {
            sstore(0, val)
        }
    }
}"""
    findings2 = _find_arbitrary_storage_write(source2)
    check("Constant slot sstore(0, val) (should be clean)", findings2, "arbitrary-storage-write", min_count=0)


# === 32. Multiple External Calls ===========================================

def test_multiple_external_calls():
    print()
    print("--- Test 32: Multiple External Calls ---")

    source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Test {
    function multiCall(address a, address b, address c) public {
        (bool ok1,) = a.call("");
        (bool ok2,) = b.call("");
        (bool ok3,) = c.call("");
    }
}"""
    findings = _find_multiple_external_calls(source)
    check("3 external calls in one function", findings, "multiple-external-calls")

    source2 = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Test2 {
    function singleCall(address a) public {
        (bool ok,) = a.call("");
    }
}"""
    findings2 = _find_multiple_external_calls(source2)
    check("1 external call (should be clean)", findings2, "multiple-external-calls", min_count=0)

    source3 = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Test3 {
    function proxyCalls(address impl) public {
        impl.delegatecall(abi.encodeWithSignature("foo()"));
        impl.delegatecall(abi.encodeWithSignature("bar()"));
        impl.delegatecall(abi.encodeWithSignature("baz()"));
    }
}"""
    findings3 = _find_multiple_external_calls(source3)
    check("3 delegatecalls in one function", findings3, "multiple-external-calls")


# === 33. Transaction Order Dependence ======================================

def test_transaction_order_dependence():
    print()
    print("--- Test 33: Transaction Order Dependence ---")

    source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Test {
    function foo() public view {
        require(balanceOf(msg.sender) > 0, "No balance");
    }
}"""
    findings = _find_transaction_order_dependence(source)
    check("balanceOf in require", findings, "transaction-order-dep")

    source2 = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Test2 {
    function foo() public view {
        if (tx.gasprice > 10 gwei) {
            revert("Gas too high");
        }
    }
}"""
    findings2 = _find_transaction_order_dependence(source2)
    check("tx.gasprice in if condition", findings2, "predictable-var")

    source3 = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Test3 {
    function foo() public view {
        if (block.prevrandao > 0) {
            revert("Not allowed");
        }
    }
}"""
    findings3 = _find_transaction_order_dependence(source3)
    check("block.prevrandao in if condition", findings3, "predictable-var")

    source4 = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Test4 {
    function foo() public view returns (uint) {
        return balanceOf(msg.sender);
    }
}"""
    findings4 = _find_transaction_order_dependence(source4)
    check("balanceOf without require/if (should be clean)", findings4, "transaction-order-dep", min_count=0)


# === 34. Strict Balance Equality ===========================================

def test_strict_balance_equality():
    print()
    print("--- Test 34: Strict Balance Equality ---")

    source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Test {
    function foo() public view {
        require(address(this).balance == 100 ether, "Not enough");
    }
}"""
    findings = _find_strict_balance_equality(source)
    check("address(this).balance == in require", findings, "strict-balance-equality")

    source2 = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Test2 {
    function foo() public view {
        if (address(this).balance != 0) {
        }
    }
}"""
    findings2 = _find_strict_balance_equality(source2)
    check("address(this).balance != in if", findings2, "strict-balance-equality")

    source3 = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Test3 {
    function foo() public view {
        require(address(this).balance >= 100 ether, "Not enough");
    }
}"""
    findings3 = _find_strict_balance_equality(source3)
    check("balance >= (should be clean)", findings3, "strict-balance-equality", min_count=0)

    source4 = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Test4 {
    function foo() public pure returns (uint) {
        return 42;
    }
}"""
    findings4 = _find_strict_balance_equality(source4)
    check("No balance check (should be clean)", findings4, "strict-balance-equality", min_count=0)


# === Integration: UniversalExploit.sol =====================================

def test_integration():
    print()
    print("--- Integration Test: Full analyze on UniversalExploit.sol ---")

    path = "exploit/contracts/UniversalExploit.sol"
    if not os.path.exists(path):
        print(f"  [SKIP] File not found: {path}")
        return

    with open(path) as f:
        source = f.read()

    findings = analyze_contract(source)
    ids = [f.id for f in findings]
    print(f"  Total findings: {len(findings)}")

    mythril_ids = ["arbitrary-jump", "arbitrary-storage-write", "multiple-external-calls",
                   "transaction-order-dep", "predictable-var", "strict-balance-equality"]
    for mid in mythril_ids:
        count = ids.count(mid)
        if count > 0:
            print(f"  [PASS] {mid}: {count}x")
            global PASS; PASS += 1
        else:
            print(f"  [INFO] {mid}: {count}x (not present in this contract)")

    multi_count = ids.count("multiple-external-calls")
    if multi_count >= 1:
        print(f"  [PASS] multiple-external-calls (integration): {multi_count}x")
        PASS += 1
    else:
        print(f"  [FAIL] multiple-external-calls: expected >=1, got {multi_count}")
        global FAIL; FAIL += 1


# === Main ==================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  Mythril Pattern Tests (30-34)")
    print("=" * 60)

    test_arbitrary_jump()
    test_arbitrary_storage_write()
    test_multiple_external_calls()
    test_transaction_order_dependence()
    test_strict_balance_equality()
    test_integration()

    print()
    print("=" * 60)
    print(f"  RESULTS: {PASS} passed, {FAIL} failed")
    print("=" * 60)

    sys.exit(1 if FAIL > 0 else 0)
