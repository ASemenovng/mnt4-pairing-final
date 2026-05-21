// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "forge-std/Test.sol";
import "./support/BN254PairingBoolWrapper.sol";

contract BN254PrecompileBoolFuzzTest is Test {
    BN254PairingBoolWrapper internal wrapper;

    function setUp() public {
        wrapper = new BN254PairingBoolWrapper();
    }

    function testEmptyInputReturnsTrueInBothPaths() public view {
        bytes memory input = "";
        assertEq(wrapper.verify(input), _rawPrecompileBool(input));
        assertTrue(wrapper.verify(input));
    }

    function testSingleValidGeneratorPairReturnsSameBoolean() public view {
        bytes memory input = _singleGeneratorPairInput();
        assertEq(wrapper.verify(input), _rawPrecompileBool(input));
    }

    function testFuzzWrapperMatchesRawPrecompileBoolean(bytes memory input) public view {
        vm.assume(input.length <= 768);
        assertEq(wrapper.verify(input), _rawPrecompileBool(input));
    }

    function _rawPrecompileBool(bytes memory input) internal view returns (bool ok) {
        bytes memory out = new bytes(32);
        bool success;
        assembly ("memory-safe") {
            success := staticcall(1000000, 0x08, add(input, 0x20), mload(input), add(out, 0x20), 0x20)
        }
        if (!success) return false;
        return abi.decode(out, (uint256)) == 1;
    }

    function _singleGeneratorPairInput() internal pure returns (bytes memory) {
        // BN254 G1 generator and EIP-197 G2 generator encoding.
        return abi.encodePacked(
            uint256(1),
            uint256(2),
            uint256(0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed),
            uint256(0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2),
            uint256(0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa),
            uint256(0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b)
        );
    }
}
