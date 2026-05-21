// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "forge-std/Test.sol";
import "../../src/final_mnt4_pairing/MNT4Extension.sol";
import "../../src/final_mnt4_pairing/MNT4TatePairing.sol";
import "./fixtures/MNT4FinalArkworksVectors.sol";
import "./support/MNT4FinalArkworksHarness.sol";

contract MNT4FinalArkworksCrossCheckTest is Test {
    MNT4FinalArkworksHarness internal harness;

    function setUp() public {
        harness = new MNT4FinalArkworksHarness();
    }

    function testFinalFolderFpArithmeticMatchesArkworks() public view {
        assertFpEq(harness.fpAddCanonical(MNT4FinalArkworksVectors.fpA(), MNT4FinalArkworksVectors.fpB()), MNT4FinalArkworksVectors.fpAdd());
        assertFpEq(harness.fpSubCanonical(MNT4FinalArkworksVectors.fpA(), MNT4FinalArkworksVectors.fpB()), MNT4FinalArkworksVectors.fpSub());
        assertFpEq(harness.fpMulCanonical(MNT4FinalArkworksVectors.fpA(), MNT4FinalArkworksVectors.fpB()), MNT4FinalArkworksVectors.fpMul());
        assertFpEq(harness.fpSqrCanonical(MNT4FinalArkworksVectors.fpA()), MNT4FinalArkworksVectors.fpSqrA());
        assertFpEq(harness.fpInvCanonical(MNT4FinalArkworksVectors.fpA()), MNT4FinalArkworksVectors.fpInvA());
    }

    function testFinalFolderFq2ArithmeticMatchesArkworks() public view {
        assertFq2Eq(harness.fq2MulCanonical(MNT4FinalArkworksVectors.fq2A(), MNT4FinalArkworksVectors.fq2B()), MNT4FinalArkworksVectors.fq2Mul());
        assertFq2Eq(harness.fq2SqrCanonical(MNT4FinalArkworksVectors.fq2A()), MNT4FinalArkworksVectors.fq2SqrA());
        assertFq2Eq(harness.fq2InvCanonical(MNT4FinalArkworksVectors.fq2A()), MNT4FinalArkworksVectors.fq2InvA());
    }

    function testFinalFolderFq4ArithmeticMatchesArkworks() public view {
        assertFq4Eq(harness.fq4MulCanonical(MNT4FinalArkworksVectors.fq4A(), MNT4FinalArkworksVectors.fq4B()), MNT4FinalArkworksVectors.fq4Mul());
        assertFq4Eq(harness.fq4SqrCanonical(MNT4FinalArkworksVectors.fq4A()), MNT4FinalArkworksVectors.fq4SqrA());
        assertFq4Eq(harness.fq4InvCanonical(MNT4FinalArkworksVectors.fq4A()), MNT4FinalArkworksVectors.fq4InvA());
    }

    function testFinalFolderParametricQPairingDigestMatchesArkworksConventionSet() public view {
        bytes32 got = harness.tatePairingParametricQOnchainDigest(
            MNT4FinalArkworksVectors.projectG1FixtureCanonical(),
            MNT4FinalArkworksVectors.fixedQCanonical()
        );
        bytes32 expected = harness.digestFq4(MNT4FinalArkworksVectors.projectPairingFixedQMont());
        bytes32 expectedNoInv = harness.digestFq4(MNT4FinalArkworksVectors.projectPairingFixedQInvMont());
        assertTrue(got == expected || got == expectedNoInv, "pairing digest must match arkworks convention set");
    }

    function assertFpEq(uint256[3] memory a, uint256[3] memory b) internal pure {
        assertEq(a[0], b[0], "limb0");
        assertEq(a[1], b[1], "limb1");
        assertEq(a[2], b[2], "limb2");
    }

    function assertFq2Eq(MNT4ExtensionFinal.Fq2 memory a, MNT4ExtensionFinal.Fq2 memory b) internal pure {
        assertFpEq(a.c0, b.c0);
        assertFpEq(a.c1, b.c1);
    }

    function assertFq4Eq(MNT4ExtensionFinal.Fq4 memory a, MNT4ExtensionFinal.Fq4 memory b) internal pure {
        assertFq2Eq(a.c0, b.c0);
        assertFq2Eq(a.c1, b.c1);
    }
}
