// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "../../../src/final_mnt4_pairing/BigIntMNT.sol";
import "../../../src/final_mnt4_pairing/MNT4Extension.sol";
import "../../../src/final_mnt4_pairing/MNT4TatePairing.sol";

contract MNT4FinalArkworksHarness {
    function fpAddCanonical(uint256[3] memory a, uint256[3] memory b) external pure returns (uint256[3] memory) {
        return BigIntMNT.add(a, b);
    }

    function fpSubCanonical(uint256[3] memory a, uint256[3] memory b) external pure returns (uint256[3] memory) {
        return BigIntMNT.sub(a, b);
    }

    function fpMulCanonical(uint256[3] memory a, uint256[3] memory b) external pure returns (uint256[3] memory) {
        return BigIntMNT.fromMontgomery(BigIntMNT.montMul(BigIntMNT.toMontgomery(a), BigIntMNT.toMontgomery(b)));
    }

    function fpSqrCanonical(uint256[3] memory a) external pure returns (uint256[3] memory) {
        return BigIntMNT.fromMontgomery(BigIntMNT.montSqr(BigIntMNT.toMontgomery(a)));
    }

    function fpInvCanonical(uint256[3] memory a) external pure returns (uint256[3] memory) {
        return BigIntMNT.fromMontgomery(BigIntMNT.inv(BigIntMNT.toMontgomery(a)));
    }

    function fq2MulCanonical(MNT4ExtensionFinal.Fq2 memory a, MNT4ExtensionFinal.Fq2 memory b)
        external
        pure
        returns (MNT4ExtensionFinal.Fq2 memory)
    {
        return _fromMontFq2(MNT4ExtensionFinal.fq2Mul(_toMontFq2(a), _toMontFq2(b)));
    }

    function fq2SqrCanonical(MNT4ExtensionFinal.Fq2 memory a)
        external
        pure
        returns (MNT4ExtensionFinal.Fq2 memory)
    {
        return _fromMontFq2(MNT4ExtensionFinal.fq2Sqr(_toMontFq2(a)));
    }

    function fq2InvCanonical(MNT4ExtensionFinal.Fq2 memory a)
        external
        pure
        returns (MNT4ExtensionFinal.Fq2 memory)
    {
        return _fromMontFq2(MNT4ExtensionFinal.fq2Inv(_toMontFq2(a)));
    }

    function fq4MulCanonical(MNT4ExtensionFinal.Fq4 memory a, MNT4ExtensionFinal.Fq4 memory b)
        external
        pure
        returns (MNT4ExtensionFinal.Fq4 memory)
    {
        return _fromMontFq4(MNT4ExtensionFinal.fq4Mul(_toMontFq4(a), _toMontFq4(b)));
    }

    function fq4SqrCanonical(MNT4ExtensionFinal.Fq4 memory a)
        external
        pure
        returns (MNT4ExtensionFinal.Fq4 memory)
    {
        return _fromMontFq4(MNT4ExtensionFinal.fq4Sqr(_toMontFq4(a)));
    }

    function fq4InvCanonical(MNT4ExtensionFinal.Fq4 memory a)
        external
        pure
        returns (MNT4ExtensionFinal.Fq4 memory)
    {
        return _fromMontFq4(MNT4ExtensionFinal.fq4Inv(_toMontFq4(a)));
    }

    function tatePairingParametricQOnchainDigest(
        MNT4TatePairing.G1Affine memory p,
        MNT4TatePairing.G2Affine memory q
    ) external pure returns (bytes32) {
        return MNT4TatePairing.tatePairingParametricQOnchainMemDigest(_toMontG1(p), _toMontG2(q));
    }

    function digestFq4(MNT4ExtensionFinal.Fq4 memory a) external pure returns (bytes32) {
        return _digestFq4(a);
    }

    function _toMontG1(MNT4TatePairing.G1Affine memory p)
        private
        pure
        returns (MNT4TatePairing.G1Affine memory r)
    {
        r.x = BigIntMNT.toMontgomery(p.x);
        r.y = BigIntMNT.toMontgomery(p.y);
    }

    function _toMontG2(MNT4TatePairing.G2Affine memory q)
        private
        pure
        returns (MNT4TatePairing.G2Affine memory r)
    {
        r.x = _toMontFq2(q.x);
        r.y = _toMontFq2(q.y);
    }

    function _toMontFq2(MNT4ExtensionFinal.Fq2 memory a) private pure returns (MNT4ExtensionFinal.Fq2 memory r) {
        r.c0 = BigIntMNT.toMontgomery(a.c0);
        r.c1 = BigIntMNT.toMontgomery(a.c1);
    }

    function _fromMontFq2(MNT4ExtensionFinal.Fq2 memory a) private pure returns (MNT4ExtensionFinal.Fq2 memory r) {
        r.c0 = BigIntMNT.fromMontgomery(a.c0);
        r.c1 = BigIntMNT.fromMontgomery(a.c1);
    }

    function _toMontFq4(MNT4ExtensionFinal.Fq4 memory a) private pure returns (MNT4ExtensionFinal.Fq4 memory r) {
        r.c0 = _toMontFq2(a.c0);
        r.c1 = _toMontFq2(a.c1);
    }

    function _fromMontFq4(MNT4ExtensionFinal.Fq4 memory a) private pure returns (MNT4ExtensionFinal.Fq4 memory r) {
        r.c0 = _fromMontFq2(a.c0);
        r.c1 = _fromMontFq2(a.c1);
    }

    function _digestFq4(MNT4ExtensionFinal.Fq4 memory a) private pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                a.c0.c0[0], a.c0.c0[1], a.c0.c0[2],
                a.c0.c1[0], a.c0.c1[1], a.c0.c1[2],
                a.c1.c0[0], a.c1.c0[1], a.c1.c0[2],
                a.c1.c1[0], a.c1.c1[1], a.c1.c1[2]
            )
        );
    }
}
