// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "./BigIntMNT.sol";
import "./MNT4Extension.sol";

library MNT4TatePairingArithmetic {
    using MNT4ExtensionFinal for MNT4ExtensionFinal.Fq2;
    using MNT4ExtensionFinal for MNT4ExtensionFinal.Fq4;

    uint256 private constant ONE_MONT_0 = 0x79589819c788b60197c3e4a0cd14572e91cd31c65a03468698a8ecabd9dc6f42;
    uint256 private constant ONE_MONT_1 = 0x598b4302d2f00a62320c3bb7133385591e0f4d8acf031d68ed269c942108976f;
    uint256 private constant ONE_MONT_2 = 0x7b479ec8e24295455fb31ff9a1950fa47edb3865e88c4074c9cbfd8ca621;

    struct G1Point {
        uint256[3] x;
        uint256[3] y;
        bool infinity;
    }

    struct G2Point {
        MNT4ExtensionFinal.Fq2 x;
        MNT4ExtensionFinal.Fq2 y;
        bool infinity;
    }

    function fq4One() internal pure returns (MNT4ExtensionFinal.Fq4 memory o) {
        o.c0.c0[0] = ONE_MONT_0;
        o.c0.c0[1] = ONE_MONT_1;
        o.c0.c0[2] = ONE_MONT_2;
    }

    function _isEq3(uint256[3] memory a, uint256[3] memory b) private pure returns (bool) {
        return a[0] == b[0] && a[1] == b[1] && a[2] == b[2];
    }

    function _isZero3(uint256[3] memory a) private pure returns (bool) {
        return (a[0] | a[1] | a[2]) == 0;
    }

    function _neg3(uint256[3] memory a) private pure returns (uint256[3] memory r) {
        (r[0], r[1], r[2]) = BigIntMNT.sub3(0, 0, 0, a[0], a[1], a[2]);
    }

    function _mul3(uint256[3] memory a, uint256[3] memory b) private pure returns (uint256[3] memory r) {
        (r[0], r[1], r[2]) = BigIntMNT.montMul3(a[0], a[1], a[2], b[0], b[1], b[2]);
    }

    function _inv3(uint256[3] memory a) private pure returns (uint256[3] memory r) {
        (r[0], r[1], r[2]) = BigIntMNT.inv3(a[0], a[1], a[2]);
    }

    function _sub3(uint256[3] memory a, uint256[3] memory b) private pure returns (uint256[3] memory r) {
        (r[0], r[1], r[2]) = BigIntMNT.sub3(a[0], a[1], a[2], b[0], b[1], b[2]);
    }

    function _add3(uint256[3] memory a, uint256[3] memory b) private pure returns (uint256[3] memory r) {
        (r[0], r[1], r[2]) = BigIntMNT.add3(a[0], a[1], a[2], b[0], b[1], b[2]);
    }

    function g1AddAffine(G1Point memory p, G1Point memory q) internal pure returns (G1Point memory r) {
        if (p.infinity) return q;
        if (q.infinity) return p;

        if (_isEq3(p.x, q.x)) {
            uint256[3] memory ySum = _add3(p.y, q.y);
            if (_isZero3(ySum)) {
                r.infinity = true;
                return r;
            }
            return g1DoubleAffine(p, [uint256(0), uint256(0), uint256(0)]);
        }

        uint256[3] memory num = _sub3(q.y, p.y);
        uint256[3] memory den = _sub3(q.x, p.x);
        uint256[3] memory lambda = _mul3(num, _inv3(den));

        uint256[3] memory lambda2 = _mul3(lambda, lambda);
        uint256[3] memory x3 = _sub3(_sub3(lambda2, p.x), q.x);
        uint256[3] memory y3 = _sub3(_mul3(lambda, _sub3(p.x, x3)), p.y);

        r.x = x3;
        r.y = y3;
    }

    function g1DoubleAffine(G1Point memory p, uint256[3] memory aCoeff) internal pure returns (G1Point memory r) {
        if (p.infinity) return p;

        uint256[3] memory xx = _mul3(p.x, p.x);
        uint256[3] memory threeXX = _add3(xx, _add3(xx, xx));
        uint256[3] memory num = _add3(threeXX, aCoeff);

        uint256[3] memory den = _add3(p.y, p.y);
        uint256[3] memory lambda = _mul3(num, _inv3(den));

        uint256[3] memory lambda2 = _mul3(lambda, lambda);
        uint256[3] memory twoX = _add3(p.x, p.x);
        uint256[3] memory x3 = _sub3(lambda2, twoX);
        uint256[3] memory y3 = _sub3(_mul3(lambda, _sub3(p.x, x3)), p.y);

        r.x = x3;
        r.y = y3;
    }

    function g2AddAffine(G2Point memory p, G2Point memory q) internal pure returns (G2Point memory r) {
        if (p.infinity) return q;
        if (q.infinity) return p;

        if (
            p.x.c0[0] == q.x.c0[0] && p.x.c0[1] == q.x.c0[1] && p.x.c0[2] == q.x.c0[2] &&
            p.x.c1[0] == q.x.c1[0] && p.x.c1[1] == q.x.c1[1] && p.x.c1[2] == q.x.c1[2]
        ) {
            MNT4ExtensionFinal.Fq2 memory ySum = MNT4ExtensionFinal.fq2Add(p.y, q.y);
            if (
                ySum.c0[0] == 0 && ySum.c0[1] == 0 && ySum.c0[2] == 0 &&
                ySum.c1[0] == 0 && ySum.c1[1] == 0 && ySum.c1[2] == 0
            ) {
                r.infinity = true;
                return r;
            }
            MNT4ExtensionFinal.Fq2 memory aZero;
            return g2DoubleAffine(p, aZero);
        }

        MNT4ExtensionFinal.Fq2 memory num = MNT4ExtensionFinal.fq2Sub(q.y, p.y);
        MNT4ExtensionFinal.Fq2 memory den = MNT4ExtensionFinal.fq2Sub(q.x, p.x);
        MNT4ExtensionFinal.Fq2 memory lambda = MNT4ExtensionFinal.fq2Mul(num, MNT4ExtensionFinal.fq2Inv(den));

        MNT4ExtensionFinal.Fq2 memory lambda2 = MNT4ExtensionFinal.fq2Sqr(lambda);
        MNT4ExtensionFinal.Fq2 memory x3 = MNT4ExtensionFinal.fq2Sub(MNT4ExtensionFinal.fq2Sub(lambda2, p.x), q.x);
        MNT4ExtensionFinal.Fq2 memory y3 = MNT4ExtensionFinal.fq2Sub(
            MNT4ExtensionFinal.fq2Mul(lambda, MNT4ExtensionFinal.fq2Sub(p.x, x3)),
            p.y
        );

        r.x = x3;
        r.y = y3;
    }

    function g2DoubleAffine(G2Point memory p, MNT4ExtensionFinal.Fq2 memory aCoeff) internal pure returns (G2Point memory r) {
        if (p.infinity) return p;

        MNT4ExtensionFinal.Fq2 memory xx = MNT4ExtensionFinal.fq2Sqr(p.x);
        MNT4ExtensionFinal.Fq2 memory threeXX = MNT4ExtensionFinal.fq2Add(xx, MNT4ExtensionFinal.fq2Add(xx, xx));
        MNT4ExtensionFinal.Fq2 memory num = MNT4ExtensionFinal.fq2Add(threeXX, aCoeff);

        MNT4ExtensionFinal.Fq2 memory den = MNT4ExtensionFinal.fq2Add(p.y, p.y);
        MNT4ExtensionFinal.Fq2 memory lambda = MNT4ExtensionFinal.fq2Mul(num, MNT4ExtensionFinal.fq2Inv(den));

        MNT4ExtensionFinal.Fq2 memory lambda2 = MNT4ExtensionFinal.fq2Sqr(lambda);
        MNT4ExtensionFinal.Fq2 memory twoX = MNT4ExtensionFinal.fq2Add(p.x, p.x);
        MNT4ExtensionFinal.Fq2 memory x3 = MNT4ExtensionFinal.fq2Sub(lambda2, twoX);
        MNT4ExtensionFinal.Fq2 memory y3 = MNT4ExtensionFinal.fq2Sub(
            MNT4ExtensionFinal.fq2Mul(lambda, MNT4ExtensionFinal.fq2Sub(p.x, x3)),
            p.y
        );

        r.x = x3;
        r.y = y3;
    }

    /// @notice Core Miller-loop accumulator transition: f <- f^2 * ell.
    function millerAccumulate(
        MNT4ExtensionFinal.Fq4 memory f,
        MNT4ExtensionFinal.Fq4 memory ell
    ) internal pure returns (MNT4ExtensionFinal.Fq4 memory) {
        return MNT4ExtensionFinal.fq4Mul(MNT4ExtensionFinal.fq4Sqr(f), ell);
    }

    /// @notice Generic fixed-exponent pow for Fq4 (LSB-first over 4 limbs).
    function fq4Pow(
        MNT4ExtensionFinal.Fq4 memory x,
        uint256 e0,
        uint256 e1,
        uint256 e2,
        uint256 e3,
        uint256 topBits
    ) internal pure returns (MNT4ExtensionFinal.Fq4 memory r) {
        r = fq4One();
        MNT4ExtensionFinal.Fq4 memory b = x;

        uint256[4] memory e = [e0, e1, e2, e3];
        for (uint256 i = 0; i < 4; ++i) {
            uint256 bits = i == 3 ? topBits : 256;
            uint256 limb = e[i];
            for (uint256 j = 0; j < bits; ++j) {
                if (((limb >> j) & 1) != 0) {
                    r = MNT4ExtensionFinal.fq4Mul(r, b);
                }
                b = MNT4ExtensionFinal.fq4Sqr(b);
            }
        }
    }
}
