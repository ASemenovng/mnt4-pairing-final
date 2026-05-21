// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "forge-std/Test.sol";
import "../../src/final_mnt4_pairing/MNT4PairingVerifier.sol";
import "../../src/final_mnt4_pairing/MNT4PairingFinal.sol";
import "../../src/final_mnt4_pairing/MNT4PairingProofChecker.sol";

contract MNT4PairingFinalE2ETest is Test {
    MNT4PairingFinal internal verifier;

    bytes internal constant PROOF_RELATION_FIXTURE =
        hex"00072f309495178a1dfcb30f85e1ce816708785cec7654dc0d296e3302eb72df034d2c702c7c8340dfcd4cebbe7a0030b29be902b2b488666c7220a85f40e83a24597a366cd6948beb55345c9f0e8c7663c302201d4187ccae815429a921e15f0aac54987b255de979bd348659fd011dda37562b4a7ca10e015557d758d0e7c81d933bc40c5189fbc641d62b9e47d355fa85f9739c4c54a1e9fd2daf59ec645d05089d96a5c8ca0cc504b2c8e86e87cbb0bbb8d65f3dd29551ffb2c59b1728d714079ea541011463f82e73d2bacfdb94574c30e2b4c0dee5d71403de186b981306fb87217cf007342e881dde2c675c55911cc81e51c27201ff2fc450be9cd9ff";

    function setUp() public {
        verifier = new MNT4PairingFinal(8);
    }

    function testFinalMainContractVerifiesRealProofEnvelope() public view {
        MNT4PairingVerifier.G1Point[] memory points = new MNT4PairingVerifier.G1Point[](1);
        points[0] = _g1Generator();
        MNT4PairingVerifier.G2Point memory q = _g2Generator();
        uint256[19] memory signals = _pubSignals();
        bytes memory envelope = _proofEnvelope(signals);

        bool ok = verifier.verifyPairingClaim(
            points,
            q,
            0x792f0eb69a2d7c2b4fabd0fcca4e0a74b47e4c40dfe58f83ec8ef1615f1c832d,
            0x138cf5d3857bcbe91bf01ee1a35307e0c1c508d3d40087b8bf45ae0744a5057c,
            0x1307e5072d48a21ae04ecc9818a6baa8ff041821f060440a53960c615c5f09ef,
            0x0000000000000000000000000000000000000000000000000000000000000000,
            1,
            _commitments(),
            envelope
        );
        assertTrue(ok);
    }

    function testFinalMainContractRejectsTamperedPoint() public {
        MNT4PairingVerifier.G1Point[] memory points = new MNT4PairingVerifier.G1Point[](1);
        points[0] = _g1Generator();
        points[0].x[0] ^= 1;
        uint256[19] memory signals = _pubSignals();

        vm.expectRevert(MNT4PairingVerifier.InvalidPublicInputBinding.selector);
        verifier.verifyPairingClaim(
            points,
            _g2Generator(),
            0x792f0eb69a2d7c2b4fabd0fcca4e0a74b47e4c40dfe58f83ec8ef1615f1c832d,
            0x138cf5d3857bcbe91bf01ee1a35307e0c1c508d3d40087b8bf45ae0744a5057c,
            0x1307e5072d48a21ae04ecc9818a6baa8ff041821f060440a53960c615c5f09ef,
            0x0000000000000000000000000000000000000000000000000000000000000000,
            1,
            _commitments(),
            _proofEnvelope(signals)
        );
    }

    function testFinalMainContractRejectsTamperedQ() public {
        MNT4PairingVerifier.G1Point[] memory points = new MNT4PairingVerifier.G1Point[](1);
        points[0] = _g1Generator();
        MNT4PairingVerifier.G2Point memory q = _g2Generator();
        q.x[0] ^= 1;

        vm.expectRevert(MNT4PairingVerifier.InvalidPublicInputBinding.selector);
        verifier.verifyPairingClaim(
            points,
            q,
            0x792f0eb69a2d7c2b4fabd0fcca4e0a74b47e4c40dfe58f83ec8ef1615f1c832d,
            0x138cf5d3857bcbe91bf01ee1a35307e0c1c508d3d40087b8bf45ae0744a5057c,
            0x1307e5072d48a21ae04ecc9818a6baa8ff041821f060440a53960c615c5f09ef,
            0x0000000000000000000000000000000000000000000000000000000000000000,
            1,
            _commitments(),
            _proofEnvelope(_pubSignals())
        );
    }

    function testFinalMainContractRejectsTamperedResultDigest() public {
        MNT4PairingVerifier.G1Point[] memory points = new MNT4PairingVerifier.G1Point[](1);
        points[0] = _g1Generator();

        vm.expectRevert(MNT4PairingVerifier.InvalidPublicInputBinding.selector);
        verifier.verifyPairingClaim(
            points,
            _g2Generator(),
            bytes32(uint256(0x792f0eb69a2d7c2b4fabd0fcca4e0a74b47e4c40dfe58f83ec8ef1615f1c832d) ^ 1),
            0x138cf5d3857bcbe91bf01ee1a35307e0c1c508d3d40087b8bf45ae0744a5057c,
            0x1307e5072d48a21ae04ecc9818a6baa8ff041821f060440a53960c615c5f09ef,
            0x0000000000000000000000000000000000000000000000000000000000000000,
            1,
            _commitments(),
            _proofEnvelope(_pubSignals())
        );
    }

    function testFinalMainContractRejectsTamperedLineCommitment() public {
        MNT4PairingVerifier.G1Point[] memory points = new MNT4PairingVerifier.G1Point[](1);
        points[0] = _g1Generator();
        MNT4PairingVerifier.ArtifactCommitments memory commitments = _commitments();
        commitments.doubleLineCommitment = bytes32(uint256(commitments.doubleLineCommitment) ^ 1);

        vm.expectRevert(MNT4PairingVerifier.InvalidPublicInputBinding.selector);
        verifier.verifyPairingClaim(
            points,
            _g2Generator(),
            0x792f0eb69a2d7c2b4fabd0fcca4e0a74b47e4c40dfe58f83ec8ef1615f1c832d,
            0x138cf5d3857bcbe91bf01ee1a35307e0c1c508d3d40087b8bf45ae0744a5057c,
            0x1307e5072d48a21ae04ecc9818a6baa8ff041821f060440a53960c615c5f09ef,
            0x0000000000000000000000000000000000000000000000000000000000000000,
            1,
            commitments,
            _proofEnvelope(_pubSignals())
        );
    }


    function testFinalMainContractRejectsTamperedMillerTraceCommitment() public {
        MNT4PairingVerifier.G1Point[] memory points = new MNT4PairingVerifier.G1Point[](1);
        points[0] = _g1Generator();
        MNT4PairingVerifier.ArtifactCommitments memory commitments = _commitments();
        commitments.millerTraceCommitment = bytes32(uint256(commitments.millerTraceCommitment) ^ 1);

        vm.expectRevert(MNT4PairingVerifier.InvalidPublicInputBinding.selector);
        verifier.verifyPairingClaim(
            points,
            _g2Generator(),
            0x792f0eb69a2d7c2b4fabd0fcca4e0a74b47e4c40dfe58f83ec8ef1615f1c832d,
            0x138cf5d3857bcbe91bf01ee1a35307e0c1c508d3d40087b8bf45ae0744a5057c,
            0x1307e5072d48a21ae04ecc9818a6baa8ff041821f060440a53960c615c5f09ef,
            0x0000000000000000000000000000000000000000000000000000000000000000,
            1,
            commitments,
            _proofEnvelope(_pubSignals())
        );
    }

    function testFinalMainContractRejectsTamperedFinalExponentiationCommitment() public {
        MNT4PairingVerifier.G1Point[] memory points = new MNT4PairingVerifier.G1Point[](1);
        points[0] = _g1Generator();
        MNT4PairingVerifier.ArtifactCommitments memory commitments = _commitments();
        commitments.finalExponentiationCommitment = bytes32(uint256(commitments.finalExponentiationCommitment) ^ 1);

        vm.expectRevert(MNT4PairingVerifier.InvalidPublicInputBinding.selector);
        verifier.verifyPairingClaim(
            points,
            _g2Generator(),
            0x792f0eb69a2d7c2b4fabd0fcca4e0a74b47e4c40dfe58f83ec8ef1615f1c832d,
            0x138cf5d3857bcbe91bf01ee1a35307e0c1c508d3d40087b8bf45ae0744a5057c,
            0x1307e5072d48a21ae04ecc9818a6baa8ff041821f060440a53960c615c5f09ef,
            0x0000000000000000000000000000000000000000000000000000000000000000,
            1,
            commitments,
            _proofEnvelope(_pubSignals())
        );
    }

    function _proofEnvelope(uint256[19] memory signals) internal pure returns (bytes memory) {
        MNT4PairingProofChecker.ProofData memory proofData = abi.decode(PROOF_RELATION_FIXTURE, (MNT4PairingProofChecker.ProofData));
        return abi.encode(bytes32(signals[12]), signals, proofData);
    }

    function _commitments() internal pure returns (MNT4PairingVerifier.ArtifactCommitments memory c) {
        c.lineCommitment = 0xdc70fe833c6bd71c7b8144166e9b94c3393a4d37a52b1497fc3e34180a3cd843;
        c.doubleLineCommitment = 0x288ded9d5a49d4a5fce95a3c0d240d128c6e1470a9bb99b8e2fa8390596e4b4c;
        c.addLineCommitment = 0xa06c68cea868049c9559bdaedc1b40a090f6161c1a47190b024aa199d6b6d71d;
        c.millerTraceCommitment = 0x03c54144794a78ef6fdeaf16bed72215ec0e4bfd7de84269f2d6a410e55c7a47;
        c.finalExponentiationCommitment = 0x792f0eb69a2d7c2b4fabd0fcca4e0a74b47e4c40dfe58f83ec8ef1615f1c832d;
    }

    function _g1Generator() internal pure returns (MNT4PairingVerifier.G1Point memory p) {
        p.x = [
            uint256(0xd4b08cafff2dfb656ea99eb96cbb6fd6052f720cf67fbafc82ea8185e14d5d54),
            uint256(0xc813b87e370cda4d34c48c9b8ab9debf0c78f1afe0bd37b1e980e9a988adf90f),
            uint256(0x1bd4456a09aee9d956c795a3e78bd21790773a524d083c217e0a038c1db6)
        ];
        p.y = [
            uint256(0x493bee51803a2b7a73296013aba459c3329803b147e38c38da05d6d7deada1ce),
            uint256(0xc263cc5a14d619cd3c971a9bca41f277c7bd91c2067595eb910c4887b84c27f2),
            uint256(0x1825593937b81fa08d2f1880d5f7435bf83c9522e6d7412d00fc9d68d790b)
        ];
    }

    function _g2Generator() internal pure returns (MNT4PairingVerifier.G2Point memory q) {
        q.x = [
            uint256(0xf5199b0d7e333053db197417e18872316a123355ee93878564cd9e87e5f14e2d),
            uint256(0x1ea26a53c24e41623f8ccbdf316d6964d1117417b290f004397da434e85b78a7),
            uint256(0x13635a0d01b785b05c21a27b7acc73c355554caad25804fa40c8be29a9276),
            uint256(0xe67355775c8eb87e9217aa6ceb0cf80802b8029c87df25f6b56fc312dc34c98b),
            uint256(0xf1e11281b99054d1de8489295782a1036bebff63e88338c290eb471ebb74c1b1),
            uint256(0x16aea1ba33dc031facd7fa4614cca6ec60806cb661af7071e05664c68aa32)
        ];
        q.y = [
            uint256(0x36739870b33ba70fa567a1375a9e2a27220b34b2b9daee2f438d727bf4c5002e),
            uint256(0xe526639d49ef3efff64a68ade535340fdb048df87997b3b7b058c55679b63f3e),
            uint256(0x1202d1e47ccef4f6af38904883c288e46b4ca897b87bbd52be2d6e4bee8fd),
            uint256(0xbbf8387b3a74937a6a393d84e066ddfca41dbc2a99750c11f06781d5bec3ed74),
            uint256(0x92e8c3c2f80404545c089d226f9c345d380c74d14f4e2d84ecb6da0ba28e9879),
            uint256(0x11e7b5c581fa35de638cd06f1c4e659a934e501a154debf6ce50f1d3555)
        ];
    }

    function _pubSignals() internal pure returns (uint256[19] memory s) {
        s[0] = 1705457877073479092679100087905933305605386600942771699920686541609740565063;
        s[1] = 11036512294337219476893357748126929782288044363298580992696647968470926656299;
        s[2] = 8842999342612207370876197781255834026150468151694239735806880359727822603644;
        s[3] = 8607892745937484478346724916499319169708766219263514929118640101331287607791;
        s[4] = 12155498653904882215483313291829599830078694931930508910329644235575711815743;
        s[5] = 18343279335568702252802081960743623610777628085996452750557383000121385306956;
        s[6] = 6896869993905197161703406764106133033494221987589751492893277980193705088794;
        s[7] = 10471926129243433667600498852140678410149053866886959659989041391195758299221;
        s[8] = 0;
        s[9] = 1;
        s[10] = 1;
        s[11] = 1705457877073479092679100087905933305605386600942771699920686541609740565063;
        s[12] = 20422886833540627566076295421553480472236339634332364802409031989335132756392;
        s[13] = 11036512294337219476893357748126929782288044363298580992696647968470926656299;
        s[14] = 4683552257264624546458934762482869852374879932339739613386321654625558838693;
        s[15] = 0;
        s[16] = 0;
        s[17] = 31337;
        s[18] = 597701131734199939596644485529582442765961009901;
    }
}
