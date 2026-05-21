// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "forge-std/Test.sol";
import "../../src/final_mnt4_pairing/MNT4ProofSystemVerifier.sol";
import "../../src/final_mnt4_pairing/MNT4PairingProofChecker.sol";

contract MNT4PairingProofCheckerTest is Test {
    MNT4ProofSystemVerifier internal verifier;
    MNT4PairingProofChecker internal checker;

    bytes internal constant PROOF_RELATION_FIXTURE =
        hex"00072f309495178a1dfcb30f85e1ce816708785cec7654dc0d296e3302eb72df034d2c702c7c8340dfcd4cebbe7a0030b29be902b2b488666c7220a85f40e83a24597a366cd6948beb55345c9f0e8c7663c302201d4187ccae815429a921e15f0aac54987b255de979bd348659fd011dda37562b4a7ca10e015557d758d0e7c81d933bc40c5189fbc641d62b9e47d355fa85f9739c4c54a1e9fd2daf59ec645d05089d96a5c8ca0cc504b2c8e86e87cbb0bbb8d65f3dd29551ffb2c59b1728d714079ea541011463f82e73d2bacfdb94574c30e2b4c0dee5d71403de186b981306fb87217cf007342e881dde2c675c55911cc81e51c27201ff2fc450be9cd9ff";

    function setUp() public {
        verifier = new MNT4ProofSystemVerifier();
        checker = new MNT4PairingProofChecker(verifier);
    }

    function testRealProofFixtureVerifiesThroughNeutralChecker() public view {
        assertTrue(checker.verifyForPublicSignals(_pubSignals(), PROOF_RELATION_FIXTURE));
    }

    function testNeutralCheckerBindsStatementHash() public view {
        uint256[19] memory signals = _pubSignals();
        bytes32 statementHash = bytes32(signals[12]);
        bytes memory envelope = abi.encode(statementHash, signals, abi.decode(PROOF_RELATION_FIXTURE, (MNT4PairingProofChecker.ProofData)));

        assertTrue(checker.verify(statementHash, envelope));
        assertFalse(checker.verify(bytes32(uint256(statementHash) ^ 1), envelope));
    }

    function testNeutralCheckerRejectsTamperedSignal() public view {
        uint256[19] memory signals = _pubSignals();
        signals[2] ^= 1;
        assertFalse(checker.verifyForPublicSignals(signals, PROOF_RELATION_FIXTURE));
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
