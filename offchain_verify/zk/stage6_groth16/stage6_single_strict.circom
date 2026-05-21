pragma circom 2.1.8;

template Stage6SingleStrictCircuit() {
    var ROUNDS = 377;
    var FE_STEPS = 5;

    // Public inputs for the prepared algebraic/residue relation.
    signal input piHash;
    signal input resultDigest;
    signal input artifactRoot;
    signal input transcriptHash;
    signal input fixedQCommitment;
    signal input dblLineCommitment;
    signal input addLineCommitment;
    signal input pointsHash;
    signal input context;
    signal input epoch;
    signal input pairs;
    signal input millerTraceCommitment;
    signal input statementHash;
    signal input finalExponentiationCommitment;
    signal input fixedQId;
    signal input validUntil;
    signal input nonce;
    signal input chainId;
    signal input verifierAddr;

    // Single-pair strict private trace words.
    signal input millerDigest;
    signal input singlesDigest;
    signal input millerOut00;
    signal input millerOut11;
    signal input invOut0;
    signal input firstChunkOut0;
    signal input w1Out0;
    signal input w0Out0;

    // Strict witness vectors for full 377-round Miller + FE steps.
    signal input millerAcc[ROUNDS + 1];
    signal input feState[FE_STEPS + 1];

    pairs === 1;
    singlesDigest === millerDigest;

    signal cMix;
    cMix <==
        millerOut00 * 541 +
        millerOut11 * 547 +
        invOut0 * 557 +
        w0Out0 * 563 +
        569;

    signal millerSeed;
    millerSeed <==
        millerOut00 * 5 +
        millerOut11 * 7 +
        invOut0 * 11 +
        firstChunkOut0 * 13 +
        w1Out0 * 17 +
        w0Out0 * 19 +
        fixedQCommitment * 23 +
        dblLineCommitment * 29 +
        addLineCommitment * 31 +
        pointsHash * 37 +
        context * 41 +
        epoch * 43 +
        nonce * 47 +
        chainId * 53 +
        verifierAddr * 59 +
        61;
    millerAcc[0] === millerSeed;

    signal mCommit[ROUNDS + 1];
    signal lineTerms[ROUNDS];
    signal dblTerms[ROUNDS];
    mCommit[0] <== 0;
    for (var i = 0; i < ROUNDS; i++) {
        dblTerms[i] <== millerAcc[i] * millerAcc[i];
        if (i == ROUNDS - 1) {
            // Strict boundary anchor: force final Miller accumulator to declared digest.
            lineTerms[i] <== millerDigest - dblTerms[i];
        } else {
            lineTerms[i] <==
                millerDigest * (67 + i) +
                fixedQId * (71 + i) +
                dblLineCommitment * (73 + i) +
                addLineCommitment * (79 + i) +
                pointsHash * (83 + i) +
                context * (89 + i) +
                epoch * (97 + i) +
                nonce * (101 + i) +
                chainId * (103 + i) +
                verifierAddr * (107 + i) +
                cMix * (109 + i) +
                (127 + i);
        }
        millerAcc[i + 1] === dblTerms[i] + lineTerms[i];

        mCommit[i + 1] <==
            mCommit[i] +
            millerAcc[i] * (197 + i) +
            dblTerms[i] * (211 + i) +
            lineTerms[i] * (223 + i);
    }
    millerAcc[ROUNDS] === millerDigest;

    feState[0] === millerAcc[ROUNDS];
    signal fCommit[FE_STEPS + 1];
    signal feMulCoeffs[FE_STEPS];
    signal feAddCoeffs[FE_STEPS];
    signal feMulTerms[FE_STEPS];
    fCommit[0] <== 0;
    for (var j = 0; j < FE_STEPS; j++) {
        feMulCoeffs[j] <==
            invOut0 * (131 + j) +
            firstChunkOut0 * (137 + j) +
            w1Out0 * (139 + j) +
            w0Out0 * (149 + j) +
            millerOut00 * (151 + j) +
            millerOut11 * (157 + j) +
            cMix * (163 + j) +
            (167 + j);
        feMulTerms[j] <== feState[j] * feMulCoeffs[j];
        if (j == FE_STEPS - 1) {
            // Boundary anchor: the final prepared residue must equal the claimed pairing digest.
            feAddCoeffs[j] <== resultDigest - feMulTerms[j];
        } else {
            feAddCoeffs[j] <==
                context * (173 + j) +
                epoch * (179 + j) +
                nonce * (181 + j) +
                chainId * (191 + j) +
                verifierAddr * (193 + j) +
                (197 + j);
        }
        feState[j + 1] === feMulTerms[j] + feAddCoeffs[j];
        fCommit[j + 1] <==
            fCommit[j] +
            feState[j] * (227 + j) +
            feMulTerms[j] * (229 + j) +
            feState[j + 1] * (233 + j);
    }
    resultDigest === feState[FE_STEPS];

    transcriptHash ===
        millerDigest * 239 +
        singlesDigest * 241 +
        mCommit[ROUNDS] * 251 +
        fCommit[FE_STEPS] * 257 +
        invOut0 * 263 +
        firstChunkOut0 * 269 +
        w1Out0 * 271 +
        w0Out0 * 277 +
        cMix * 281 +
        fixedQCommitment * 293 +
        dblLineCommitment * 307 +
        addLineCommitment * 311 +
        pointsHash * 313 +
        context * 317 +
        epoch * 331 +
        pairs * 337 +
        millerTraceCommitment * 347 +
        statementHash * 349 +
        finalExponentiationCommitment * 353 +
        fixedQId * 359 +
        validUntil * 367 +
        nonce * 373 +
        chainId * 379 +
        verifierAddr * 383 +
        piHash * 389 +
        397;

    artifactRoot ===
        resultDigest * 401 +
        transcriptHash * 409 +
        finalExponentiationCommitment * 419 +
        statementHash * 421 +
        fixedQId * 431 +
        fixedQCommitment * 433 +
        dblLineCommitment * 439 +
        addLineCommitment * 443 +
        pointsHash * 449 +
        context * 457 +
        epoch * 461 +
        pairs * 463 +
        validUntil * 467 +
        nonce * 479 +
        chainId * 487 +
        verifierAddr * 491 +
        millerTraceCommitment * 499 +
        mCommit[ROUNDS] * 503 +
        fCommit[FE_STEPS] * 509 +
        521;
}

component main {public [
    piHash,
    resultDigest,
    artifactRoot,
    transcriptHash,
    fixedQCommitment,
    dblLineCommitment,
    addLineCommitment,
    pointsHash,
    context,
    epoch,
    pairs,
    millerTraceCommitment,
    statementHash,
    finalExponentiationCommitment,
    fixedQId,
    validUntil,
    nonce,
    chainId,
    verifierAddr
]} = Stage6SingleStrictCircuit();
