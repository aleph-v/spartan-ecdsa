pragma circom 2.1.2;

include "eff_ecdsa_membership/regular_ecdsa.circom";
include "jwt_tx_builder/header-payload-extractor.circom";
include "keyless_zk_proofs/arrays.circom";

template JWT(

    maxMessageLength,
    maxB64HeaderLength,
    maxB64PayloadLength,

    maxMatches,
    maxSubstringLength
) {
    signal input message[maxMessageLength]; // JWT message (header + payload)
    signal input messageLength; // Length of the message signed in the JWT
    signal input periodIndex; // Index of the period in the JWT message
    signal input claimed_hash; // We allow the message to be hashed in a linked proof, WARNING- IN ISOLATION THIS PROOF IS NOT SECURE

    signal input sig_r;
    signal input sig_s;
    signal input pubKeyX;
    signal input pubKeyY;

    signal input matchesCount;
    signal input matchSubstring[maxMatches][maxSubstringLength];
    signal input matchLength[maxMatches];
    signal input matchIndex[maxMatches];

    component sig_checker = ECDSA();
    /// Note we need to invert this s before providing it to this proof
    sig_checker.s_inverse <== sig_s;
    sig_checker.r <== sig_r;
    sig_checker.m <== claimed_hash;
    sig_checker.pubKeyX <== pubKeyX;
    sig_checker.pubKeyY <== pubKeyY;

    component extractor = HeaderPayloadExtractor(maxMessageLength,maxB64HeaderLength, maxB64PayloadLength);
    extractor.message <== message;
    extractor.messageLength <== messageLength;
    extractor.periodIndex <== periodIndex;    

    component enableMacher[maxMatches];
    component matcher[maxMatches];
    var       maxPayloadLength = (maxB64PayloadLength * 3) \ 4;

    for (var i=0;i<maxMatches;i++) {
        enableMacher[i] = LessThan(8);
        enableMacher[i].in[0] <== i;
        enableMacher[i].in[1] <== matchesCount;

        matcher[i] = CheckSubstrInclusionPoly(maxPayloadLength,maxSubstringLength);
        matcher[i].str <== extractor.payload;
        matcher[i].str_hash <== 81283812381238128;
        matcher[i].substr <== matchSubstring[i];
        matcher[i].substr_len <== matchLength[i];
        matcher[i].start_index <== matchIndex[i];
        matcher[i].enabled <== enableMacher[i].out;

    }
}