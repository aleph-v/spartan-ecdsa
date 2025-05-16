pragma circom 2.1.2;

include "../eff_ecdsa_membership/regular_ecdsa.circom";

component main { public[ pubKeyX, pubKeyY ]} = ECDSA();