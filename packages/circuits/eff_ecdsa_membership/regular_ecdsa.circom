pragma circom 2.1.2;

include "./secp256k1/mul.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";


/**
 *  ECDSA
 *  ====================
 *  
 *  Implements ECDSA verification. Each Secp256k1Mul takes 3k constraints, however adding checked wrong field multiplication
 *  costs 4k constraints and so instead of doing the s_inverse * m and s_inverse * r mod n where n is the order of the secp256k1
 *  we just do scalar mults which use the native field of spec256k1.
 */
template ECDSA() {
    signal input s_inverse;
    signal input r;
    signal input m;
    signal input pubKeyX;
    signal input pubKeyY;

    // TODO - Do we want more checks on s_inverse? (I think s_inv != 0 suffices)
    component check0 = IsZero();
    check0.in <== s_inverse;
    check0.out === 0;

    // TODO - Its shocking that this is more efficient than big number multiply, perhaps we should double check

    // s^-1 x Q_a computation
    component siPub = Secp256k1Mul();
    siPub.scalar <== s_inverse;
    siPub.xP <== pubKeyX;
    siPub.yP <== pubKeyY;

    // r x (s^-1 x Q_a) computation
    component rSiPub = Secp256k1Mul();
    rSiPub.scalar <== r;
    rSiPub.xP <== siPub.outX;
    rSiPub.yP <== siPub.outY;

    // s^-1 x G computation
    component siG = Secp256k1Mul();
    siG.scalar <== s_inverse;
    siG.xP <== 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    siG.yP <== 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    // m x (s^-1 x G) computation
    component mSiG = Secp256k1Mul();
    mSiG.scalar <== m;
    mSiG.xP <== siG.outX;
    mSiG.yP <== siG.outY;

    // R = r s^-1 x Q_a + m s^-1 x G
    component R = Secp256k1AddComplete();
    R.xP <== rSiPub.outX;
    R.yP <== rSiPub.outY;
    R.xQ <== mSiG.outX;
    R.yQ <== mSiG.outY;

    // In ECDSA we have that the R's x coordinate should be the r from the signature's verification result
    r === R.outX;
} 