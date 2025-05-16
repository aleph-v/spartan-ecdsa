pragma circom 2.1.2;

include "../jwt.circom";

// Using the values from the example JWTs
component main { public[ pubKeyX, pubKeyY]} = JWT(2048, 256, 2000, 5, 50);
