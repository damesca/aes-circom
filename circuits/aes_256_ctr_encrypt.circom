pragma circom 2.0.0;

include "aes_256_ctr.circom";
include "aes_256_key_expansion.circom";

template AES_256_CTR_ENC(n_bits) {

    component aes_encryptor = AES256CTR(n_bits);

    signal input MSG[n_bits];
    signal input CTR[128];
    signal input KEY[256];
    signal output CTX[128];

    component key_expansion = AES256KeyExpansion();
    for(var i = 0; i < 256; i++) {
        key_expansion.key[i] <== KEY[i];
    }
    for(var i = 0; i < 1920; i++) {
        aes_encryptor.ks[i] <== key_expansion.w[i];
    }
    for(var i = 0; i < 128; i++) {
        aes_encryptor.ctr[i] <== CTR[i];
    }
    for(var i = 0; i < n_bits; i++) {
        aes_encryptor.in[i] <== MSG[i];
    }
    for(var i = 0; i < n_bits; i++) {
        CTX[i] <== aes_encryptor.out[i];
    }

}