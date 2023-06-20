pragma circom 2.0.0;

include "aes_256_encrypt.circom";
include "aes_256_key_expansion.circom";
include "hmac256.circom";

template aes_256_ecb_encrypt(n_bits) {

    signal input in[n_bits];
    signal input key[256];
    signal output out[n_bits];
    signal output tag[256];

    var msg_len = n_bits / 8;
    var blocks = msg_len / 16;

    // Add padding verification

    component aes[blocks];
    for(var i = 0; i < blocks; i++) {
        aes[i] = AES256Encrypt();
    }
    
    component key_expansion = AES256KeyExpansion();
    for(var i = 0; i < 256; i++) {
        key_expansion.key[i] <== key[i];
    }

    for(var i = 0; i < blocks; i++) {
        for(var j = 0; j < 128; j++) {
            aes[i].in[j] <== in[j + i * 128];
        }
        for(var k = 0; k < 1920; k++) {
            aes[i].ks[k] <== key_expansion.w[k];
        }
        for(var j = 0; j < 128; j++) {
            out[j + i * 128] <== aes[i].out[j];
        }
    }

    // HMAC auth
    component hmac = hmac256(n_bits);
	for (var i = 0; i < n_bits; i++) {
		hmac.message[i] <== in[i];
	}
	for (var i = 0; i < 256; i++) {
		hmac.key[i] <== key[i];
	}
	for (var i = 0; i < 256; i++) {
		tag[i] <== hmac.tag[i];
	}

}