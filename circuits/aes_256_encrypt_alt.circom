pragma circom 2.0.0;

include "aes_emulation_tables.circom";
include "aes_emulation.circom";
include "helper_functions.circom";

template AES256Encrypt()
{
    signal input in[128];
    signal input ks[1920];
    signal output out[128];

    var ks_index = 0;
    var s[4][32], t[4][32];

    var i, j, k;

    /* FUNC: First assignment to s0,s1,s2,s3 */
    component xor_1[4][32];

    for(i=0; i<4; i++)
    {
        for(j=0; j<32; j++)
        {
            // s[i][j] = in[i*32+j] ^ ks[i*32+j];

            xor_1[i][j] = XOR();
            xor_1[i][j].a <== in[i*32+j];
            xor_1[i][j].b <== ks[i*32+j];

            s[i][j] = xor_1[i][j].out;
        }
    }

    /* FUNC: 14 iterations for emulated aes tables */
    for(i=0; i<13; i++)
    {
        var tmp_index_8[32], tmp_index_16[32], tmp_index_24[32];

        /* FUNC: compute t0 */
        /* FUNC: right shifts */
        component right_shift_8 = BitwiseRightShift(32, 8);
        component right_shift_16 = BitwiseRightShift(32, 16);
        component right_shift_24 = BitwiseRightShift(32, 24);
        for(j=0; j<32; j++)
        {
            right_shift_8.in[j] = s[1][j];
            right_shift_16.in[j] = s[2][j];
            right_shift_24.in[j] = s[3][j];
        }
        for(j=0; j<32; j++)
        {
            tmp_index_8[j] = right_shift_8.out[j];
            tmp_index_16[j] = right_shift_16.out[j];
            tmp_index_24[j] = right_shift_24.out[j];
        }

        /* FUNC: take last 8 bits */
        // TODO: revise if it must be taken the first 8 instead of the last
        var index[4][8], index_num[4];
        for(j=0; j<8; j++)
        {
            index[0][j] = s[0][(32-8)+j];
            index[1][j] = tmp_index_8[(32-8)+j];
            index[2][j] = tmp_index_16[(32-8)+j];
            index[3][j] = tmp_index_24[(32-8)+j];
        }

        /* FUNC: index from bits to num */
        component bits2num_0[4];
        for(j=0; j<4; j++)
        {
            bits2num_0[j] = Bits2Num(8);
            for(k=0; k<8; k++)
            {
                bits2num_0[j].in[k] = index[j][k];
            }
            index_num[j] = bits2num_0[j].out;
        }

        /* FUNC: take values from aes tables */
        var aes_table_value_0[4];
        for(j=0; j<4; j++)
        {
            aes_table_value_0[j] = emulated_aesenc_enc_table(j, index_num[j]);
        }

        /* FUNC: xor the 4 table values */
        ...
        /* Assign t0 */
        ...
    }

}