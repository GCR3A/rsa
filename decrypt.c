#include <stdio.h>
#include <openssl/bn.h>

void mod_expo(BIGNUM* base, BIGNUM* expo, BIGNUM* mod, BN_CTX* ctx, BIGNUM* retVal) {
    BIGNUM* one;
    one = BN_new(); BN_one(one);
    BIGNUM* temp;
    temp = BN_new();
    BIGNUM* two;
    two = BN_new();
    BN_set_word(two,2);

    while (!BN_is_zero(expo)) {
        BN_nnmod(temp,expo,two,ctx);
        if (!BN_is_zero(temp)) {
            BN_mul(temp,one,base,ctx);
            BN_nnmod(one,temp,mod,ctx);
        }
        BN_mul(temp,base,base,ctx);
        BN_nnmod(base,temp,mod,ctx);
        BN_rshift(expo,expo,1);
    }

    BN_nnmod(one,one,mod,ctx);
    BN_copy(retVal,one);
    BN_free(one);
    BN_free(two);
    BN_free(temp);
}

int main(int argc, char* argv[]) {
    // arg1 should be c
    // arg2 should be d
    // arg3 should be n
    BIGNUM *c, *d, *n;
    c = BN_new();
    d = BN_new();
    n = BN_new();

    BN_CTX *ctx;
    ctx = BN_CTX_new();

    BN_dec2bn(&c,argv[1]);
    BN_dec2bn(&d,argv[2]);
    BN_dec2bn(&n,argv[3]);

    BIGNUM *decrypted;
    decrypted = BN_new();
    mod_expo(c,d,n,ctx,decrypted);
    printf("the decrypted message is: %s\n",BN_bn2dec(decrypted));

    /* free all the things */
    BN_free(c);
    BN_free(d);
    BN_free(n);
    BN_free(decrypted);
    BN_CTX_free(ctx);
}
