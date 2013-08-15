#include <stdio.h>
#include <openssl/bn.h>

BIGNUM* modExpo(BIGNUM* gen, BIGNUM* expo, BIGNUM* mod, BN_CTX* ctx) {
    BIGNUM *test;
    BIGNUM *temp1,*temp2,*temp3,*one;
    test = BN_new();
    one = BN_new(); BN_one(one);
    temp1 = BN_new();
    temp2 = BN_new();
    temp3 = BN_new();
    int ret;

    for (BN_one(test); (ret = BN_is_zero(expo)) != 1; BN_rshift1(expo,expo)) {
        if (BN_is_bit_set(expo,0x1)) { // same as expo & 1
            BN_nnmod(temp1,test,mod,ctx);
            BN_nnmod(temp2,gen,mod,ctx);
            BN_mul(temp3,temp1,temp2,ctx);
            BN_nnmod(test,temp3,mod,ctx);
            // equivalent to test = ((test % mod) * (gen % mod)) % mod
        }
        // equivalent to gen = ((gen % mod) * (gen % mod)) % mod
        BN_nnmod(temp1,gen,mod,ctx);
        BN_mul(temp2,temp1,temp1,ctx);
        BN_nnmod(gen,temp2,mod,ctx);
    }
    BN_free(temp1);
    BN_free(temp2);
    BN_free(temp3);
    BN_free(one);
    return test;
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
    decrypted = modExpo(c,d,n,ctx);
    printf("the decrypted message is: %s\n",BN_bn2dec(decrypted));

    /* free all the things */
    BN_free(c);
    BN_free(d);
    BN_free(n);
    BN_free(decrypted);
    BN_CTX_free(ctx);
}
