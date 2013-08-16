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
    // arg1 should be m
    // arg2 should be e
    // arg3 should be n
    BIGNUM *m, *e, *n;
    m = BN_new();
    e = BN_new();
    n = BN_new();

    BN_CTX *ctx;
    ctx = BN_CTX_new();

    BN_dec2bn(&m,argv[1]);
    BN_dec2bn(&e,argv[2]);
    BN_dec2bn(&n,argv[3]);

    if (BN_cmp(m,n) != -1)
        printf("m is not smaller than n\n");
    printf("m is: %s\n",BN_bn2dec(m));
    printf("e is: %s\n",BN_bn2dec(e));
    printf("n is: %s\n\n\n",BN_bn2dec(n));
    BIGNUM *encrypted;
    encrypted = BN_new();
    mod_expo(m,e,n,ctx,encrypted);
    //BN_mod_exp(encrypted,m,e,n,ctx);
    printf("the encrypted message is: %s\n",BN_bn2dec(encrypted));

    /* free all the things */
    BN_free(m);
    BN_free(e);
    BN_free(n);
    BN_free(encrypted);
    BN_CTX_free(ctx);
}
