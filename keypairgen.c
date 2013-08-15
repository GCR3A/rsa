#include <stdio.h>
#include <openssl/dh.h>
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
    return test;
}

int main() {
    BIGNUM *p, *q, *n, *e, *d, *phiN, *GCD, *pMinus, *qMinus;
    BN_CTX *ctx;

    /* initialize bignums */
    p = BN_new();
    q = BN_new();
    n = BN_new();
    e = BN_new();
    d = BN_new();
    phiN = BN_new();
    GCD = BN_new();
    pMinus = BN_new();
    qMinus = BN_new();
    ctx = BN_CTX_new();

    /* set e to 65537 */
    BN_set_word(e,65537);

    /* generate primes that satisfy gcd( (p-1)(q-1), 65537 ) == 1 and high order bits are set */
    do {
        BN_generate_prime(p,512,1,NULL,NULL,NULL,NULL);
        BN_generate_prime(q,512,1,NULL,NULL,NULL,NULL);
        BN_sub(pMinus,p,BN_value_one());
        BN_sub(qMinus,q,BN_value_one());
        BN_mul(phiN,pMinus,qMinus,ctx);
        BN_gcd(GCD,phiN,e,ctx);
    } while(BN_is_bit_set(p,512) && BN_is_bit_set(q,512) && BN_is_one(GCD));

    /* compute n = pq */
    BN_mul(n,p,q,ctx);

    /* now find d using Euclid's algorithm */
}
