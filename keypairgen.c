#include <stdio.h>
#include <openssl/bn.h>

/**
 * follows format ax+by = gcd(a,b)
 */
int bignum_gcd(BIGNUM* a, BIGNUM* b, BIGNUM* gcd, BIGNUM* x, BIGNUM* y, BN_CTX* ctx) {
    BIGNUM *lastx, *lasty, *temp, *temp1, *temp2, *temp3, *q, *res1, *res2;
    lastx = BN_new();
    lasty = BN_new();
    q = BN_new();
    temp1 = BN_new();
    temp2 = BN_new();
    temp3 = BN_new();
    res1 = BN_new();
    res2 = BN_new();
    int switched = 0;
    if (BN_cmp(a,b) == -1) { // a < b
        temp = a;
        a = b;
        b = temp;
        switched = 1;
    }
    BN_zero(x);
    BN_one(y);
    BN_one(lastx);
    BN_zero(lasty);
    while (!BN_is_zero(b)) {
        BN_div(q,temp1,a,b,ctx);
        BN_copy(a,b); // to, from
        BN_copy(b,temp1);

        BN_copy(temp2,x);
        BN_mul(res2,q,x,ctx);
        BN_sub(res1,lastx,res2);
        BN_copy(x,res1);
        BN_copy(lastx,temp2);

        BN_copy(temp3,y);
        BN_mul(res2,q,y,ctx);
        BN_sub(res1,lasty,res2);
        BN_copy(y,res1);
        BN_copy(lasty,temp3);
    }

    /* prepare for return */
    BN_copy(gcd,a);
    BN_copy(x,lastx);
    BN_copy(y,lasty);

    /* free all the things */
    BN_free(lastx);
    BN_free(lasty);
    BN_free(q);
    BN_free(temp1);
    BN_free(temp2);
    BN_free(temp3);
    BN_free(res1);
    BN_free(res2);

    return switched;
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
        // bc i have /dev/urandom openssl takes care of seeding
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
    BIGNUM *x, *y;
    x = BN_new(); y = BN_new();
    // format is phiN*x + e*y == gcd(phiN,e). d will be y
    // because the function switches a and b iff a < b we worry
    // about whether x and y will correspond to the same thing 
    // on return. switched var takes care of that for us. if
    // switched is 1 then x will be d instead of y
    int switched = bignum_gcd(phiN,e,GCD,x,y,ctx);
    /*if (switched) {
        // use x for d
        BN_copy(d,x);
    }
    else
        BN_copy(d,y);
*/
    /* print all the things!! */
    printf("p: %s\n",BN_bn2dec(p));
    printf("q: %s\n\n",BN_bn2dec(q));
    printf("n: %s\n",BN_bn2dec(n));
    printf("phi(n): %s\n\n",BN_bn2dec(phiN));
    printf("e: %s\n",BN_bn2dec(e));
    printf("x: %s\n",BN_bn2dec(x));
    printf("y: %s\n",BN_bn2dec(y));
    printf("the positive one is d\n");
    printf("gcd(phi(n),e): %s\n\n",BN_bn2dec(GCD));

    /* free all the things!! */
    BN_free(x);
    BN_free(y);
    BN_free(p);
    BN_free(q);
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(phiN);
    BN_free(GCD);
    BN_free(pMinus);
    BN_free(qMinus);
    BN_CTX_free(ctx);
}
