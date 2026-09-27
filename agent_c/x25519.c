/* RFC 7748 X25519. Field arithmetic from TweetNaCl (public domain). */
#include <stdint.h>
#include <string.h>

typedef int64_t gf[16];

static void car(gf o) {
    int i;
    int64_t c;
    for (i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void sel(gf p, gf q, int b) {
    int64_t t, i, c = ~(b - 1);
    for (i = 0; i < 16; i++) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack(unsigned char *o, gf n) {
    int i, j, b;
    gf m, t;
    memcpy(t, n, sizeof(gf));
    car(t); car(t); car(t);
    for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) {
        o[2 * i] = t[i] & 0xff;
        o[2 * i + 1] = t[i] >> 8;
    }
}

static void unpack(gf o, const unsigned char *n) {
    int i;
    for (i = 0; i < 16; i++) o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void A(gf o, gf a, gf b) { int i; for (i = 0; i < 16; i++) o[i] = a[i] + b[i]; }
static void Z(gf o, gf a, gf b) { int i; for (i = 0; i < 16; i++) o[i] = a[i] - b[i]; }
static void M(gf o, gf a, gf b) {
    int64_t t[31];
    int i, j;
    for (i = 0; i < 31; i++) t[i] = 0;
    for (i = 0; i < 16; i++) for (j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
    for (i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
    for (i = 0; i < 16; i++) o[i] = t[i];
    car(o); car(o);
}
static void S(gf o, gf a) { M(o, a, a); }
static void inv(gf o, gf i) {
    gf c;
    int a;
    memcpy(c, i, sizeof(gf));
    for (a = 253; a >= 0; a--) {
        S(c, c);
        if (a != 2 && a != 4) M(c, c, i);
    }
    memcpy(o, c, sizeof(gf));
}

void x25519(unsigned char *q, const unsigned char *n, const unsigned char *p) {
    unsigned char z[32];
    int64_t r;
    int i;
    gf x, a, b, c, d, e, f;
    memcpy(z, n, 32);
    z[31] = (z[31] & 127) | 64;
    z[0] &= 248;
    unpack(x, p);
    for (i = 0; i < 16; i++) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for (i = 254; i >= 0; i--) {
        r = (z[i >> 3] >> (i & 7)) & 1;
        sel(a, b, r);
        sel(c, d, r);
        A(e, a, c);
        Z(a, a, c);
        A(c, b, d);
        Z(b, b, d);
        S(d, e);
        S(f, a);
        M(a, c, a);
        M(c, b, e);
        A(e, a, c);
        Z(a, a, c);
        S(b, a);
        Z(c, d, f);
        M(a, c, (gf){0xdb41, 1});
        A(a, a, d);
        M(c, c, a);
        M(a, d, f);
        M(d, b, x);
        S(b, e);
        sel(a, b, r);
        sel(c, d, r);
    }
    inv(c, c);
    M(a, a, c);
    pack(q, a);
}

void x25519_base(unsigned char *q, const unsigned char *n) {
    static const unsigned char base[32] = {9};
    x25519(q, n, base);
}
