/*
 * light-lattice adapters for the pq_alg C ABI.
 *
 * The vendor algorithms are built as separate shared libraries
 * (pqc/vendor/build.sh).  This file only loads them with dlopen and adapts
 * their NGCC-style API to pq_alg.  Replacing an algorithm therefore means
 * replacing one .so, not editing TLS.
 */
#define _GNU_SOURCE
#include "pq_alg.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <sys/random.h>
#endif

#define BIT128_PK 1264
#define BIT128_SK 1696
#define BIT128_SIG 1440
#define BIT256_PK 2528
#define BIT256_SK 3392
#define BIT256_SIG 2976
#define BIT512_PK 5824
#define BIT512_SK 7488
#define BIT512_SIG 7474

#define POLARLAC_REJECT_SEED 16

typedef int (*bit_sig_fn)(unsigned char *, unsigned long long,
                          unsigned char *, unsigned long long);
typedef int (*kem_keygen_fn)(unsigned char *, unsigned long long *,
                             unsigned char *, unsigned long long *);
typedef int (*kem_enc_fn)(unsigned char *, unsigned long long,
                          unsigned char *, unsigned long long *,
                          unsigned char *, unsigned long long *);
typedef int (*kem_dec_fn)(unsigned char *, unsigned long long,
                          unsigned char *, unsigned long long,
                          unsigned char *, unsigned long long *);

typedef struct {
    pthread_mutex_t load_lock;
    pthread_mutex_t op_lock;
    void *handle;
    void *drng;
    int (*init_random)(void *, const unsigned char *, unsigned long long);
    int (*get_random)(void *, unsigned char *, unsigned long long);
    int (*keygen)(unsigned char *, unsigned long long *,
                  unsigned char *, unsigned long long *);
    int (*sign)(unsigned char *, unsigned long long,
                unsigned char *, unsigned long long,
                unsigned char *, unsigned long long *);
    int (*verify)(unsigned char *, unsigned long long,
                  unsigned char *, unsigned long long,
                  unsigned char *, unsigned long long);
    int (*enc)(unsigned char *, unsigned long long,
               unsigned char *, unsigned long long *,
               unsigned char *, unsigned long long *);
    int (*dec)(unsigned char *, unsigned long long,
               unsigned char *, unsigned long long,
               unsigned char *, unsigned long long *);
    int loaded;
    int failed;
} ll_api;

#define LL_API_INIT {PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, \
                     NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, 0}

static ll_api bit128_api = LL_API_INIT;
static ll_api bit256_api = LL_API_INIT;
static ll_api bit512_api = LL_API_INIT;
static ll_api polarlac128_api = LL_API_INIT;
static ll_api polarlac256_api = LL_API_INIT;
static ll_api polarlac512_api = LL_API_INIT;
static ll_api polarlac_light_api = LL_API_INIT;
static ll_api polarlac_512star_api = LL_API_INIT;

static int os_random(unsigned char *out, size_t len) {
#if defined(__linux__)
    size_t off = 0;
    while (off < len) {
        ssize_t n = getrandom(out + off, len - off, 0);
        if (n <= 0) break;
        off += (size_t)n;
    }
    if (off == len) return 0;
#endif
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL) return -1;
    size_t n = fread(out, 1, len, f);
    fclose(f);
    return n == len ? 0 : -1;
}

static void *ll_sym(void *h, const char *name) {
    void *p = dlsym(h, name);
    return p;
}

static int ll_load(ll_api *api, const char *so_name, int kind) {
    pthread_mutex_lock(&api->load_lock);
    if (api->loaded || api->failed) {
        int ok = api->loaded;
        pthread_mutex_unlock(&api->load_lock);
        return ok;
    }
    const char *dir = getenv("LIGHTLATTICE_LIBDIR");
    if (dir == NULL || dir[0] == '\0') dir = ".";
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, so_name);
    void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (h == NULL) {
        fprintf(stderr, "light-lattice: dlopen %s failed: %s\n", path, dlerror());
        api->failed = 1;
        pthread_mutex_unlock(&api->load_lock);
        return 0;
    }
    api->handle = h;
    api->drng = ll_sym(h, "drng_algorithm");
    api->init_random = (int (*)(void *, const unsigned char *, unsigned long long))ll_sym(h, "init_random_number");
    api->get_random = (int (*)(void *, unsigned char *, unsigned long long))ll_sym(h, "get_random_number");
    if (kind == PQ_KIND_SIG) {
        api->keygen = (int (*)(unsigned char *, unsigned long long *, unsigned char *, unsigned long long *))ll_sym(h, "sig_keygen");
        api->sign = (int (*)(unsigned char *, unsigned long long, unsigned char *, unsigned long long, unsigned char *, unsigned long long *))ll_sym(h, "sig_sign");
        api->verify = (int (*)(unsigned char *, unsigned long long, unsigned char *, unsigned long long, unsigned char *, unsigned long long))ll_sym(h, "sig_verify");
    } else {
        api->keygen = (int (*)(unsigned char *, unsigned long long *, unsigned char *, unsigned long long *))ll_sym(h, "kem_keygen");
        api->enc = (int (*)(unsigned char *, unsigned long long, unsigned char *, unsigned long long *, unsigned char *, unsigned long long *))ll_sym(h, "kem_enc");
        api->dec = (int (*)(unsigned char *, unsigned long long, unsigned char *, unsigned long long, unsigned char *, unsigned long long *))ll_sym(h, "kem_dec");
    }
    if (api->drng == NULL || api->init_random == NULL || api->keygen == NULL ||
        (kind == PQ_KIND_SIG && (api->sign == NULL || api->verify == NULL)) ||
        (kind == PQ_KIND_KEM && (api->enc == NULL || api->dec == NULL))) {
        fprintf(stderr, "light-lattice: missing symbols in %s\n", path);
        api->failed = 1;
        pthread_mutex_unlock(&api->load_lock);
        return 0;
    }
    unsigned char seed[64];
    if (os_random(seed, sizeof(seed)) != 0 ||
        api->init_random(api->drng, seed, sizeof(seed)) != 0) {
        fprintf(stderr, "light-lattice: DRNG init failed for %s\n", path);
        api->failed = 1;
        pthread_mutex_unlock(&api->load_lock);
        return 0;
    }
    api->loaded = 1;
    pthread_mutex_unlock(&api->load_lock);
    return 1;
}

static int ll_lock(ll_api *api, const char *so_name, int kind) {
    if (!ll_load(api, so_name, kind)) return 0;
    pthread_mutex_lock(&api->op_lock);
    return 1;
}

static void ll_unlock(ll_api *api) {
    pthread_mutex_unlock(&api->op_lock);
}

static int bit_keygen(ll_api *api, const char *so, unsigned char *pk, unsigned char *sk) {
    if (!ll_lock(api, so, PQ_KIND_SIG)) return PQ_ERR_NOTIMPL;
    unsigned long long pk_len = 0, sk_len = 0;
    int st = api->keygen(pk, &pk_len, sk, &sk_len);
    ll_unlock(api);
    return st == 0 ? PQ_OK : PQ_ERR_INVALID;
}

#define BIT_PK(api) ((api) == &bit128_api ? BIT128_PK : (api) == &bit256_api ? BIT256_PK : BIT512_PK)
#define BIT_SK(api) ((api) == &bit128_api ? BIT128_SK : (api) == &bit256_api ? BIT256_SK : BIT512_SK)

static int bit_sign(ll_api *api, const char *so, const unsigned char *sk,
                    const unsigned char *msg, size_t msg_len,
                    unsigned char *sig, size_t sig_cap) {
    size_t need = api == &bit128_api ? BIT128_SIG : api == &bit256_api ? BIT256_SIG : BIT512_SIG;
    if (sig_cap < need) return PQ_ERR_BUFFER;
    if (!ll_lock(api, so, PQ_KIND_SIG)) return PQ_ERR_NOTIMPL;
    unsigned long long sig_len = 0;
    int st = api->sign((unsigned char *)sk, BIT_SK(api),
                       (unsigned char *)msg, msg_len, sig, &sig_len);
    ll_unlock(api);
    return st == 0 ? PQ_OK : PQ_ERR_VERIFY;
}

static int bit_verify(ll_api *api, const char *so, const unsigned char *pk,
                      const unsigned char *msg, size_t msg_len,
                      const unsigned char *sig, size_t sig_len) {
    if (!ll_lock(api, so, PQ_KIND_SIG)) return PQ_ERR_NOTIMPL;
    int st = api->verify((unsigned char *)pk, BIT_PK(api),
                         (unsigned char *)sig, sig_len,
                         (unsigned char *)msg, msg_len);
    ll_unlock(api);
    return st == 0 ? PQ_OK : PQ_ERR_VERIFY;
}

/* The wrappers below need the compile-time sizes; macros expand per level. */
static int bit128_keygen(unsigned char *pk, unsigned char *sk) { return bit_keygen(&bit128_api, "libbit-128.so", pk, sk); }
static int bit128_sign(const unsigned char *sk, const unsigned char *m, size_t ml, unsigned char *sig, size_t cap) { return bit_sign(&bit128_api, "libbit-128.so", sk, m, ml, sig, cap); }
static int bit128_verify(const unsigned char *pk, const unsigned char *m, size_t ml, const unsigned char *sig, size_t sl) { return bit_verify(&bit128_api, "libbit-128.so", pk, m, ml, sig, sl); }
static int bit256_keygen(unsigned char *pk, unsigned char *sk) { return bit_keygen(&bit256_api, "libbit-256.so", pk, sk); }
static int bit256_sign(const unsigned char *sk, const unsigned char *m, size_t ml, unsigned char *sig, size_t cap) { return bit_sign(&bit256_api, "libbit-256.so", sk, m, ml, sig, cap); }
static int bit256_verify(const unsigned char *pk, const unsigned char *m, size_t ml, const unsigned char *sig, size_t sl) { return bit_verify(&bit256_api, "libbit-256.so", pk, m, ml, sig, sl); }
static int bit512_keygen(unsigned char *pk, unsigned char *sk) { return bit_keygen(&bit512_api, "libbit-512.so", pk, sk); }
static int bit512_sign(const unsigned char *sk, const unsigned char *m, size_t ml, unsigned char *sig, size_t cap) { return bit_sign(&bit512_api, "libbit-512.so", sk, m, ml, sig, cap); }
static int bit512_verify(const unsigned char *pk, const unsigned char *m, size_t ml, const unsigned char *sig, size_t sl) { return bit_verify(&bit512_api, "libbit-512.so", pk, m, ml, sig, sl); }

static int polarlac_keygen(ll_api *api, const char *so, unsigned char *pk, unsigned char *sk) {
    if (!ll_lock(api, so, PQ_KIND_KEM)) return PQ_ERR_NOTIMPL;
    unsigned long long pk_len = 0, sk_len = 0;
    int st = api->keygen(pk, &pk_len, sk, &sk_len);
    ll_unlock(api);
    return st == 0 ? PQ_OK : PQ_ERR_INVALID;
}

static int polarlac_pub_from_sk(const unsigned char *sk, unsigned char *pk, size_t pk_len, size_t sk_len) {
    size_t offset = sk_len - pk_len - POLARLAC_REJECT_SEED;
    if (sk_len < pk_len + POLARLAC_REJECT_SEED) return PQ_ERR_INVALID;
    memcpy(pk, sk + offset, pk_len);
    return PQ_OK;
}

#define POLARLAC_PK(api) ((api) == &polarlac128_api || (api) == &polarlac_light_api ? 530 : \
                          (api) == &polarlac256_api ? 1060 : \
                          (api) == &polarlac512_api ? 2116 : 2522)
#define POLARLAC_SK(api) ((api) == &polarlac128_api || (api) == &polarlac_light_api ? 1570 : \
                          (api) == &polarlac256_api ? 3140 : \
                          (api) == &polarlac512_api ? 6276 : 6682)

static int polarlac_enc(ll_api *api, const char *so, const unsigned char *pk,
                        unsigned char *ct, size_t ct_cap,
                        unsigned char *ss, size_t ss_cap) {
    if (!ll_lock(api, so, PQ_KIND_KEM)) return PQ_ERR_NOTIMPL;
    unsigned long long ct_len = 0, ss_len = 0;
    int st = api->enc((unsigned char *)pk, POLARLAC_PK(api),
                      ss, &ss_len, ct, &ct_len);
    ll_unlock(api);
    if (st != 0 || ct_len > ct_cap || ss_len > ss_cap) return PQ_ERR_INVALID;
    return PQ_OK;
}

static int polarlac_dec(ll_api *api, const char *so, const unsigned char *sk,
                        const unsigned char *ct, size_t ct_len,
                        unsigned char *ss, size_t ss_cap) {
    if (!ll_lock(api, so, PQ_KIND_KEM)) return PQ_ERR_NOTIMPL;
    unsigned long long ss_len = 0;
    int st = api->dec((unsigned char *)sk, POLARLAC_SK(api),
                      (unsigned char *)ct, ct_len, ss, &ss_len);
    ll_unlock(api);
    if (st != 0 || ss_len > ss_cap) return PQ_ERR_INVALID;
    return PQ_OK;
}

#define POLARLAC_WRAPPERS(prefix, api, so, pklen, sklen, ctlen, sslen) \
static int prefix##_keygen(unsigned char *pk, unsigned char *sk) { return polarlac_keygen(&api, so, pk, sk); } \
static int prefix##_pub(const unsigned char *sk, unsigned char *pk) { return polarlac_pub_from_sk(sk, pk, pklen, sklen); } \
static int prefix##_enc(const unsigned char *pk, unsigned char *ct, size_t ctcap, unsigned char *ss, size_t sscap) { return polarlac_enc(&api, so, pk, ct, ctcap, ss, sscap); } \
static int prefix##_dec(const unsigned char *sk, const unsigned char *ct, size_t ct_bytes, unsigned char *ss, size_t sscap) { return polarlac_dec(&api, so, sk, ct, ct_bytes, ss, sscap); }

POLARLAC_WRAPPERS(polarlac128, polarlac128_api, "libpolarlac-128.so", 530, 1570, 640, 16)
POLARLAC_WRAPPERS(polarlac256, polarlac256_api, "libpolarlac-256.so", 1060, 3140, 1280, 32)
POLARLAC_WRAPPERS(polarlac512, polarlac512_api, "libpolarlac-512.so", 2116, 6276, 2560, 64)
POLARLAC_WRAPPERS(polarlac_light, polarlac_light_api, "libpolarlac-Light.so", 530, 1570, 608, 16)
POLARLAC_WRAPPERS(polarlac_512star, polarlac_512star_api, "libpolarlac-512-Star.so", 2522, 6682, 2970, 64)

const pq_alg pq_bit128 = {
    .abi_version = PQ_ALG_ABI_VERSION, .kind = PQ_KIND_SIG, .input = PQ_INPUT_DIGEST,
    .flags = 0, .name = "BiT-128", .oid = "1.3.6.1.4.1.54321.30.1", .tls_code = 0xFE30,
    .version = "BiT v2.1", .pk_len = BIT128_PK, .sk_len = BIT128_SK, .sig_len = BIT128_SIG,
    .keygen = bit128_keygen, .sign = bit128_sign, .verify = bit128_verify,
};
const pq_alg pq_bit256 = {
    .abi_version = PQ_ALG_ABI_VERSION, .kind = PQ_KIND_SIG, .input = PQ_INPUT_DIGEST,
    .flags = 0, .name = "BiT-256", .oid = "1.3.6.1.4.1.54321.30.2", .tls_code = 0xFE31,
    .version = "BiT v2.1", .pk_len = BIT256_PK, .sk_len = BIT256_SK, .sig_len = BIT256_SIG,
    .keygen = bit256_keygen, .sign = bit256_sign, .verify = bit256_verify,
};
const pq_alg pq_bit512 = {
    .abi_version = PQ_ALG_ABI_VERSION, .kind = PQ_KIND_SIG, .input = PQ_INPUT_DIGEST,
    .flags = 0, .name = "BiT-512", .oid = "1.3.6.1.4.1.54321.30.3", .tls_code = 0xFE32,
    .version = "BiT v2.1", .pk_len = BIT512_PK, .sk_len = BIT512_SK, .sig_len = BIT512_SIG,
    .keygen = bit512_keygen, .sign = bit512_sign, .verify = bit512_verify,
};

#define POLARLAC_DESC(sym, str, oidv, pkv, skv, ctv, ssv, kfn, pfn, efn, dfn) \
const pq_alg sym = { \
    .abi_version = PQ_ALG_ABI_VERSION, .kind = PQ_KIND_KEM, .input = PQ_INPUT_MESSAGE, \
    .flags = 0, .name = str, .oid = oidv, .tls_code = 0, .version = "PolarLAC v1.0", \
    .pk_len = pkv, .sk_len = skv, .ct_len = ctv, .ss_len = ssv, \
    .keygen = kfn, .pub_from_sk = pfn, .encaps = efn, .decaps = dfn, \
}
POLARLAC_DESC(polarlac128, "POLARLAC-128", "1.3.6.1.4.1.54321.31.1", 530, 1570, 640, 16, polarlac128_keygen, polarlac128_pub, polarlac128_enc, polarlac128_dec);
POLARLAC_DESC(polarlac256, "POLARLAC-256", "1.3.6.1.4.1.54321.31.2", 1060, 3140, 1280, 32, polarlac256_keygen, polarlac256_pub, polarlac256_enc, polarlac256_dec);
POLARLAC_DESC(polarlac512, "POLARLAC-512", "1.3.6.1.4.1.54321.31.3", 2116, 6276, 2560, 64, polarlac512_keygen, polarlac512_pub, polarlac512_enc, polarlac512_dec);
POLARLAC_DESC(polarlac_light, "POLARLAC-Light", "1.3.6.1.4.1.54321.31.4", 530, 1570, 608, 16, polarlac_light_keygen, polarlac_light_pub, polarlac_light_enc, polarlac_light_dec);
POLARLAC_DESC(polarlac_512star, "POLARLAC-512-Star", "1.3.6.1.4.1.54321.31.5", 2522, 6682, 2970, 64, polarlac_512star_keygen, polarlac_512star_pub, polarlac_512star_enc, polarlac_512star_dec);
