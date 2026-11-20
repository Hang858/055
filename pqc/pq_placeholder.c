/*
 * Toy algorithms used only to exercise the registry, cgo bridge and tests.
 * They are NOT cryptographic and must never be enabled in a real TLS profile.
 */
#include "pq_alg.h"

#include <string.h>

#define TOY_PK_LEN 32u
#define TOY_SK_LEN 32u
#define TOY_SIG_LEN 64u
#define TOY_CT_LEN 32u
#define TOY_SS_LEN 32u

static void toy_hash(const uint8_t *a, size_t alen,
                     const uint8_t *b, size_t blen,
                     uint8_t out[32]) {
    uint64_t h = 1469598103934665603ULL;
    size_t i;
    for (i = 0; i < alen; i++) {
        h = (h ^ a[i]) * 1099511628211ULL;
    }
    for (i = 0; i < blen; i++) {
        h = (h ^ b[i]) * 1099511628211ULL;
    }
    for (i = 0; i < 32; i++) {
        h ^= h >> 33;
        h *= 0xff51afd7ed558ccdULL;
        h ^= h >> 33;
        out[i] = (uint8_t)(h >> (8 * (i % 8)));
    }
}

static int toy_keygen(uint8_t *pk, uint8_t *sk) {
    size_t i;
    if (pk == NULL || sk == NULL) {
        return PQ_ERR_INVALID;
    }
    for (i = 0; i < TOY_PK_LEN; i++) {
        pk[i] = (uint8_t)(0x11u + 7u * i);
        sk[i] = pk[i];
    }
    return PQ_OK;
}

static int toy_pub_from_sk(const uint8_t *sk, uint8_t *pk) {
    if (sk == NULL || pk == NULL) {
        return PQ_ERR_INVALID;
    }
    memcpy(pk, sk, TOY_PK_LEN);
    return PQ_OK;
}

static int toy_sign(const uint8_t *sk,
                    const uint8_t *msg, size_t msg_len,
                    uint8_t *sig, size_t sig_cap) {
    uint8_t h[32];
    size_t i;
    if (sk == NULL || (msg == NULL && msg_len != 0) || sig == NULL) {
        return PQ_ERR_INVALID;
    }
    if (sig_cap < TOY_SIG_LEN) {
        return PQ_ERR_BUFFER;
    }
    toy_hash(sk, TOY_SK_LEN, msg, msg_len, h);
    for (i = 0; i < TOY_SIG_LEN; i++) {
        sig[i] = (uint8_t)(h[i % 32] ^ sk[i % 32] ^ 0x5au);
    }
    return PQ_OK;
}

static int toy_verify(const uint8_t *pk,
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t *sig, size_t sig_len) {
    uint8_t h[32];
    uint8_t diff = 0;
    size_t i;
    if (pk == NULL || (msg == NULL && msg_len != 0) || sig == NULL) {
        return PQ_ERR_INVALID;
    }
    if (sig_len != TOY_SIG_LEN) {
        return PQ_ERR_VERIFY;
    }
    toy_hash(pk, TOY_PK_LEN, msg, msg_len, h);
    for (i = 0; i < TOY_SIG_LEN; i++) {
        uint8_t want = (uint8_t)(h[i % 32] ^ pk[i % 32] ^ 0x5au);
        diff |= (uint8_t)(want ^ sig[i]);
    }
    return diff == 0 ? PQ_OK : PQ_ERR_VERIFY;
}

static int toy_encaps(const uint8_t *pk,
                      uint8_t *ct, size_t ct_cap,
                      uint8_t *ss, size_t ss_cap) {
    size_t i;
    if (pk == NULL || ct == NULL || ss == NULL) {
        return PQ_ERR_INVALID;
    }
    if (ct_cap < TOY_CT_LEN || ss_cap < TOY_SS_LEN) {
        return PQ_ERR_BUFFER;
    }
    for (i = 0; i < TOY_CT_LEN; i++) {
        ct[i] = (uint8_t)(pk[i] ^ 0xa7u);
    }
    toy_hash(pk, TOY_PK_LEN, ct, TOY_CT_LEN, ss);
    return PQ_OK;
}

static int toy_decaps(const uint8_t *sk,
                      const uint8_t *ct, size_t ct_len,
                      uint8_t *ss, size_t ss_cap) {
    if (sk == NULL || ct == NULL || ss == NULL) {
        return PQ_ERR_INVALID;
    }
    if (ct_len != TOY_CT_LEN || ss_cap < TOY_SS_LEN) {
        return PQ_ERR_VERIFY;
    }
    toy_hash(sk, TOY_SK_LEN, ct, TOY_CT_LEN, ss);
    return PQ_OK;
}

const pq_alg pq_placeholder_sig = {
    .abi_version = PQ_ALG_ABI_VERSION,
    .kind = PQ_KIND_SIG,
    .input = PQ_INPUT_DIGEST,
    .flags = 0,
    .name = "PLACEHOLDER-SIG",
    .oid = "1.3.6.1.4.1.54321.99.1",
    .tls_code = 0xFE7Fu,
    .version = "toy-1",
    .pk_len = TOY_PK_LEN,
    .sk_len = TOY_SK_LEN,
    .sig_len = TOY_SIG_LEN,
    .keygen = toy_keygen,
    .pub_from_sk = toy_pub_from_sk,
    .sign = toy_sign,
    .verify = toy_verify,
};

const pq_alg pq_placeholder_kem = {
    .abi_version = PQ_ALG_ABI_VERSION,
    .kind = PQ_KIND_KEM,
    .input = PQ_INPUT_MESSAGE,
    .flags = 0,
    .name = "PLACEHOLDER-KEM",
    .oid = "1.3.6.1.4.1.54321.99.2",
    .tls_code = 0,
    .version = "toy-1",
    .pk_len = TOY_PK_LEN,
    .sk_len = TOY_SK_LEN,
    .ct_len = TOY_CT_LEN,
    .ss_len = TOY_SS_LEN,
    .keygen = toy_keygen,
    .pub_from_sk = toy_pub_from_sk,
    .encaps = toy_encaps,
    .decaps = toy_decaps,
};
