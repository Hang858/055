/*
 * pq_alg.h - one C ABI for post-quantum signature and KEM algorithms.
 *
 * This header is the only contract between the C algorithm implementations
 * (BiT, later KEMs) and the Go/TLS layer.  Adding an algorithm must not
 * require changes in crypto/tls: add a descriptor and register it.
 *
 * ABI rules:
 *   - The caller owns every output buffer.  Callees never return malloc()ed
 *     memory and never retain input pointers.
 *   - All functions must be reentrant and thread-safe.  No mutable global
 *     state is allowed inside an algorithm.
 *   - Lengths are explicit.  A short output buffer returns PQ_ERR_BUFFER.
 *   - Keys are deterministic byte strings; pub_from_sk is mandatory for
 *     algorithms used in certificates.
 *   - Signature input is selected by pq_alg.input.  The TLS layer passes a
 *     SHA-512 digest (64 bytes) for CertificateVerify, so a TLS signature
 *     provider MUST advertise PQ_INPUT_DIGEST and must not hash again.
 */
#ifndef PQ_ALG_H
#define PQ_ALG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQ_ALG_ABI_VERSION 1u
#define PQ_ALG_MAX 64u

typedef enum {
    PQ_KIND_SIG = 1,
    PQ_KIND_KEM = 2
} pq_kind;

typedef enum {
    PQ_INPUT_MESSAGE = 0,
    PQ_INPUT_DIGEST  = 1
} pq_input;

typedef enum {
    PQ_OK               =  0,
    PQ_ERR_INVALID      = -1,
    PQ_ERR_BUFFER       = -2,
    PQ_ERR_NOTIMPL      = -3,
    PQ_ERR_VERIFY       = -4,
    PQ_ERR_DUPLICATE    = -5,
    PQ_ERR_NOMEM        = -6,
    PQ_ERR_UNSUPPORTED  = -7
} pq_status;

/* A descriptor marked PLACEHOLDER may be listed but cannot be used yet. */
#define PQ_FLAG_PLACEHOLDER 1u

typedef int (*pq_keygen_fn)(uint8_t *pk, uint8_t *sk);
typedef int (*pq_pub_from_sk_fn)(const uint8_t *sk, uint8_t *pk);

typedef int (*pq_sign_fn)(const uint8_t *sk,
                          const uint8_t *msg, size_t msg_len,
                          uint8_t *sig, size_t sig_cap);

typedef int (*pq_verify_fn)(const uint8_t *pk,
                            const uint8_t *msg, size_t msg_len,
                            const uint8_t *sig, size_t sig_len);

typedef int (*pq_encaps_fn)(const uint8_t *pk,
                            uint8_t *ct, size_t ct_cap,
                            uint8_t *ss, size_t ss_cap);

typedef int (*pq_decaps_fn)(const uint8_t *sk,
                            const uint8_t *ct, size_t ct_len,
                            uint8_t *ss, size_t ss_cap);

typedef struct pq_alg {
    uint32_t        abi_version;
    pq_kind         kind;
    pq_input        input;       /* signatures only */
    uint32_t        flags;       /* PQ_FLAG_* */

    const char     *name;        /* "BiT", "KEM-X"; stable identifier */
    const char     *oid;         /* dotted OID; certificate extension value */
    uint16_t        tls_code;    /* private SignatureScheme; 0 for KEM */
    const char     *version;     /* implementation version, free-form */

    size_t          pk_len;
    size_t          sk_len;
    size_t          sig_len;     /* signatures */
    size_t          ct_len;      /* KEM ciphertext */
    size_t          ss_len;      /* KEM shared secret */

    pq_keygen_fn      keygen;
    pq_pub_from_sk_fn pub_from_sk;
    pq_sign_fn        sign;
    pq_verify_fn      verify;
    pq_encaps_fn      encaps;
    pq_decaps_fn      decaps;
} pq_alg;

/* The single lookup entry used by Go and by C callers. */
const pq_alg *pq_alg_lookup(const char *name);
const pq_alg *pq_alg_by_tls_code(uint16_t code);
const pq_alg *pq_alg_at(size_t index);
size_t        pq_alg_count(void);
int           pq_alg_available(const pq_alg *alg);

/* Dynamic registration is for plugins loaded before serving.  It is not
 * synchronized: call it during init, never from a handshake. */
int pq_alg_register(const pq_alg *alg);

const char *pq_status_string(int status);

#ifdef __cplusplus
}
#endif

#endif /* PQ_ALG_H */
