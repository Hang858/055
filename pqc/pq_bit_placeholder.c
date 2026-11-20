/* Placeholder descriptors.  Replace this file with the real BiT adapter
 * (same symbol name pq_bit) when the C implementation arrives. */
#include "pq_alg.h"

/*
 * Placeholder descriptors for algorithms whose C implementation is not linked
 * yet.  They are visible through the registry (so configuration and tests can
 * be written now) but pq_alg_available() returns false and every operation
 * returns PQ_ERR_NOTIMPL.
 */
const pq_alg pq_bit = {
    .abi_version = PQ_ALG_ABI_VERSION,
    .kind = PQ_KIND_SIG,
    .input = PQ_INPUT_DIGEST,
    .flags = PQ_FLAG_PLACEHOLDER,
    .name = "BiT",
    .oid = "1.3.6.1.4.1.54321.22.1", /* TODO: confirm vendor OID before issue */
    .tls_code = 0xFE20u,             /* TODO: confirm private code point */
    .version = "placeholder",
};

const pq_alg pq_kem_template = {
    .abi_version = PQ_ALG_ABI_VERSION,
    .kind = PQ_KIND_KEM,
    .input = PQ_INPUT_MESSAGE,
    .flags = PQ_FLAG_PLACEHOLDER,
    .name = "KEM-TEMPLATE",
    .oid = "1.3.6.1.4.1.54321.22.2",
    .tls_code = 0,
    .version = "placeholder",
};
