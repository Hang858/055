#include "pq_alg.h"

#include <string.h>

/* Builtins are linked in.  To add an algorithm, define its descriptor in a
 * .c file and add the symbol here; no TLS or Go code changes. */
extern const pq_alg pq_bit;
extern const pq_alg pq_kem_template;
extern const pq_alg pq_placeholder_sig;
extern const pq_alg pq_placeholder_kem;

static const pq_alg *const pq_builtin[] = {
    &pq_bit,
    &pq_kem_template,
    &pq_placeholder_sig,
    &pq_placeholder_kem,
};

#define PQ_BUILTIN_COUNT (sizeof(pq_builtin) / sizeof(pq_builtin[0]))

static const pq_alg *pq_dynamic[PQ_ALG_MAX];
static size_t pq_dynamic_count;

static int is_placeholder(const pq_alg *a) {
    return a != NULL && (a->flags & PQ_FLAG_PLACEHOLDER) != 0;
}

static int valid_alg(const pq_alg *a) {
    if (a == NULL || a->abi_version != PQ_ALG_ABI_VERSION) {
        return 0;
    }
    if (a->name == NULL || a->name[0] == '\0' || a->oid == NULL) {
        return 0;
    }
    if (a->kind != PQ_KIND_SIG && a->kind != PQ_KIND_KEM) {
        return 0;
    }
    if (is_placeholder(a)) {
        return 1;
    }
    if (a->keygen == NULL || a->pub_from_sk == NULL) {
        return 0;
    }
    if (a->kind == PQ_KIND_SIG) {
        return a->pk_len != 0 && a->sk_len != 0 && a->sig_len != 0 &&
               a->sign != NULL && a->verify != NULL;
    }
    return a->pk_len != 0 && a->sk_len != 0 && a->ct_len != 0 &&
           a->ss_len != 0 && a->encaps != NULL && a->decaps != NULL;
}

int pq_alg_available(const pq_alg *a) {
    if (!valid_alg(a) || is_placeholder(a)) {
        return 0;
    }
    return 1;
}

size_t pq_alg_count(void) {
    return PQ_BUILTIN_COUNT + pq_dynamic_count;
}

const pq_alg *pq_alg_at(size_t index) {
    if (index < PQ_BUILTIN_COUNT) {
        return pq_builtin[index];
    }
    index -= PQ_BUILTIN_COUNT;
    if (index >= pq_dynamic_count) {
        return NULL;
    }
    return pq_dynamic[index];
}

const pq_alg *pq_alg_lookup(const char *name) {
    size_t i;
    if (name == NULL) {
        return NULL;
    }
    for (i = 0; i < PQ_BUILTIN_COUNT; i++) {
        if (strcmp(pq_builtin[i]->name, name) == 0) {
            return pq_builtin[i];
        }
    }
    for (i = 0; i < pq_dynamic_count; i++) {
        if (strcmp(pq_dynamic[i]->name, name) == 0) {
            return pq_dynamic[i];
        }
    }
    return NULL;
}

const pq_alg *pq_alg_by_tls_code(uint16_t code) {
    size_t i;
    if (code == 0) {
        return NULL;
    }
    for (i = 0; i < PQ_BUILTIN_COUNT; i++) {
        if (pq_builtin[i]->kind == PQ_KIND_SIG &&
            pq_builtin[i]->tls_code == code) {
            return pq_builtin[i];
        }
    }
    for (i = 0; i < pq_dynamic_count; i++) {
        if (pq_dynamic[i]->kind == PQ_KIND_SIG &&
            pq_dynamic[i]->tls_code == code) {
            return pq_dynamic[i];
        }
    }
    return NULL;
}

int pq_alg_register(const pq_alg *alg) {
    size_t i;
    if (!valid_alg(alg)) {
        return PQ_ERR_INVALID;
    }
    if (pq_dynamic_count >= PQ_ALG_MAX) {
        return PQ_ERR_NOMEM;
    }
    for (i = 0; i < PQ_BUILTIN_COUNT; i++) {
        if (strcmp(pq_builtin[i]->name, alg->name) == 0) {
            return PQ_ERR_DUPLICATE;
        }
        if (alg->tls_code != 0 && pq_builtin[i]->tls_code == alg->tls_code) {
            return PQ_ERR_DUPLICATE;
        }
    }
    for (i = 0; i < pq_dynamic_count; i++) {
        if (strcmp(pq_dynamic[i]->name, alg->name) == 0) {
            return PQ_ERR_DUPLICATE;
        }
        if (alg->tls_code != 0 && pq_dynamic[i]->tls_code == alg->tls_code) {
            return PQ_ERR_DUPLICATE;
        }
    }
    pq_dynamic[pq_dynamic_count++] = alg;
    return PQ_OK;
}

const char *pq_status_string(int status) {
    switch (status) {
    case PQ_OK:              return "ok";
    case PQ_ERR_INVALID:     return "invalid argument";
    case PQ_ERR_BUFFER:      return "output buffer too small";
    case PQ_ERR_NOTIMPL:     return "not implemented";
    case PQ_ERR_VERIFY:      return "verification failed";
    case PQ_ERR_DUPLICATE:   return "duplicate algorithm";
    case PQ_ERR_NOMEM:       return "registry full";
    case PQ_ERR_UNSUPPORTED: return "unsupported";
    default:                 return "unknown error";
    }
}
