/*
 * frozt-lib FFI header
 */
#ifndef _FROZT_LIB_H
#define _FROZT_LIB_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct {
    const uint8_t *ptr;
    size_t len;
    size_t cap;
} go_slice;

typedef struct {
    const uint8_t *ptr;
    size_t len;
} tss_buffer;

typedef struct {
    int32_t _0;
} Handle;

typedef enum {
    LIB_OK = 0,
    LIB_INVALID_HANDLE,
    LIB_HANDLE_IN_USE,
    LIB_INVALID_HANDLE_TYPE,
    LIB_NULL_PTR,
    LIB_INVALID_BUFFER_SIZE,
    LIB_UNKNOWN_ERROR,
    LIB_SERIALIZATION_ERROR,
    LIB_INVALID_IDENTIFIER,
    LIB_DKG_ERROR,
    LIB_SIGNING_ERROR,
    LIB_RESHARE_ERROR,
} lib_error;

/* Utility */
void tss_buffer_free(tss_buffer *buf);

/* DKG Keygen */
lib_error frozt_dkg_part1(uint16_t identifier,
                          uint16_t max_signers,
                          uint16_t min_signers,
                          Handle *out_secret,
                          tss_buffer *out_package);

lib_error frozt_dkg_part2(Handle secret,
                          const go_slice *round1_packages,
                          Handle *out_secret,
                          tss_buffer *out_packages);

lib_error frozt_dkg_part3(Handle secret,
                          const go_slice *round1_packages,
                          const go_slice *round2_packages,
                          tss_buffer *out_key_package,
                          tss_buffer *out_pub_key_package);

/* Reshare */
lib_error frozt_reshare_part1(uint16_t identifier,
                              uint16_t max_signers,
                              uint16_t min_signers,
                              const go_slice *old_key_package,
                              const go_slice *old_identifiers,
                              Handle *out_secret,
                              tss_buffer *out_package);

lib_error frozt_reshare_part3(Handle secret,
                              const go_slice *round1_packages,
                              const go_slice *round2_packages,
                              const go_slice *expected_vk,
                              tss_buffer *out_key_package,
                              tss_buffer *out_pub_key_package);

/* Signing */
lib_error frozt_sign_commit(const go_slice *key_package,
                            Handle *out_nonces,
                            tss_buffer *out_commitments);

lib_error frozt_sign_new_package(const go_slice *message,
                                 const go_slice *commitments_map,
                                 const go_slice *pub_key_package,
                                 tss_buffer *out_signing_package,
                                 tss_buffer *out_randomizer_seed);

lib_error frozt_sign(const go_slice *signing_package,
                     Handle nonces,
                     const go_slice *key_package,
                     const go_slice *randomizer_seed,
                     tss_buffer *out_share);

lib_error frozt_sign_aggregate(const go_slice *signing_package,
                               const go_slice *shares_map,
                               const go_slice *pub_key_package,
                               const go_slice *randomizer_seed,
                               tss_buffer *out_signature);

/* Identifier encoding */
lib_error frozt_encode_identifier(uint16_t id,
                                  tss_buffer *out_bytes);

lib_error frozt_decode_identifier(const go_slice *id_bytes,
                                  uint16_t *out_id);

/* Key inspection */
lib_error frozt_keypackage_identifier(const go_slice *key_package,
                                      uint16_t *out_id);

lib_error frozt_pubkeypackage_verifying_key(const go_slice *pub_key_package,
                                            tss_buffer *out_key);

/* Address derivation */
lib_error frozt_derive_z_address(const go_slice *pub_key_package,
                                 tss_buffer *out_address);

lib_error frozt_derive_t_address(const go_slice *pubkey_hash,
                                 tss_buffer *out_address);

lib_error frozt_pubkey_to_t_address(const go_slice *pub_key_package,
                                    tss_buffer *out_address);

#endif /* _FROZT_LIB_H */
