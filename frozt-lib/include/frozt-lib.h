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
    LIB_KEY_IMPORT_ERROR,
    LIB_SAPLING_ERROR,
} lib_error;

/* Utility */
void tss_buffer_free(tss_buffer *buf);
lib_error frozt_handle_free(Handle h);

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

/* Key Import */
lib_error frozt_key_import_part1(uint16_t identifier,
                                 uint16_t max_signers,
                                 uint16_t min_signers,
                                 const go_slice *seed,
                                 uint32_t account_index,
                                 Handle *out_secret,
                                 tss_buffer *out_package,
                                 tss_buffer *out_vk,
                                 tss_buffer *out_extras);

lib_error frozt_key_import_part3(Handle secret,
                                 const go_slice *round1_packages,
                                 const go_slice *round2_packages,
                                 const go_slice *expected_vk,
                                 tss_buffer *out_key_package,
                                 tss_buffer *out_pub_key_package);

/* Sapling */
lib_error frozt_sapling_generate_extras(tss_buffer *out_sapling_extras);

lib_error frozt_sapling_derive_keys(const go_slice *pub_key_package,
                                     const go_slice *sapling_extras,
                                     tss_buffer *out_address,
                                     tss_buffer *out_ivk,
                                     tss_buffer *out_nk);

lib_error frozt_sapling_try_decrypt_compact(const go_slice *ivk,
                                            const go_slice *cmu,
                                            const go_slice *ephemeral_key,
                                            const go_slice *ciphertext,
                                            uint64_t height,
                                            uint64_t *out_value);

lib_error frozt_sapling_decrypt_note_full(const go_slice *ivk,
                                          const go_slice *cmu,
                                          const go_slice *ephemeral_key,
                                          const go_slice *enc_ciphertext,
                                          uint64_t height,
                                          tss_buffer *out_note_data);

lib_error frozt_sapling_compute_nullifier(const go_slice *pkp_bytes,
                                           const go_slice *extras_bytes,
                                           const go_slice *note_data,
                                           uint64_t position,
                                           uint64_t height,
                                           tss_buffer *out_nullifier);

/* Commitment Tree & Witness */
lib_error frozt_sapling_tree_size(const go_slice *tree_state_hex,
                                   uint64_t *out_size);

lib_error frozt_sapling_tree_from_state(const go_slice *tree_state_hex,
                                         Handle *out_tree);

lib_error frozt_sapling_tree_append(Handle tree,
                                     const go_slice *cmu);

lib_error frozt_sapling_tree_witness(Handle tree,
                                      Handle *out_witness);

lib_error frozt_sapling_witness_append(Handle witness,
                                        const go_slice *cmu);

lib_error frozt_sapling_witness_root(Handle witness,
                                      tss_buffer *out_anchor);

lib_error frozt_sapling_witness_serialize(Handle witness,
                                           tss_buffer *out_data);

lib_error frozt_sapling_witness_deserialize(const go_slice *data,
                                             Handle *out_witness);

/* Transaction Builder (multi-input) */
lib_error frozt_tx_builder_new(const go_slice *pkp_bytes,
                                const go_slice *extras_bytes,
                                uint32_t target_height,
                                Handle *out_handle);

lib_error frozt_tx_builder_add_spend(Handle builder_handle,
                                      const go_slice *note_data,
                                      const go_slice *witness_data,
                                      tss_buffer *out_alpha);

lib_error frozt_tx_builder_add_output(Handle builder_handle,
                                       const go_slice *address,
                                       uint64_t amount);

lib_error frozt_tx_builder_build(Handle builder_handle,
                                  tss_buffer *out_sighash);

lib_error frozt_tx_builder_complete(Handle builder_handle,
                                     const go_slice *spend_auth_sigs,
                                     tss_buffer *out_raw_tx);

#endif /* _FROZT_LIB_H */
