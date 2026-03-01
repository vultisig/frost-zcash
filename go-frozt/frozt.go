package frozt

/*
#include "includes/frozt-lib.h"
#include <stdlib.h>
*/
import "C"

import (
	"runtime"
	"unsafe"
)

type Handle int32

type DkgSecretHandle Handle
type NoncesHandle Handle
type TreeHandle Handle
type WitnessHandle Handle
type TxBuilderHandle Handle

func (h DkgSecretHandle) Close() error { return HandleFree(Handle(h)) }
func (h NoncesHandle) Close() error    { return HandleFree(Handle(h)) }
func (h TreeHandle) Close() error      { return HandleFree(Handle(h)) }
func (h WitnessHandle) Close() error   { return HandleFree(Handle(h)) }
func (h TxBuilderHandle) Close() error { return HandleFree(Handle(h)) }

func cHandle(h Handle) C.Handle {
	return C.Handle{_0: C.int32_t(h)}
}

// cGoSlice reinterprets a Go []byte as a C go_slice pointer.
// This relies on Go's slice header layout (pointer, len, cap) matching
// the C go_slice struct { ptr, len, cap }. The caller must Pin the slice
// data via runtime.Pinner before passing it across the FFI boundary so
// the GC does not relocate the backing array during the C call.
func cGoSlice(data []byte, pinner *runtime.Pinner) *C.go_slice {
	if data == nil || len(data) == 0 {
		return nil
	}
	pinner.Pin(&data[0])
	return (*C.go_slice)(unsafe.Pointer(&data))
}

func copyBuffer(buf *C.tss_buffer) []byte {
	if buf.len == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(buf.ptr), C.int(buf.len))
}

func HandleFree(h Handle) error {
	res := C.frozt_handle_free(cHandle(h))
	if res != 0 {
		return mapLibError(int(res))
	}
	return nil
}

// DKG

func DkgPart1(identifier, maxSigners, minSigners uint16) (DkgSecretHandle, []byte, error) {
	var outSecret C.Handle
	var outPackage C.tss_buffer
	defer C.tss_buffer_free(&outPackage)

	res := C.frozt_dkg_part1(
		C.uint16_t(identifier),
		C.uint16_t(maxSigners),
		C.uint16_t(minSigners),
		&outSecret,
		&outPackage,
	)
	if res != 0 {
		return 0, nil, mapLibError(int(res))
	}

	return DkgSecretHandle(outSecret._0), copyBuffer(&outPackage), nil
}

func DkgPart2(secret DkgSecretHandle, round1Packages []byte) (DkgSecretHandle, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	r1 := cGoSlice(round1Packages, pinner)

	var outSecret C.Handle
	var outPackages C.tss_buffer
	defer C.tss_buffer_free(&outPackages)

	res := C.frozt_dkg_part2(
		cHandle(Handle(secret)),
		r1,
		&outSecret,
		&outPackages,
	)
	if res != 0 {
		return 0, nil, mapLibError(int(res))
	}

	return DkgSecretHandle(outSecret._0), copyBuffer(&outPackages), nil
}

func DkgPart3(secret DkgSecretHandle, round1Packages, round2Packages []byte) ([]byte, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	r1 := cGoSlice(round1Packages, pinner)
	r2 := cGoSlice(round2Packages, pinner)

	var outKP C.tss_buffer
	var outPKP C.tss_buffer
	defer C.tss_buffer_free(&outKP)
	defer C.tss_buffer_free(&outPKP)

	res := C.frozt_dkg_part3(
		cHandle(Handle(secret)),
		r1,
		r2,
		&outKP,
		&outPKP,
	)
	if res != 0 {
		return nil, nil, mapLibError(int(res))
	}

	return copyBuffer(&outKP), copyBuffer(&outPKP), nil
}

// Reshare

func ResharePart1(identifier, maxSigners, minSigners uint16, oldKeyPackage []byte, oldIdentifiers []uint16) (DkgSecretHandle, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	oldKP := cGoSlice(oldKeyPackage, pinner)

	var oldIDs *C.go_slice
	if len(oldIdentifiers) > 0 {
		idBytes := make([]byte, len(oldIdentifiers)*2)
		for i, id := range oldIdentifiers {
			idBytes[i*2] = byte(id)
			idBytes[i*2+1] = byte(id >> 8)
		}
		oldIDs = cGoSlice(idBytes, pinner)
	}

	var outSecret C.Handle
	var outPackage C.tss_buffer
	defer C.tss_buffer_free(&outPackage)

	res := C.frozt_reshare_part1(
		C.uint16_t(identifier),
		C.uint16_t(maxSigners),
		C.uint16_t(minSigners),
		oldKP,
		oldIDs,
		&outSecret,
		&outPackage,
	)
	if res != 0 {
		return 0, nil, mapLibError(int(res))
	}

	return DkgSecretHandle(outSecret._0), copyBuffer(&outPackage), nil
}

func ResharePart3(secret DkgSecretHandle, round1Packages, round2Packages, expectedVerifyingKey []byte) ([]byte, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	r1 := cGoSlice(round1Packages, pinner)
	r2 := cGoSlice(round2Packages, pinner)
	vk := cGoSlice(expectedVerifyingKey, pinner)

	var outKP C.tss_buffer
	var outPKP C.tss_buffer
	defer C.tss_buffer_free(&outKP)
	defer C.tss_buffer_free(&outPKP)

	res := C.frozt_reshare_part3(
		cHandle(Handle(secret)),
		r1,
		r2,
		vk,
		&outKP,
		&outPKP,
	)
	if res != 0 {
		return nil, nil, mapLibError(int(res))
	}

	return copyBuffer(&outKP), copyBuffer(&outPKP), nil
}

// Signing

func SignCommit(keyPackage []byte) (NoncesHandle, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	kp := cGoSlice(keyPackage, pinner)

	var outNonces C.Handle
	var outCommitments C.tss_buffer
	defer C.tss_buffer_free(&outCommitments)

	res := C.frozt_sign_commit(kp, &outNonces, &outCommitments)
	if res != 0 {
		return 0, nil, mapLibError(int(res))
	}

	return NoncesHandle(outNonces._0), copyBuffer(&outCommitments), nil
}

func SignNewPackage(message, commitmentsMap, pubKeyPackage []byte) ([]byte, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	msg := cGoSlice(message, pinner)
	cm := cGoSlice(commitmentsMap, pinner)
	pkp := cGoSlice(pubKeyPackage, pinner)

	var outSP C.tss_buffer
	var outRandomizer C.tss_buffer
	defer C.tss_buffer_free(&outSP)
	defer C.tss_buffer_free(&outRandomizer)

	res := C.frozt_sign_new_package(msg, cm, pkp, &outSP, &outRandomizer)
	if res != 0 {
		return nil, nil, mapLibError(int(res))
	}

	return copyBuffer(&outSP), copyBuffer(&outRandomizer), nil
}

func Sign(signingPackage []byte, nonces NoncesHandle, keyPackage, randomizer []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	sp := cGoSlice(signingPackage, pinner)
	kp := cGoSlice(keyPackage, pinner)
	r := cGoSlice(randomizer, pinner)

	var outShare C.tss_buffer
	defer C.tss_buffer_free(&outShare)

	res := C.frozt_sign(sp, cHandle(Handle(nonces)), kp, r, &outShare)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outShare), nil
}

func SignAggregate(signingPackage, sharesMap, pubKeyPackage, randomizer []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	sp := cGoSlice(signingPackage, pinner)
	sm := cGoSlice(sharesMap, pinner)
	pkp := cGoSlice(pubKeyPackage, pinner)
	r := cGoSlice(randomizer, pinner)

	var outSig C.tss_buffer
	defer C.tss_buffer_free(&outSig)

	res := C.frozt_sign_aggregate(sp, sm, pkp, r, &outSig)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outSig), nil
}

func encodeIdentifier(id uint16) ([]byte, error) {
	var outBytes C.tss_buffer
	defer C.tss_buffer_free(&outBytes)

	res := C.frozt_encode_identifier(C.uint16_t(id), &outBytes)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outBytes), nil
}

func decodeIdentifier(idBytes []byte) (uint16, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	data := cGoSlice(idBytes, pinner)

	var outID C.uint16_t

	res := C.frozt_decode_identifier(data, &outID)
	if res != 0 {
		return 0, mapLibError(int(res))
	}

	return uint16(outID), nil
}

// Key inspection

func KeyPackageIdentifier(keyPackage []byte) (uint16, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	kp := cGoSlice(keyPackage, pinner)

	var outID C.uint16_t

	res := C.frozt_keypackage_identifier(kp, &outID)
	if res != 0 {
		return 0, mapLibError(int(res))
	}

	return uint16(outID), nil
}

func PubKeyPackageVerifyingKey(pubKeyPackage []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	pkp := cGoSlice(pubKeyPackage, pinner)

	var outKey C.tss_buffer
	defer C.tss_buffer_free(&outKey)

	res := C.frozt_pubkeypackage_verifying_key(pkp, &outKey)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outKey), nil
}

// Key Import

func KeyImportPart1(identifier, maxSigners, minSigners uint16, seed []byte, accountIndex uint32) (DkgSecretHandle, []byte, []byte, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	s := cGoSlice(seed, pinner)

	var outSecret C.Handle
	var outPackage C.tss_buffer
	var outVK C.tss_buffer
	var outExtras C.tss_buffer
	defer C.tss_buffer_free(&outPackage)
	defer C.tss_buffer_free(&outVK)
	defer C.tss_buffer_free(&outExtras)

	res := C.frozt_key_import_part1(
		C.uint16_t(identifier),
		C.uint16_t(maxSigners),
		C.uint16_t(minSigners),
		s,
		C.uint32_t(accountIndex),
		&outSecret,
		&outPackage,
		&outVK,
		&outExtras,
	)
	if res != 0 {
		return 0, nil, nil, nil, mapLibError(int(res))
	}

	return DkgSecretHandle(outSecret._0), copyBuffer(&outPackage), copyBuffer(&outVK), copyBuffer(&outExtras), nil
}

func KeyImportPart3(secret DkgSecretHandle, round1Packages, round2Packages, expectedVK []byte) ([]byte, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	r1 := cGoSlice(round1Packages, pinner)
	r2 := cGoSlice(round2Packages, pinner)
	vk := cGoSlice(expectedVK, pinner)

	var outKP C.tss_buffer
	var outPKP C.tss_buffer
	defer C.tss_buffer_free(&outKP)
	defer C.tss_buffer_free(&outPKP)

	res := C.frozt_key_import_part3(
		cHandle(Handle(secret)),
		r1,
		r2,
		vk,
		&outKP,
		&outPKP,
	)
	if res != 0 {
		return nil, nil, mapLibError(int(res))
	}

	return copyBuffer(&outKP), copyBuffer(&outPKP), nil
}

// Sapling

func SaplingGenerateExtras() ([]byte, error) {
	var outExtras C.tss_buffer
	defer C.tss_buffer_free(&outExtras)

	res := C.frozt_sapling_generate_extras(&outExtras)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outExtras), nil
}

type SaplingKeys struct {
	Address string
	Ivk     []byte
	Nk      []byte
}

func SaplingDeriveKeys(pubKeyPackage, saplingExtras []byte) (*SaplingKeys, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	pkp := cGoSlice(pubKeyPackage, pinner)
	extras := cGoSlice(saplingExtras, pinner)

	var outAddr C.tss_buffer
	var outIvk C.tss_buffer
	var outNk C.tss_buffer
	defer C.tss_buffer_free(&outAddr)
	defer C.tss_buffer_free(&outIvk)
	defer C.tss_buffer_free(&outNk)

	res := C.frozt_sapling_derive_keys(pkp, extras, &outAddr, &outIvk, &outNk)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return &SaplingKeys{
		Address: string(copyBuffer(&outAddr)),
		Ivk:     copyBuffer(&outIvk),
		Nk:      copyBuffer(&outNk),
	}, nil
}

func SaplingDecryptNoteFull(ivk, cmu, epk, encCiphertext []byte, height uint64) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	ivkSlice := cGoSlice(ivk, pinner)
	cmuSlice := cGoSlice(cmu, pinner)
	epkSlice := cGoSlice(epk, pinner)
	ctSlice := cGoSlice(encCiphertext, pinner)

	var outNoteData C.tss_buffer
	defer C.tss_buffer_free(&outNoteData)

	res := C.frozt_sapling_decrypt_note_full(ivkSlice, cmuSlice, epkSlice, ctSlice, C.uint64_t(height), &outNoteData)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outNoteData), nil
}

func SaplingComputeNullifier(pubKeyPackage, saplingExtras, noteData []byte, position, height uint64) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	pkpSlice := cGoSlice(pubKeyPackage, pinner)
	extrasSlice := cGoSlice(saplingExtras, pinner)
	ndSlice := cGoSlice(noteData, pinner)

	var outNullifier C.tss_buffer
	defer C.tss_buffer_free(&outNullifier)

	res := C.frozt_sapling_compute_nullifier(pkpSlice, extrasSlice, ndSlice, C.uint64_t(position), C.uint64_t(height), &outNullifier)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outNullifier), nil
}

func SaplingTreeSize(treeStateHex []byte) (uint64, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	data := cGoSlice(treeStateHex, pinner)

	var outSize C.uint64_t

	res := C.frozt_sapling_tree_size(data, &outSize)
	if res != 0 {
		return 0, mapLibError(int(res))
	}

	return uint64(outSize), nil
}

func SaplingTreeFromState(treeStateHex []byte) (TreeHandle, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	data := cGoSlice(treeStateHex, pinner)

	var outTree C.Handle

	res := C.frozt_sapling_tree_from_state(data, &outTree)
	if res != 0 {
		return 0, mapLibError(int(res))
	}

	return TreeHandle(outTree._0), nil
}

func SaplingTreeAppend(tree TreeHandle, cmu []byte) error {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cmuSlice := cGoSlice(cmu, pinner)

	res := C.frozt_sapling_tree_append(cHandle(Handle(tree)), cmuSlice)
	if res != 0 {
		return mapLibError(int(res))
	}

	return nil
}

func SaplingTreeWitness(tree TreeHandle) (WitnessHandle, error) {
	var outWitness C.Handle

	res := C.frozt_sapling_tree_witness(cHandle(Handle(tree)), &outWitness)
	if res != 0 {
		return 0, mapLibError(int(res))
	}

	return WitnessHandle(outWitness._0), nil
}

func SaplingWitnessAppend(witness WitnessHandle, cmu []byte) error {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cmuSlice := cGoSlice(cmu, pinner)

	res := C.frozt_sapling_witness_append(cHandle(Handle(witness)), cmuSlice)
	if res != 0 {
		return mapLibError(int(res))
	}

	return nil
}

func SaplingWitnessRoot(witness WitnessHandle) ([]byte, error) {
	var outAnchor C.tss_buffer
	defer C.tss_buffer_free(&outAnchor)

	res := C.frozt_sapling_witness_root(cHandle(Handle(witness)), &outAnchor)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outAnchor), nil
}

func SaplingWitnessSerialize(witness WitnessHandle) ([]byte, error) {
	var outData C.tss_buffer
	defer C.tss_buffer_free(&outData)

	res := C.frozt_sapling_witness_serialize(cHandle(Handle(witness)), &outData)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outData), nil
}

func SaplingWitnessDeserialize(data []byte) (WitnessHandle, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	dataSlice := cGoSlice(data, pinner)

	var outWitness C.Handle

	res := C.frozt_sapling_witness_deserialize(dataSlice, &outWitness)
	if res != 0 {
		return 0, mapLibError(int(res))
	}

	return WitnessHandle(outWitness._0), nil
}

func TxBuilderNew(pubKeyPackage, saplingExtras []byte, targetHeight uint32) (TxBuilderHandle, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	pkpSlice := cGoSlice(pubKeyPackage, pinner)
	extrasSlice := cGoSlice(saplingExtras, pinner)

	var outHandle C.Handle

	res := C.frozt_tx_builder_new(pkpSlice, extrasSlice, C.uint32_t(targetHeight), &outHandle)
	if res != 0 {
		return 0, mapLibError(int(res))
	}

	return TxBuilderHandle(outHandle._0), nil
}

func TxBuilderAddSpend(builder TxBuilderHandle, noteData, witnessData []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	noteSlice := cGoSlice(noteData, pinner)
	witSlice := cGoSlice(witnessData, pinner)

	var outAlpha C.tss_buffer
	defer C.tss_buffer_free(&outAlpha)

	res := C.frozt_tx_builder_add_spend(cHandle(Handle(builder)), noteSlice, witSlice, &outAlpha)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outAlpha), nil
}

func TxBuilderAddOutput(builder TxBuilderHandle, address string, amount uint64) error {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	addrBytes := []byte(address)
	addrSlice := cGoSlice(addrBytes, pinner)

	res := C.frozt_tx_builder_add_output(cHandle(Handle(builder)), addrSlice, C.uint64_t(amount))
	if res != 0 {
		return mapLibError(int(res))
	}

	return nil
}

func TxBuilderBuild(builder TxBuilderHandle) ([]byte, error) {
	var outSighash C.tss_buffer
	defer C.tss_buffer_free(&outSighash)

	res := C.frozt_tx_builder_build(cHandle(Handle(builder)), &outSighash)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outSighash), nil
}

func TxBuilderComplete(builder TxBuilderHandle, spendAuthSigs [][]byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	packed := make([]byte, 0, len(spendAuthSigs)*64)
	for _, sig := range spendAuthSigs {
		packed = append(packed, sig...)
	}
	sigSlice := cGoSlice(packed, pinner)

	var outRawTx C.tss_buffer
	defer C.tss_buffer_free(&outRawTx)

	res := C.frozt_tx_builder_complete(cHandle(Handle(builder)), sigSlice, &outRawTx)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outRawTx), nil
}

func SaplingTryDecryptCompact(ivk, cmu, epk, ciphertext []byte, height uint64) (uint64, bool, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	ivkSlice := cGoSlice(ivk, pinner)
	cmuSlice := cGoSlice(cmu, pinner)
	epkSlice := cGoSlice(epk, pinner)
	ctSlice := cGoSlice(ciphertext, pinner)

	var outValue C.uint64_t

	res := C.frozt_sapling_try_decrypt_compact(ivkSlice, cmuSlice, epkSlice, ctSlice, C.uint64_t(height), &outValue)
	if res == C.LIB_SAPLING_ERROR {
		return 0, false, nil
	}
	if res != 0 {
		return 0, false, mapLibError(int(res))
	}

	return uint64(outValue), true, nil
}
