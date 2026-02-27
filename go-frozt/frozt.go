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

func cHandle(h Handle) C.Handle {
	return C.Handle{_0: C.int32_t(h)}
}

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

// DKG

func DkgPart1(identifier, maxSigners, minSigners uint16) (Handle, []byte, error) {
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

	return Handle(outSecret._0), copyBuffer(&outPackage), nil
}

func DkgPart2(secret Handle, round1Packages []byte) (Handle, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	r1 := cGoSlice(round1Packages, pinner)

	var outSecret C.Handle
	var outPackages C.tss_buffer
	defer C.tss_buffer_free(&outPackages)

	res := C.frozt_dkg_part2(
		cHandle(secret),
		r1,
		&outSecret,
		&outPackages,
	)
	if res != 0 {
		return 0, nil, mapLibError(int(res))
	}

	return Handle(outSecret._0), copyBuffer(&outPackages), nil
}

func DkgPart3(secret Handle, round1Packages, round2Packages []byte) ([]byte, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	r1 := cGoSlice(round1Packages, pinner)
	r2 := cGoSlice(round2Packages, pinner)

	var outKP C.tss_buffer
	var outPKP C.tss_buffer
	defer C.tss_buffer_free(&outKP)
	defer C.tss_buffer_free(&outPKP)

	res := C.frozt_dkg_part3(
		cHandle(secret),
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

func ResharePart1(identifier, maxSigners, minSigners uint16, oldKeyPackage []byte, oldIdentifiers []uint16) (Handle, []byte, error) {
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

	return Handle(outSecret._0), copyBuffer(&outPackage), nil
}

func ResharePart3(secret Handle, round1Packages, round2Packages, expectedVerifyingKey []byte) ([]byte, []byte, error) {
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
		cHandle(secret),
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

func SignCommit(keyPackage []byte) (Handle, []byte, error) {
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

	return Handle(outNonces._0), copyBuffer(&outCommitments), nil
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

func Sign(signingPackage []byte, nonces Handle, keyPackage, randomizer []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	sp := cGoSlice(signingPackage, pinner)
	kp := cGoSlice(keyPackage, pinner)
	r := cGoSlice(randomizer, pinner)

	var outShare C.tss_buffer
	defer C.tss_buffer_free(&outShare)

	res := C.frozt_sign(sp, cHandle(nonces), kp, r, &outShare)
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

// Identifier encoding

func EncodeIdentifier(id uint16) ([]byte, error) {
	var outBytes C.tss_buffer
	defer C.tss_buffer_free(&outBytes)

	res := C.frozt_encode_identifier(C.uint16_t(id), &outBytes)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outBytes), nil
}

func DecodeIdentifier(idBytes []byte) (uint16, error) {
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

// Address derivation

func DeriveZAddress(pubKeyPackage []byte) (string, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	pkp := cGoSlice(pubKeyPackage, pinner)

	var outAddr C.tss_buffer
	defer C.tss_buffer_free(&outAddr)

	res := C.frozt_derive_z_address(pkp, &outAddr)
	if res != 0 {
		return "", mapLibError(int(res))
	}

	return string(copyBuffer(&outAddr)), nil
}

func PubKeyToTAddress(pubKeyPackage []byte) (string, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	pkp := cGoSlice(pubKeyPackage, pinner)

	var outAddr C.tss_buffer
	defer C.tss_buffer_free(&outAddr)

	res := C.frozt_pubkey_to_t_address(pkp, &outAddr)
	if res != 0 {
		return "", mapLibError(int(res))
	}

	return string(copyBuffer(&outAddr)), nil
}
