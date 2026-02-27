package frozt

import (
	"bytes"
	"testing"
)

func mustEncodeID(t *testing.T, id uint16) []byte {
	t.Helper()
	b, err := EncodeIdentifier(id)
	if err != nil {
		t.Fatalf("EncodeIdentifier(%d): %v", id, err)
	}
	return b
}

func runDKG(t *testing.T, n, threshold uint16) (keyPackages [][]byte, pubKeyPackage []byte) {
	t.Helper()

	type party struct {
		id     uint16
		secret Handle
		r1Pkg  []byte
	}

	parties := make([]party, n)
	for i := uint16(0); i < n; i++ {
		id := i + 1
		secret, pkg, err := DkgPart1(id, n, threshold)
		if err != nil {
			t.Fatalf("DkgPart1 party %d: %v", id, err)
		}
		parties[i] = party{id: id, secret: secret, r1Pkg: pkg}
	}

	type r2Result struct {
		secret Handle
		r2Pkgs []MapEntry
	}
	r2Results := make([]r2Result, n)

	for i := uint16(0); i < n; i++ {
		var others []MapEntry
		for j := uint16(0); j < n; j++ {
			if j == i {
				continue
			}
			others = append(others, MapEntry{
				ID:    mustEncodeID(t, parties[j].id),
				Value: parties[j].r1Pkg,
			})
		}

		secret, pkgsBytes, err := DkgPart2(parties[i].secret, EncodeMap(others))
		if err != nil {
			t.Fatalf("DkgPart2 party %d: %v", parties[i].id, err)
		}

		entries, decErr := DecodeMap(pkgsBytes)
		if decErr != nil {
			t.Fatalf("DecodeMap r2 party %d: %v", parties[i].id, decErr)
		}
		r2Results[i] = r2Result{secret: secret, r2Pkgs: entries}
	}

	keyPackages = make([][]byte, n)
	myIDBytes := make([][]byte, n)
	for i := uint16(0); i < n; i++ {
		myIDBytes[i] = mustEncodeID(t, i+1)
	}

	for i := uint16(0); i < n; i++ {
		var r1Others []MapEntry
		for j := uint16(0); j < n; j++ {
			if j == i {
				continue
			}
			r1Others = append(r1Others, MapEntry{
				ID:    mustEncodeID(t, parties[j].id),
				Value: parties[j].r1Pkg,
			})
		}

		var r2ForMe []MapEntry
		for senderIdx := uint16(0); senderIdx < n; senderIdx++ {
			if senderIdx == i {
				continue
			}
			senderIDBytes := mustEncodeID(t, parties[senderIdx].id)
			for _, entry := range r2Results[senderIdx].r2Pkgs {
				if bytes.Equal(entry.ID, myIDBytes[i]) {
					r2ForMe = append(r2ForMe, MapEntry{
						ID:    senderIDBytes,
						Value: entry.Value,
					})
				}
			}
		}

		kp, pkp, err := DkgPart3(
			r2Results[i].secret,
			EncodeMap(r1Others),
			EncodeMap(r2ForMe),
		)
		if err != nil {
			t.Fatalf("DkgPart3 party %d: %v", i+1, err)
		}
		keyPackages[i] = kp
		if i == 0 {
			pubKeyPackage = pkp
		}
	}

	return keyPackages, pubKeyPackage
}

func runSign(t *testing.T, keyPackages [][]byte, pubKeyPackage []byte, signerIndices []int, message []byte) []byte {
	t.Helper()

	type signerState struct {
		idx    int
		id     uint16
		nonces Handle
		commit []byte
	}

	signers := make([]signerState, len(signerIndices))
	for i, idx := range signerIndices {
		id := uint16(idx + 1)
		nonces, commitments, err := SignCommit(keyPackages[idx])
		if err != nil {
			t.Fatalf("SignCommit signer %d: %v", id, err)
		}
		signers[i] = signerState{idx: idx, id: id, nonces: nonces, commit: commitments}
	}

	var commitEntries []MapEntry
	for _, s := range signers {
		commitEntries = append(commitEntries, MapEntry{
			ID:    mustEncodeID(t, s.id),
			Value: s.commit,
		})
	}

	signingPackage, randomizer, err := SignNewPackage(message, EncodeMap(commitEntries), pubKeyPackage)
	if err != nil {
		t.Fatalf("SignNewPackage: %v", err)
	}

	var shareEntries []MapEntry
	for _, s := range signers {
		share, signErr := Sign(signingPackage, s.nonces, keyPackages[s.idx], randomizer)
		if signErr != nil {
			t.Fatalf("Sign signer %d: %v", s.id, signErr)
		}
		shareEntries = append(shareEntries, MapEntry{
			ID:    mustEncodeID(t, s.id),
			Value: share,
		})
	}

	signature, err := SignAggregate(signingPackage, EncodeMap(shareEntries), pubKeyPackage, randomizer)
	if err != nil {
		t.Fatalf("SignAggregate: %v", err)
	}

	return signature
}

func TestFullFlow(t *testing.T) {
	n := uint16(3)
	threshold := uint16(2)

	t.Log("=== DKG ===")
	keyPackages, pubKeyPackage := runDKG(t, n, threshold)

	vk, err := PubKeyPackageVerifyingKey(pubKeyPackage)
	if err != nil {
		t.Fatalf("PubKeyPackageVerifyingKey: %v", err)
	}
	t.Logf("group verifying key: %x", vk)

	for i, kp := range keyPackages {
		id, idErr := KeyPackageIdentifier(kp)
		if idErr != nil {
			t.Fatalf("KeyPackageIdentifier %d: %v", i, idErr)
		}
		t.Logf("party %d identifier: %d", i, id)
	}

	t.Log("=== Sign (parties 0,1) ===")
	msg := []byte("hello zcash shielded frozt")
	sig := runSign(t, keyPackages, pubKeyPackage, []int{0, 1}, msg)
	t.Logf("signature: %x (%d bytes)", sig, len(sig))

	t.Log("=== Sign (parties 1,2) ===")
	sig2 := runSign(t, keyPackages, pubKeyPackage, []int{1, 2}, msg)
	t.Logf("signature: %x (%d bytes)", sig2, len(sig2))

	t.Log("=== Address Derivation ===")
	zAddr, err := DeriveZAddress(pubKeyPackage)
	if err != nil {
		t.Fatalf("DeriveZAddress: %v", err)
	}
	t.Logf("z-address: %s", zAddr)

	tAddr, err := PubKeyToTAddress(pubKeyPackage)
	if err != nil {
		t.Fatalf("PubKeyToTAddress: %v", err)
	}
	t.Logf("t-address: %s", tAddr)

	t.Log("=== All operations successful ===")
}

func runReshare(t *testing.T, oldKPs [][]byte, oldPKP []byte, newN, newT uint16, oldIDs []uint16) (keyPackages [][]byte, pubKeyPackage []byte) {
	t.Helper()

	vk, err := PubKeyPackageVerifyingKey(oldPKP)
	if err != nil {
		t.Fatalf("PubKeyPackageVerifyingKey: %v", err)
	}

	type party struct {
		id     uint16
		secret Handle
		r1Pkg  []byte
	}

	parties := make([]party, newN)
	for i := uint16(0); i < newN; i++ {
		id := i + 1
		var oldKP []byte
		if containsU16(oldIDs, id) {
			oldKP = oldKPs[id-1]
		}
		secret, pkg, reshareErr := ResharePart1(id, newN, newT, oldKP, oldIDs)
		if reshareErr != nil {
			t.Fatalf("ResharePart1 party %d: %v", id, reshareErr)
		}
		parties[i] = party{id: id, secret: secret, r1Pkg: pkg}
	}

	type r2Result struct {
		secret Handle
		r2Pkgs []MapEntry
	}
	r2Results := make([]r2Result, newN)

	for i := uint16(0); i < newN; i++ {
		var others []MapEntry
		for j := uint16(0); j < newN; j++ {
			if j == i {
				continue
			}
			others = append(others, MapEntry{
				ID:    mustEncodeID(t, parties[j].id),
				Value: parties[j].r1Pkg,
			})
		}

		secret, pkgsBytes, dkgErr := DkgPart2(parties[i].secret, EncodeMap(others))
		if dkgErr != nil {
			t.Fatalf("DkgPart2 party %d: %v", parties[i].id, dkgErr)
		}

		entries, decErr := DecodeMap(pkgsBytes)
		if decErr != nil {
			t.Fatalf("DecodeMap r2 party %d: %v", parties[i].id, decErr)
		}
		r2Results[i] = r2Result{secret: secret, r2Pkgs: entries}
	}

	keyPackages = make([][]byte, newN)
	myIDBytes := make([][]byte, newN)
	for i := uint16(0); i < newN; i++ {
		myIDBytes[i] = mustEncodeID(t, i+1)
	}

	for i := uint16(0); i < newN; i++ {
		var r1Others []MapEntry
		for j := uint16(0); j < newN; j++ {
			if j == i {
				continue
			}
			r1Others = append(r1Others, MapEntry{
				ID:    mustEncodeID(t, parties[j].id),
				Value: parties[j].r1Pkg,
			})
		}

		var r2ForMe []MapEntry
		for senderIdx := uint16(0); senderIdx < newN; senderIdx++ {
			if senderIdx == i {
				continue
			}
			senderIDBytes := mustEncodeID(t, parties[senderIdx].id)
			for _, entry := range r2Results[senderIdx].r2Pkgs {
				if bytes.Equal(entry.ID, myIDBytes[i]) {
					r2ForMe = append(r2ForMe, MapEntry{
						ID:    senderIDBytes,
						Value: entry.Value,
					})
				}
			}
		}

		kp, pkp, reshareErr := ResharePart3(
			r2Results[i].secret,
			EncodeMap(r1Others),
			EncodeMap(r2ForMe),
			vk,
		)
		if reshareErr != nil {
			t.Fatalf("ResharePart3 party %d: %v", i+1, reshareErr)
		}
		keyPackages[i] = kp
		if i == 0 {
			pubKeyPackage = pkp
		}
	}

	return keyPackages, pubKeyPackage
}

func containsU16(slice []uint16, val uint16) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func TestReshare(t *testing.T) {
	msg := []byte("hello zcash reshare")

	t.Log("=== DKG 2-of-2 ===")
	kps2, pkp2 := runDKG(t, 2, 2)

	vk2, err := PubKeyPackageVerifyingKey(pkp2)
	if err != nil {
		t.Fatalf("PubKeyPackageVerifyingKey: %v", err)
	}

	t.Log("=== Sign 2-of-2 (parties 0,1) ===")
	runSign(t, kps2, pkp2, []int{0, 1}, msg)

	t.Log("=== Reshare 2-of-2 → 2-of-3 ===")
	kps3, pkp3 := runReshare(t, kps2, pkp2, 3, 2, []uint16{1, 2})

	vk3, err := PubKeyPackageVerifyingKey(pkp3)
	if err != nil {
		t.Fatalf("PubKeyPackageVerifyingKey: %v", err)
	}
	if !bytes.Equal(vk2, vk3) {
		t.Fatal("verifying key changed after reshare 2-of-2 → 2-of-3")
	}

	t.Log("=== Sign 2-of-3 (parties 0,1) ===")
	runSign(t, kps3, pkp3, []int{0, 1}, msg)
	t.Log("=== Sign 2-of-3 (parties 1,2) ===")
	runSign(t, kps3, pkp3, []int{1, 2}, msg)

	t.Log("=== Reshare 2-of-3 → 3-of-4 ===")
	kps4, pkp4 := runReshare(t, kps3, pkp3, 4, 3, []uint16{1, 2, 3})

	vk4, err := PubKeyPackageVerifyingKey(pkp4)
	if err != nil {
		t.Fatalf("PubKeyPackageVerifyingKey: %v", err)
	}
	if !bytes.Equal(vk2, vk4) {
		t.Fatal("verifying key changed after reshare 2-of-3 → 3-of-4")
	}

	t.Log("=== Sign 3-of-4 (parties 0,1,2) ===")
	runSign(t, kps4, pkp4, []int{0, 1, 2}, msg)
	t.Log("=== Sign 3-of-4 (parties 1,2,3) ===")
	runSign(t, kps4, pkp4, []int{1, 2, 3}, msg)

	t.Log("=== All reshare operations successful ===")
}
