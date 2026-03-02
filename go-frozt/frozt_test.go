package frozt

import (
	"bytes"
	"encoding/hex"
	"testing"
)

const abandonAddr = "zs188wzupg00tqs3y5reyjc758c6vhl8qm2kg4k43mcp533ytrdkwpy8xjdk3zqtek0ng0cv7f0nta"

func abandonSeed(t *testing.T) []byte {
	t.Helper()
	seed, err := hex.DecodeString(
		"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1" +
			"9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")
	if err != nil {
		t.Fatalf("decode abandon seed: %v", err)
	}
	return seed
}

func runDKG(t *testing.T, n, threshold uint16) (keyPackages [][]byte, pubKeyPackage []byte) {
	t.Helper()

	type party struct {
		id     uint16
		secret DkgSecretHandle
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
		secret DkgSecretHandle
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
				ID:    parties[j].id,
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

	for i := uint16(0); i < n; i++ {
		myID := i + 1
		var r1Others []MapEntry
		for j := uint16(0); j < n; j++ {
			if j == i {
				continue
			}
			r1Others = append(r1Others, MapEntry{
				ID:    parties[j].id,
				Value: parties[j].r1Pkg,
			})
		}

		var r2ForMe []MapEntry
		for senderIdx := uint16(0); senderIdx < n; senderIdx++ {
			if senderIdx == i {
				continue
			}
			for _, entry := range r2Results[senderIdx].r2Pkgs {
				if entry.ID == myID {
					r2ForMe = append(r2ForMe, MapEntry{
						ID:    parties[senderIdx].id,
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
		nonces NoncesHandle
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
			ID:    s.id,
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
			ID:    s.id,
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
		secret DkgSecretHandle
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
		secret DkgSecretHandle
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
				ID:    parties[j].id,
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

	for i := uint16(0); i < newN; i++ {
		myID := i + 1
		var r1Others []MapEntry
		for j := uint16(0); j < newN; j++ {
			if j == i {
				continue
			}
			r1Others = append(r1Others, MapEntry{
				ID:    parties[j].id,
				Value: parties[j].r1Pkg,
			})
		}

		var r2ForMe []MapEntry
		for senderIdx := uint16(0); senderIdx < newN; senderIdx++ {
			if senderIdx == i {
				continue
			}
			for _, entry := range r2Results[senderIdx].r2Pkgs {
				if entry.ID == myID {
					r2ForMe = append(r2ForMe, MapEntry{
						ID:    parties[senderIdx].id,
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

type keyImportResult struct {
	keyPackages   [][]byte
	pubKeyPackage []byte
	vk            []byte
	extras        []byte
}

func runKeyImport(t *testing.T, n, threshold uint16, seed []byte, accountIndex uint32) keyImportResult {
	t.Helper()

	type party struct {
		id     uint16
		secret DkgSecretHandle
		r1Pkg  []byte
	}

	parties := make([]party, n)
	var vk []byte
	var extras []byte
	for i := uint16(0); i < n; i++ {
		id := i + 1
		var s []byte
		if id == 1 {
			s = seed
		}
		secret, pkg, outVK, outExtras, err := KeyImportPart1(id, n, threshold, s, accountIndex)
		if err != nil {
			t.Fatalf("KeyImportPart1 party %d: %v", id, err)
		}
		if id == 1 {
			vk = outVK
			extras = outExtras
		}
		parties[i] = party{id: id, secret: secret, r1Pkg: pkg}
	}

	type r2Result struct {
		secret DkgSecretHandle
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
				ID:    parties[j].id,
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

	kps := make([][]byte, n)

	var pkp []byte
	for i := uint16(0); i < n; i++ {
		myID := i + 1
		var r1Others []MapEntry
		for j := uint16(0); j < n; j++ {
			if j == i {
				continue
			}
			r1Others = append(r1Others, MapEntry{
				ID:    parties[j].id,
				Value: parties[j].r1Pkg,
			})
		}

		var r2ForMe []MapEntry
		for senderIdx := uint16(0); senderIdx < n; senderIdx++ {
			if senderIdx == i {
				continue
			}
			for _, entry := range r2Results[senderIdx].r2Pkgs {
				if entry.ID == myID {
					r2ForMe = append(r2ForMe, MapEntry{
						ID:    parties[senderIdx].id,
						Value: entry.Value,
					})
				}
			}
		}

		kp, p, err := KeyImportPart3(
			r2Results[i].secret,
			EncodeMap(r1Others),
			EncodeMap(r2ForMe),
			vk,
		)
		if err != nil {
			t.Fatalf("KeyImportPart3 party %d: %v", i+1, err)
		}
		kps[i] = kp
		if i == 0 {
			pkp = p
		}
	}

	return keyImportResult{keyPackages: kps, pubKeyPackage: pkp, vk: vk, extras: extras}
}

func TestKeyImport(t *testing.T) {
	seed := abandonSeed(t)

	t.Log("=== Key Import 2-of-3 ===")
	result := runKeyImport(t, 3, 2, seed, 0)

	importedVK, err := PubKeyPackageVerifyingKey(result.pubKeyPackage)
	if err != nil {
		t.Fatalf("PubKeyPackageVerifyingKey: %v", err)
	}
	if !bytes.Equal(result.vk, importedVK) {
		t.Fatal("verifying key mismatch after import")
	}
	if len(result.extras) != 96 {
		t.Fatalf("expected 96 bytes sapling extras, got %d", len(result.extras))
	}

	t.Log("=== Sign (parties 0,1) ===")
	msg := []byte("hello zcash key import")
	runSign(t, result.keyPackages, result.pubKeyPackage, []int{0, 1}, msg)

	t.Log("=== Sign (parties 1,2) ===")
	runSign(t, result.keyPackages, result.pubKeyPackage, []int{1, 2}, msg)

	t.Log("=== Derive z-address from extras ===")
	keys, err := SaplingDeriveKeys(result.pubKeyPackage, result.extras)
	if err != nil {
		t.Fatalf("SaplingDeriveKeys: %v", err)
	}
	expectedAddr := abandonAddr
	if keys.Address != expectedAddr {
		t.Fatalf("z-address mismatch:\n  got:  %s\n  want: %s", keys.Address, expectedAddr)
	}
	t.Logf("z-address: %s", keys.Address)

	t.Log("=== All key import operations successful ===")
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

func TestSaplingExtras(t *testing.T) {
	t.Log("=== DKG 2-of-3 ===")
	_, pubKeyPackage := runDKG(t, 3, 2)

	t.Log("=== Generate sapling extras ===")
	extras, err := SaplingGenerateExtras()
	if err != nil {
		t.Fatalf("SaplingGenerateExtras: %v", err)
	}
	if len(extras) != 96 {
		t.Fatalf("expected 96 bytes, got %d", len(extras))
	}

	t.Log("=== Derive keys from extras ===")
	keys, err := SaplingDeriveKeys(pubKeyPackage, extras)
	if err != nil {
		t.Fatalf("SaplingDeriveKeys: %v", err)
	}
	if len(keys.Address) < 3 || keys.Address[:2] != "zs" {
		t.Fatalf("expected zs... address, got: %s", keys.Address)
	}
	if len(keys.Ivk) != 32 {
		t.Fatalf("expected 32 bytes ivk, got %d", len(keys.Ivk))
	}
	if len(keys.Nk) != 32 {
		t.Fatalf("expected 32 bytes nk, got %d", len(keys.Nk))
	}
	t.Logf("z-address: %s", keys.Address)

	t.Log("=== All sapling extras operations successful ===")
}

func TestRejectOutOfRangeAccountIndex(t *testing.T) {
	seed := make([]byte, 64)

	_, _, _, _, err := KeyImportPart1(1, 3, 2, seed, 1<<31)
	if err == nil {
		t.Fatal("expected KeyImportPart1 to reject out-of-range account index")
	}
}

func TestSaplingDeriveKeysCombined(t *testing.T) {
	_, pubKeyPackage := runDKG(t, 3, 2)

	extras, err := SaplingGenerateExtras()
	if err != nil {
		t.Fatalf("SaplingGenerateExtras: %v", err)
	}

	keys, err := SaplingDeriveKeys(pubKeyPackage, extras)
	if err != nil {
		t.Fatalf("SaplingDeriveKeys: %v", err)
	}

	if len(keys.Address) < 3 || keys.Address[:2] != "zs" {
		t.Fatalf("expected zs... address, got: %s", keys.Address)
	}
	if len(keys.Ivk) != 32 {
		t.Fatalf("expected 32 bytes ivk, got %d", len(keys.Ivk))
	}
	if len(keys.Nk) != 32 {
		t.Fatalf("expected 32 bytes nk, got %d", len(keys.Nk))
	}

	t.Run("DeriveKeysDeterministic", func(t *testing.T) {
		seed := abandonSeed(t)
		result1 := runKeyImport(t, 3, 2, seed, 0)
		result2 := runKeyImport(t, 3, 2, seed, 0)
		if !bytes.Equal(result1.extras, result2.extras) {
			t.Fatal("seed-derived extras should be deterministic")
		}
	})
}

func TestTreeAndWitness(t *testing.T) {
	emptyTreeHex := []byte("000000")
	tree, err := SaplingTreeFromState(emptyTreeHex)
	if err != nil {
		t.Fatalf("SaplingTreeFromState: %v", err)
	}
	defer tree.Close()

	cmu1 := make([]byte, 32)
	cmu1[0] = 1

	err = SaplingTreeAppend(tree, cmu1)
	if err != nil {
		t.Fatalf("SaplingTreeAppend cmu1: %v", err)
	}

	witness, err := SaplingTreeWitness(tree)
	if err != nil {
		t.Fatalf("SaplingTreeWitness: %v", err)
	}
	defer witness.Close()

	cmu2 := make([]byte, 32)
	cmu2[0] = 2

	err = SaplingTreeAppend(tree, cmu2)
	if err != nil {
		t.Fatalf("SaplingTreeAppend cmu2: %v", err)
	}

	err = SaplingWitnessAppend(witness, cmu2)
	if err != nil {
		t.Fatalf("SaplingWitnessAppend: %v", err)
	}

	root, err := SaplingWitnessRoot(witness)
	if err != nil {
		t.Fatalf("SaplingWitnessRoot: %v", err)
	}
	if len(root) != 32 {
		t.Fatalf("expected 32 bytes root, got %d", len(root))
	}

	serialized, err := SaplingWitnessSerialize(witness)
	if err != nil {
		t.Fatalf("SaplingWitnessSerialize: %v", err)
	}
	if len(serialized) == 0 {
		t.Fatal("serialized witness should not be empty")
	}

	witness2, err := SaplingWitnessDeserialize(serialized)
	if err != nil {
		t.Fatalf("SaplingWitnessDeserialize: %v", err)
	}
	defer witness2.Close()

	root2, err := SaplingWitnessRoot(witness2)
	if err != nil {
		t.Fatalf("SaplingWitnessRoot (deserialized): %v", err)
	}
	if !bytes.Equal(root, root2) {
		t.Fatal("witness root mismatch after serialize/deserialize roundtrip")
	}
	t.Logf("witness root: %x", root)
}

func TestTreeMultipleAppends(t *testing.T) {
	tree, err := SaplingTreeFromState([]byte("000000"))
	if err != nil {
		t.Fatalf("SaplingTreeFromState: %v", err)
	}
	defer tree.Close()

	for i := byte(1); i <= 10; i++ {
		cmu := make([]byte, 32)
		cmu[0] = i
		appendErr := SaplingTreeAppend(tree, cmu)
		if appendErr != nil {
			t.Fatalf("SaplingTreeAppend %d: %v", i, appendErr)
		}
	}

	witness, err := SaplingTreeWitness(tree)
	if err != nil {
		t.Fatalf("SaplingTreeWitness: %v", err)
	}
	defer witness.Close()

	root, err := SaplingWitnessRoot(witness)
	if err != nil {
		t.Fatalf("SaplingWitnessRoot: %v", err)
	}
	if len(root) != 32 {
		t.Fatalf("expected 32 bytes root, got %d", len(root))
	}

	for i := byte(11); i <= 15; i++ {
		cmu := make([]byte, 32)
		cmu[0] = i
		appendErr := SaplingWitnessAppend(witness, cmu)
		if appendErr != nil {
			t.Fatalf("SaplingWitnessAppend %d: %v", i, appendErr)
		}
	}

	rootAfter, err := SaplingWitnessRoot(witness)
	if err != nil {
		t.Fatalf("SaplingWitnessRoot after appends: %v", err)
	}
	if bytes.Equal(root, rootAfter) {
		t.Fatal("root should change after appending more nodes")
	}
}

func TestTxBuilder(t *testing.T) {
	seed := abandonSeed(t)
	result := runKeyImport(t, 3, 2, seed, 0)

	builder, err := TxBuilderNew(result.pubKeyPackage, result.extras, 2_000_000)
	if err != nil {
		t.Fatalf("TxBuilderNew: %v", err)
	}
	defer builder.Close()

	addr := abandonAddr
	err = TxBuilderAddOutput(builder, addr, 100000)
	if err != nil {
		t.Fatalf("TxBuilderAddOutput: %v", err)
	}
	t.Log("TxBuilderNew + AddOutput succeeded")
}

func TestHandleClose(t *testing.T) {
	tree, err := SaplingTreeFromState([]byte("000000"))
	if err != nil {
		t.Fatalf("SaplingTreeFromState: %v", err)
	}

	cmu := make([]byte, 32)
	cmu[0] = 1
	err = SaplingTreeAppend(tree, cmu)
	if err != nil {
		t.Fatalf("SaplingTreeAppend: %v", err)
	}

	err = tree.Close()
	if err != nil {
		t.Fatalf("tree.Close: %v", err)
	}

	err = tree.Close()
	if err == nil {
		t.Fatal("double Close should return error")
	}
}
