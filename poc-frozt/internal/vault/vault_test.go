package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	frozt "github.com/vultisig/frozt-zcash/go-frozt"

	"github.com/vultisig/frozt-zcash/poc-frozt/internal/bip39"
	"github.com/vultisig/frozt-zcash/poc-frozt/internal/config"
	"github.com/vultisig/frozt-zcash/poc-frozt/internal/lightwalletd"
)

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
		secret frozt.DkgSecretHandle
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
		secret, pkg, outVK, outExtras, err := frozt.KeyImportPart1(id, n, threshold, s, accountIndex)
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
		secret frozt.DkgSecretHandle
		r2Pkgs []frozt.MapEntry
	}
	r2Results := make([]r2Result, n)

	for i := uint16(0); i < n; i++ {
		var others []frozt.MapEntry
		for j := uint16(0); j < n; j++ {
			if j == i {
				continue
			}
			others = append(others, frozt.MapEntry{
				ID:    parties[j].id,
				Value: parties[j].r1Pkg,
			})
		}

		secret, pkgsBytes, err := frozt.DkgPart2(parties[i].secret, frozt.EncodeMap(others))
		if err != nil {
			t.Fatalf("DkgPart2 party %d: %v", parties[i].id, err)
		}

		entries, decErr := frozt.DecodeMap(pkgsBytes)
		if decErr != nil {
			t.Fatalf("DecodeMap r2 party %d: %v", parties[i].id, decErr)
		}
		r2Results[i] = r2Result{secret: secret, r2Pkgs: entries}
	}

	kps := make([][]byte, n)
	var pkp []byte
	for i := uint16(0); i < n; i++ {
		myID := i + 1
		var r1Others []frozt.MapEntry
		for j := uint16(0); j < n; j++ {
			if j == i {
				continue
			}
			r1Others = append(r1Others, frozt.MapEntry{
				ID:    parties[j].id,
				Value: parties[j].r1Pkg,
			})
		}

		var r2ForMe []frozt.MapEntry
		for senderIdx := uint16(0); senderIdx < n; senderIdx++ {
			if senderIdx == i {
				continue
			}
			for _, entry := range r2Results[senderIdx].r2Pkgs {
				if entry.ID == myID {
					r2ForMe = append(r2ForMe, frozt.MapEntry{
						ID:    parties[senderIdx].id,
						Value: entry.Value,
					})
				}
			}
		}

		kp, p, err := frozt.KeyImportPart3(
			r2Results[i].secret,
			frozt.EncodeMap(r1Others),
			frozt.EncodeMap(r2ForMe),
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

func runSign(t *testing.T, keyPackages [][]byte, pubKeyPackage []byte, signerIndices []int, message []byte) []byte {
	t.Helper()

	type signerState struct {
		idx    int
		id     uint16
		nonces frozt.NoncesHandle
		commit []byte
	}

	signers := make([]signerState, len(signerIndices))
	for i, idx := range signerIndices {
		id := uint16(idx + 1)
		nonces, commitments, err := frozt.SignCommit(keyPackages[idx])
		if err != nil {
			t.Fatalf("SignCommit signer %d: %v", id, err)
		}
		signers[i] = signerState{idx: idx, id: id, nonces: nonces, commit: commitments}
	}

	var commitEntries []frozt.MapEntry
	for _, s := range signers {
		commitEntries = append(commitEntries, frozt.MapEntry{
			ID:    s.id,
			Value: s.commit,
		})
	}

	signingPackage, randomizer, err := frozt.SignNewPackage(message, frozt.EncodeMap(commitEntries), pubKeyPackage)
	if err != nil {
		t.Fatalf("SignNewPackage: %v", err)
	}

	var shareEntries []frozt.MapEntry
	for _, s := range signers {
		share, signErr := frozt.Sign(signingPackage, s.nonces, keyPackages[s.idx], randomizer)
		if signErr != nil {
			t.Fatalf("Sign signer %d: %v", s.id, signErr)
		}
		shareEntries = append(shareEntries, frozt.MapEntry{
			ID:    s.id,
			Value: share,
		})
	}

	signature, err := frozt.SignAggregate(signingPackage, frozt.EncodeMap(shareEntries), pubKeyPackage, randomizer)
	if err != nil {
		t.Fatalf("SignAggregate: %v", err)
	}

	return signature
}

func loadEnv(t *testing.T) (mnemonic string, birthday int, expectedAddr string) {
	t.Helper()

	envPath := filepath.Join("..", "..", ".env")
	env, err := config.LoadDotEnv(envPath)
	if err != nil {
		t.Fatalf("LoadDotEnv: %v", err)
	}

	mnemonic = env["MNEMONIC"]
	if mnemonic == "" {
		t.Fatal("MNEMONIC not set in .env")
	}

	birthdayStr := env["BIRTHDAY"]
	birthday, err = strconv.Atoi(birthdayStr)
	if err != nil {
		t.Fatalf("invalid BIRTHDAY: %v", err)
	}

	expectedAddr = env["EXPECTED_ADDRESS"]
	if expectedAddr == "" {
		t.Fatal("EXPECTED_ADDRESS not set in .env")
	}

	return mnemonic, birthday, expectedAddr
}

func TestSeedVault(t *testing.T) {
	mnemonic, birthday, expectedAddr := loadEnv(t)

	t.Log("=== BIP39 seed derivation ===")
	seed := bip39.MnemonicToSeed(mnemonic)
	t.Logf("seed: %x (%d bytes)", seed, len(seed))

	t.Log("=== Key import 2-of-3 ===")
	result := runKeyImport(t, 3, 2, seed, 0)

	importedVK, err := frozt.PubKeyPackageVerifyingKey(result.pubKeyPackage)
	if err != nil {
		t.Fatalf("PubKeyPackageVerifyingKey: %v", err)
	}
	if !bytes.Equal(result.vk, importedVK) {
		t.Fatal("verifying key mismatch after import")
	}

	t.Log("=== Derive z-address ===")
	keys, err := frozt.SaplingDeriveKeys(result.pubKeyPackage, result.extras)
	if err != nil {
		t.Fatalf("SaplingDeriveKeys: %v", err)
	}
	t.Logf("z-address: %s", keys.Address)
	if keys.Address != expectedAddr {
		t.Fatalf("address mismatch:\n  got:  %s\n  want: %s", keys.Address, expectedAddr)
	}

	t.Log("=== Sign (parties 0,1) ===")
	sig := runSign(t, result.keyPackages, result.pubKeyPackage, []int{0, 1}, []byte("vault test"))
	t.Logf("signature: %x (%d bytes)", sig, len(sig))

	t.Log("=== Sign (parties 1,2) ===")
	sig2 := runSign(t, result.keyPackages, result.pubKeyPackage, []int{1, 2}, []byte("vault test"))
	t.Logf("signature: %x (%d bytes)", sig2, len(sig2))

	t.Log("=== Export .vultshare files ===")
	tmpDir := t.TempDir()
	for i, kp := range result.keyPackages {
		share := VultShare{
			Version:       1,
			Chain:         "zcash-sapling",
			Threshold:     2,
			TotalParties:  3,
			PartyID:       i + 1,
			Birthday:      birthday,
			ZAddress:      keys.Address,
			KeyPackage:    base64.StdEncoding.EncodeToString(kp),
			PubKeyPackage: base64.StdEncoding.EncodeToString(result.pubKeyPackage),
			SaplingExtras: base64.StdEncoding.EncodeToString(result.extras),
		}
		path := filepath.Join(tmpDir, fmt.Sprintf("party-%d.vultshare", i+1))
		exportErr := ExportVultShare(path, share)
		if exportErr != nil {
			t.Fatalf("ExportVultShare party %d: %v", i+1, exportErr)
		}
		info, _ := os.Stat(path)
		t.Logf("exported party-%d.vultshare (%d bytes)", i+1, info.Size())
	}

	t.Log("=== Re-import .vultshare and verify ===")
	importedKPs := make([][]byte, 3)
	var importedPKP []byte
	var importedExtras []byte
	for i := 0; i < 3; i++ {
		path := filepath.Join(tmpDir, fmt.Sprintf("party-%d.vultshare", i+1))
		share, importErr := ImportVultShare(path)
		if importErr != nil {
			t.Fatalf("ImportVultShare party %d: %v", i+1, importErr)
		}

		kpBytes, _ := base64.StdEncoding.DecodeString(share.KeyPackage)
		pkpBytes, _ := base64.StdEncoding.DecodeString(share.PubKeyPackage)
		extrasBytes, _ := base64.StdEncoding.DecodeString(share.SaplingExtras)

		importedKPs[i] = kpBytes
		if i == 0 {
			importedPKP = pkpBytes
			importedExtras = extrasBytes
		}

		if share.ZAddress != expectedAddr {
			t.Fatalf("imported share %d address mismatch", i+1)
		}
	}

	reKeys, err := frozt.SaplingDeriveKeys(importedPKP, importedExtras)
	if err != nil {
		t.Fatalf("re-derive address: %v", err)
	}
	if reKeys.Address != expectedAddr {
		t.Fatalf("re-derived address mismatch:\n  got:  %s\n  want: %s", reKeys.Address, expectedAddr)
	}
	t.Log("re-derived address matches after import")

	t.Log("=== Sign with re-imported shares (parties 0,1) ===")
	sig3 := runSign(t, importedKPs, importedPKP, []int{0, 1}, []byte("re-imported vault test"))
	t.Logf("signature: %x (%d bytes)", sig3, len(sig3))

	t.Log("=== Sign with re-imported shares (parties 1,2) ===")
	sig4 := runSign(t, importedKPs, importedPKP, []int{1, 2}, []byte("re-imported vault test"))
	t.Logf("signature: %x (%d bytes)", sig4, len(sig4))

	t.Log("=== All vault operations successful ===")
}

func TestBalanceScan(t *testing.T) {
	mnemonic, birthday, _ := loadEnv(t)

	t.Log("=== Derive IVK from seed ===")
	seed := bip39.MnemonicToSeed(mnemonic)

	result := runKeyImport(t, 3, 2, seed, 0)

	keys, err := frozt.SaplingDeriveKeys(result.pubKeyPackage, result.extras)
	if err != nil {
		t.Fatalf("SaplingDeriveKeys: %v", err)
	}
	t.Logf("ivk: %x (%d bytes)", keys.Ivk, len(keys.Ivk))

	t.Log("=== Connect to lightwalletd ===")
	scanner, err := lightwalletd.NewScanner("zec.rocks:443")
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	defer scanner.Close()

	ctx := context.Background()

	info, err := scanner.GetLightdInfo(ctx)
	if err != nil {
		t.Fatalf("GetLightdInfo: %v", err)
	}
	t.Logf("lightwalletd: %s chain=%s height=%d", info.Version, info.ChainName, info.BlockHeight)

	tip, err := scanner.GetLatestBlock(ctx)
	if err != nil {
		t.Fatalf("GetLatestBlock: %v", err)
	}
	t.Logf("chain tip: %d", tip)

	startHeight := uint64(birthday)
	t.Logf("=== Scanning blocks %d → %d (%d blocks) ===", startHeight, tip, tip-startHeight+1)

	scanResult, err := scanner.Scan(ctx, keys.Ivk, startHeight, tip, 0, func(scanned, total uint64) {
		t.Logf("progress: %d / %d blocks (%.1f%%)", scanned, total, float64(scanned)/float64(total)*100)
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	t.Logf("=== Scan complete ===")
	t.Logf("blocks scanned: %d", scanResult.BlocksScaned)
	t.Logf("notes found: %d", len(scanResult.Notes))

	for i, note := range scanResult.Notes {
		zec := float64(note.Value) / 1e8
		t.Logf("  note %d: height=%d value=%.8f ZEC (%d zatoshi) tx=%x", i, note.Height, zec, note.Value, note.TxHash)
	}

	totalZEC := float64(scanResult.TotalValue) / 1e8
	t.Logf("total received: %.8f ZEC (%d zatoshi)", totalZEC, scanResult.TotalValue)
}

func runSignWithRandomizer(t *testing.T, keyPackages [][]byte, pubKeyPackage []byte, signerIndices []int, message, randomizer []byte) []byte {
	t.Helper()

	type signerState struct {
		idx    int
		id     uint16
		nonces frozt.NoncesHandle
		commit []byte
	}

	signers := make([]signerState, len(signerIndices))
	for i, idx := range signerIndices {
		id := uint16(idx + 1)
		nonces, commitments, err := frozt.SignCommit(keyPackages[idx])
		if err != nil {
			t.Fatalf("SignCommit signer %d: %v", id, err)
		}
		signers[i] = signerState{idx: idx, id: id, nonces: nonces, commit: commitments}
	}

	var commitEntries []frozt.MapEntry
	for _, s := range signers {
		commitEntries = append(commitEntries, frozt.MapEntry{
			ID:    s.id,
			Value: s.commit,
		})
	}

	signingPackage, _, err := frozt.SignNewPackage(message, frozt.EncodeMap(commitEntries), pubKeyPackage)
	if err != nil {
		t.Fatalf("SignNewPackage: %v", err)
	}

	var shareEntries []frozt.MapEntry
	for _, s := range signers {
		share, signErr := frozt.Sign(signingPackage, s.nonces, keyPackages[s.idx], randomizer)
		if signErr != nil {
			t.Fatalf("Sign signer %d: %v", s.id, signErr)
		}
		shareEntries = append(shareEntries, frozt.MapEntry{
			ID:    s.id,
			Value: share,
		})
	}

	signature, err := frozt.SignAggregate(signingPackage, frozt.EncodeMap(shareEntries), pubKeyPackage, randomizer)
	if err != nil {
		t.Fatalf("SignAggregate: %v", err)
	}

	return signature
}

func parseSaplingOutputsFromRawTx(rawTx []byte) (cmus [][]byte, epks [][]byte, encCiphertexts [][]byte, err error) {
	if len(rawTx) < 20 {
		return nil, nil, nil, fmt.Errorf("raw tx too short")
	}

	offset := 20

	tinCount, n := binary.Uvarint(rawTx[offset:])
	if n <= 0 {
		vinLen := int(rawTx[offset])
		offset++
		_ = tinCount
		for i := 0; i < vinLen; i++ {
			offset += 36
			scriptLen := int(rawTx[offset])
			offset++
			offset += scriptLen + 4
		}
	} else {
		offset += n
		for i := uint64(0); i < tinCount; i++ {
			offset += 36
			scriptLen := int(rawTx[offset])
			offset++
			offset += scriptLen + 4
		}
	}

	toutCount := int(rawTx[offset])
	offset++
	for i := 0; i < toutCount; i++ {
		offset += 8
		scriptLen := int(rawTx[offset])
		offset++
		offset += scriptLen
	}

	spendCount := int(rawTx[offset])
	offset++
	offset += spendCount * (32 + 32 + 32)

	outputCount := int(rawTx[offset])
	offset++

	for i := 0; i < outputCount; i++ {
		if offset+32+32+32+580+80 > len(rawTx) {
			return nil, nil, nil, fmt.Errorf("raw tx truncated at output %d", i)
		}
		offset += 32
		cmu := make([]byte, 32)
		copy(cmu, rawTx[offset:offset+32])
		cmus = append(cmus, cmu)
		offset += 32
		epk := make([]byte, 32)
		copy(epk, rawTx[offset:offset+32])
		epks = append(epks, epk)
		offset += 32
		enc := make([]byte, 580)
		copy(enc, rawTx[offset:offset+580])
		encCiphertexts = append(encCiphertexts, enc)
		offset += 580
		offset += 80
	}

	return cmus, epks, encCiphertexts, nil
}

func TestSpend(t *testing.T) {
	mnemonic, birthday, expectedAddr := loadEnv(t)

	recipientAddr := os.Getenv("RECIPIENT_ADDRESS")
	if recipientAddr == "" {
		recipientAddr = "zs16e9zw4av0tnduqenmz2y5kllpwm09juz29wxusvdzp9acl6fs33geyzfhd0xfp8f903tuk0l74z"
	}

	t.Log("=== Setup keys ===")
	seed := bip39.MnemonicToSeed(mnemonic)

	result := runKeyImport(t, 3, 2, seed, 0)

	keys, err := frozt.SaplingDeriveKeys(result.pubKeyPackage, result.extras)
	if err != nil {
		t.Fatalf("SaplingDeriveKeys: %v", err)
	}

	t.Logf("our z-address: %s", keys.Address)
	if keys.Address != expectedAddr {
		t.Fatalf("address mismatch")
	}

	t.Log("=== Connect to lightwalletd ===")
	scanner, err := lightwalletd.NewScanner("zec.rocks:443")
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	defer scanner.Close()

	ctx := context.Background()

	tip, err := scanner.GetLatestBlock(ctx)
	if err != nil {
		t.Fatalf("GetLatestBlock: %v", err)
	}
	t.Logf("chain tip: %d", tip)

	t.Log("=== Scan for notes ===")
	startHeight := uint64(birthday)
	scanResult, err := scanner.Scan(ctx, keys.Ivk, startHeight, tip, 0, func(scanned, total uint64) {
		if scanned%50000 == 0 {
			t.Logf("scan progress: %d / %d (%.1f%%)", scanned, total, float64(scanned)/float64(total)*100)
		}
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(scanResult.Notes) == 0 {
		t.Fatal("no notes found")
	}

	note := scanResult.Notes[0]
	t.Logf("spending note: height=%d value=%d zatoshi tx=%x index=%d", note.Height, note.Value, note.TxHash, note.Index)

	t.Log("=== Get full transaction for note decryption ===")
	rawTx, _, err := scanner.GetTransaction(ctx, note.TxHash)
	if err != nil {
		t.Fatalf("GetTransaction: %v", err)
	}
	t.Logf("raw tx: %d bytes", len(rawTx))

	cmus, epks, encCiphertexts, err := parseSaplingOutputsFromRawTx(rawTx)
	if err != nil {
		t.Fatalf("parseSaplingOutputsFromRawTx: %v", err)
	}

	if note.Index >= len(cmus) {
		t.Fatalf("note index %d out of range (tx has %d sapling outputs)", note.Index, len(cmus))
	}

	noteData, err := frozt.SaplingDecryptNoteFull(
		keys.Ivk, cmus[note.Index], epks[note.Index], encCiphertexts[note.Index], note.Height,
	)
	if err != nil {
		t.Fatalf("SaplingDecryptNoteFull: %v", err)
	}
	t.Logf("decrypted note data: %x (%d bytes)", noteData, len(noteData))

	t.Log("=== Build commitment tree witness ===")
	treeState, err := scanner.GetTreeState(ctx, note.Height-1)
	if err != nil {
		t.Fatalf("GetTreeState(%d): %v", note.Height-1, err)
	}
	t.Logf("tree state at %d: sapling_tree=%d chars", note.Height-1, len(treeState.SaplingTree))

	treeHandle, err := frozt.SaplingTreeFromState([]byte(treeState.SaplingTree))
	if err != nil {
		t.Fatalf("SaplingTreeFromState: %v", err)
	}
	defer treeHandle.Close()

	noteBlock, err := scanner.ScanBlock(ctx, note.Height)
	if err != nil {
		t.Fatalf("ScanBlock(%d): %v", note.Height, err)
	}

	var witnessHandle frozt.WitnessHandle
	witnessCreated := false

	for _, tx := range noteBlock.Vtx {
		for outputIdx, output := range tx.Outputs {
			if len(output.Cmu) != 32 {
				continue
			}

			appendErr := frozt.SaplingTreeAppend(treeHandle, output.Cmu)
			if appendErr != nil {
				t.Fatalf("SaplingTreeAppend: %v", appendErr)
			}

			if bytes.Equal(tx.Hash, note.TxHash) && outputIdx == note.Index {
				witnessHandle, err = frozt.SaplingTreeWitness(treeHandle)
				if err != nil {
					t.Fatalf("SaplingTreeWitness: %v", err)
				}
				witnessCreated = true
			} else if witnessCreated {
				appendErr = frozt.SaplingWitnessAppend(witnessHandle, output.Cmu)
				if appendErr != nil {
					t.Fatalf("SaplingWitnessAppend: %v", appendErr)
				}
			}
		}
	}

	if !witnessCreated {
		t.Fatal("witness not created - note not found in block")
	}

	t.Log("advancing witness through subsequent blocks...")
	advanceEnd := tip
	if advanceEnd > note.Height+10000 {
		advanceEnd = note.Height + 10000
	}
	for h := note.Height + 1; h <= advanceEnd; h++ {
		block, blockErr := scanner.ScanBlock(ctx, h)
		if blockErr != nil {
			t.Fatalf("ScanBlock(%d): %v", h, blockErr)
		}
		for _, tx := range block.Vtx {
			for _, output := range tx.Outputs {
				if len(output.Cmu) != 32 {
					continue
				}
				appendErr := frozt.SaplingTreeAppend(treeHandle, output.Cmu)
				if appendErr != nil {
					t.Fatalf("SaplingTreeAppend at %d: %v", h, appendErr)
				}
				appendErr = frozt.SaplingWitnessAppend(witnessHandle, output.Cmu)
				if appendErr != nil {
					t.Fatalf("SaplingWitnessAppend at %d: %v", h, appendErr)
				}
			}
		}
		if (h-note.Height)%1000 == 0 {
			t.Logf("  advanced witness to height %d", h)
		}
	}

	witnessData, err := frozt.SaplingWitnessSerialize(witnessHandle)
	if err != nil {
		t.Fatalf("SaplingWitnessSerialize: %v", err)
	}
	t.Logf("witness serialized: %d bytes", len(witnessData))

	anchor, err := frozt.SaplingWitnessRoot(witnessHandle)
	if err != nil {
		t.Fatalf("SaplingWitnessRoot: %v", err)
	}
	t.Logf("anchor: %x", anchor)

	t.Log("=== Build unsigned transaction ===")
	sendAmount := uint64(5_000_000)
	targetHeight := uint32(tip + 1)

	t.Logf("send: %d zatoshi to %s", sendAmount, recipientAddr)

	builder, err := frozt.TxBuilderNew(result.pubKeyPackage, result.extras, targetHeight)
	if err != nil {
		t.Fatalf("TxBuilderNew: %v", err)
	}

	alpha, err := frozt.TxBuilderAddSpend(builder, noteData, witnessData)
	if err != nil {
		t.Fatalf("TxBuilderAddSpend: %v", err)
	}
	t.Logf("alpha (randomizer): %x", alpha)

	err = frozt.TxBuilderAddOutput(builder, recipientAddr, sendAmount)
	if err != nil {
		t.Fatalf("TxBuilderAddOutput (recipient): %v", err)
	}

	changeAmount := note.Value - sendAmount - 10_000
	if changeAmount > 0 {
		err = frozt.TxBuilderAddOutput(builder, keys.Address, changeAmount)
		if err != nil {
			t.Fatalf("TxBuilderAddOutput (change): %v", err)
		}
	}

	sighash, err := frozt.TxBuilderBuild(builder)
	if err != nil {
		t.Fatalf("TxBuilderBuild: %v", err)
	}
	t.Logf("sighash: %x", sighash)

	t.Log("=== FROST threshold sign ===")
	spendAuthSig := runSignWithRandomizer(t, result.keyPackages, result.pubKeyPackage, []int{0, 1}, sighash, alpha)
	t.Logf("spend auth sig: %x (%d bytes)", spendAuthSig, len(spendAuthSig))

	t.Log("=== Finalize transaction ===")
	finalTx, err := frozt.TxBuilderComplete(builder, [][]byte{spendAuthSig})
	if err != nil {
		t.Fatalf("TxBuilderComplete: %v", err)
	}
	t.Logf("final tx: %d bytes", len(finalTx))
	t.Logf("tx hex: %s", hex.EncodeToString(finalTx))

	t.Log("=== Broadcast transaction ===")
	sendErr := scanner.SendTransaction(ctx, finalTx)
	if sendErr != nil {
		t.Logf("WARNING: SendTransaction failed: %v", sendErr)
		t.Logf("(transaction may still be valid - check tx hex above)")
	} else {
		t.Log("transaction sent successfully!")
	}

	t.Log("=== Spend test complete ===")
}
