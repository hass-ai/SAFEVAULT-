package main

import (
	"crypto/rand"
	"testing"

	"filippo.io/edwards25519"

	"safevault/internal/crypto"
	"safevault/internal/shamir"
)

// sealedFile chiffre un petit fichier comme le client et renvoie son premier bloc.
func sealedFile(t *testing.T, secret *edwards25519.Scalar, fileID string, content string) []byte {
	t.Helper()
	label := crypto.VersionContext(fileID, 1) // la démo ne dépose qu'une version
	key, err := crypto.DeriveFileKey(secret.Bytes(), label)
	if err != nil {
		t.Fatal(err)
	}
	fc, err := crypto.NewFileCipher(key, label)
	if err != nil {
		t.Fatal(err)
	}
	return fc.SealBlock(0, true, []byte(content))
}

func steal(shares []shamir.Share, indexes ...int) []stolenShare {
	var out []stolenShare
	for _, i := range indexes {
		s := shares[i]
		out = append(out, stolenShare{X: s.Index, Epoch: s.Epoch, value: s.Value.Bytes()})
	}
	return out
}

func TestAttackerWithoutRenewalReadsTheFile(t *testing.T) {
	secret, _ := shamir.NewSecret(rand.Reader)
	shares, _ := shamir.Split(secret, 3, 5, rand.Reader)
	block := sealedFile(t, secret, "f1", "secret défense")

	// Époque 1 : nœuds 1 et 2, puis nœuds 3 et 4, sans renouvellement entre les deux.
	outcome := tryDecrypt(steal(shares, 0, 1, 2, 3), 3, "f1", block)
	if !outcome.Success || outcome.Leaked != "secret défense" {
		t.Fatalf("l'attaquant aurait dû lire le fichier : %+v", outcome)
	}
}

func TestAttackerWithRenewalFails(t *testing.T) {
	secret, _ := shamir.NewSecret(rand.Reader)
	shares, _ := shamir.Split(secret, 3, 5, rand.Reader)
	block := sealedFile(t, secret, "f1", "secret défense")

	renewed, err := shamir.Refresh(shares, 3, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stolen := append(steal(shares, 0, 1), steal(renewed, 2, 3)...)
	outcome := tryDecrypt(stolen, 3, "f1", block)
	if outcome.Success {
		t.Fatalf("l'attaquant a lu le fichier malgré le renouvellement : %+v", outcome)
	}
	if outcome.Tried != 4 {
		t.Fatalf("%d combinaisons essayées, attendues 4", outcome.Tried)
	}
}

func TestAttackerNeedsThreshold(t *testing.T) {
	secret, _ := shamir.NewSecret(rand.Reader)
	shares, _ := shamir.Split(secret, 3, 5, rand.Reader)
	block := sealedFile(t, secret, "f1", "secret défense")

	if outcome := tryDecrypt(steal(shares, 0, 1), 3, "f1", block); outcome.Success || outcome.Tried != 0 {
		t.Fatalf("2 parts ne devraient rien donner : %+v", outcome)
	}
}

func TestCombinations(t *testing.T) {
	if got := len(combinations(5, 3)); got != 10 {
		t.Fatalf("%d combinaisons de 3 parmi 5, attendues 10", got)
	}
}
