package storage

import (
	"bytes"
	"errors"
	"testing"
)

func TestVersionKey(t *testing.T) {
	if VersionKey("f", 0) != "f_v1" || VersionKey("f", 12) != "f_v12" {
		t.Fatalf("clés inattendues : %s %s", VersionKey("f", 0), VersionKey("f", 12))
	}
	// Le fichier « f_v2 » en version 1 ne se confond pas avec le fichier « f » en version 2.
	if VersionKey("f_v2", 1) == VersionKey("f", 2) {
		t.Fatal("deux versions de fichiers différents partagent une clé")
	}
}

func TestClaimVersion(t *testing.T) {
	s := openStore(t)
	alice, bob := []byte("alice"), []byte("bob")
	if err := s.ClaimVersion("f", 2, alice); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimVersion("f", 2, alice); err != nil {
		t.Fatalf("même auteur refusé : %v", err)
	}
	if err := s.ClaimVersion("f", 2, bob); !errors.Is(err, ErrOwnerMismatch) {
		t.Fatalf("version écrasée par un autre : %v", err)
	}
	if a, err := s.VersionAuthor("f", 2); err != nil || !bytes.Equal(a, alice) {
		t.Fatalf("auteur %q, %v", a, err)
	}
	if _, err := s.VersionAuthor("f", 3); !errors.Is(err, ErrNotFound) {
		t.Fatalf("version inconnue : %v", err)
	}
}

func TestTransferOwner(t *testing.T) {
	s := openStore(t)
	alice, bob := []byte("alice"), []byte("bob")
	if err := s.ClaimOwner("f", alice); err != nil {
		t.Fatal(err)
	}
	if err := s.TransferOwner("f", bob, 100); err != nil {
		t.Fatal(err)
	}
	owners, err := s.Owners("f")
	if err != nil || len(owners) != 2 || !bytes.Equal(owners[0].Key, bob) || owners[0].Until != 0 ||
		!bytes.Equal(owners[1].Key, alice) || owners[1].Until != 100 {
		t.Fatalf("propriétaires : %+v, %v", owners, err)
	}
	// Retour à alice : elle redevient propriétaire actuelle, sans rester dans l'historique.
	if err := s.TransferOwner("f", alice, 200); err != nil {
		t.Fatal(err)
	}
	owners, _ = s.Owners("f")
	if len(owners) != 2 || !bytes.Equal(owners[0].Key, alice) || !bytes.Equal(owners[1].Key, bob) {
		t.Fatalf("propriétaires après retour : %+v", owners)
	}
	if err := s.TransferOwner("absent", bob, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("transfert d'un fichier inconnu : %v", err)
	}
}

func TestDeleteFile(t *testing.T) {
	s := openStore(t)
	owner := []byte("alice")
	if err := s.ClaimOwner("f", owner); err != nil {
		t.Fatal(err)
	}
	for v := uint32(1); v <= 2; v++ {
		key := VersionKey("f", v)
		if err := s.ClaimVersion("f", v, owner); err != nil {
			t.Fatal(err)
		}
		if err := s.PutShare(key, Share{X: 1, Value: []byte("part"), Epoch: 1}); err != nil {
			t.Fatal(err)
		}
		if err := s.PutBlock(key, 0, bytes.NewReader([]byte("bloc"))); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PutRevocation("f", []byte("bob"), 5); err != nil {
		t.Fatal(err)
	}
	// Un autre fichier ne doit pas être touché.
	if err := s.PutShare(VersionKey("g", 1), Share{X: 1, Value: []byte("autre"), Epoch: 1}); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteFile("f"); err != nil {
		t.Fatal(err)
	}
	for v := uint32(1); v <= 2; v++ {
		if _, err := s.Share(VersionKey("f", v)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("part de la version %d encore là : %v", v, err)
		}
		if _, err := s.BlockIndexes(VersionKey("f", v)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("blocs de la version %d encore là : %v", v, err)
		}
	}
	if _, err := s.Owner("f"); !errors.Is(err, ErrNotFound) {
		t.Fatal("propriétaire encore enregistré")
	}
	if _, ok, _ := s.RevokedAt("f", []byte("bob")); ok {
		t.Fatal("retrait encore enregistré")
	}
	if _, err := s.Share(VersionKey("g", 1)); err != nil {
		t.Fatalf("un autre fichier a été effacé : %v", err)
	}
}
