package storage

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func openStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestShareRoundTrip(t *testing.T) {
	s := openStore(t)

	want := Share{X: 3, Value: []byte("part"), Epoch: 7}
	if err := s.PutShare("f1", want); err != nil {
		t.Fatal(err)
	}
	got, err := s.Share("f1")
	if err != nil {
		t.Fatal(err)
	}
	if got.X != want.X || got.Epoch != want.Epoch || !bytes.Equal(got.Value, want.Value) {
		t.Fatalf("part lue %+v, attendue %+v", got, want)
	}
}

func TestShareNotFound(t *testing.T) {
	s := openStore(t)
	if _, err := s.Share("absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("erreur %v, attendue ErrNotFound", err)
	}
}

func TestPutShareReplacesOlderEpoch(t *testing.T) {
	s := openStore(t)

	s.PutShare("f1", Share{X: 1, Value: []byte("ancienne"), Epoch: 1})
	s.PutShare("f1", Share{X: 1, Value: []byte("nouvelle"), Epoch: 2})

	got, err := s.Share("f1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Epoch != 2 || string(got.Value) != "nouvelle" {
		t.Fatalf("part lue %+v", got)
	}
}

func TestOwner(t *testing.T) {
	s := openStore(t)

	if err := s.ClaimOwner("f1", []byte("alice")); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimOwner("f1", []byte("alice")); err != nil {
		t.Fatalf("même propriétaire refusé : %v", err)
	}
	if err := s.ClaimOwner("f1", []byte("bob")); !errors.Is(err, ErrOwnerMismatch) {
		t.Fatalf("erreur %v, attendue ErrOwnerMismatch", err)
	}
	owner, err := s.Owner("f1")
	if err != nil || string(owner) != "alice" {
		t.Fatalf("propriétaire %q, erreur %v", owner, err)
	}
	if _, err := s.Owner("absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("erreur %v, attendue ErrNotFound", err)
	}
}

func TestCommitEpoch(t *testing.T) {
	s := openStore(t)

	s.PutShare("f1", Share{X: 2, Value: []byte("e1"), Epoch: 1})
	if err := s.PutPendingShare("f1", Share{X: 2, Value: []byte("e2"), Epoch: 2}); err != nil {
		t.Fatal(err)
	}

	// Tant que l'époque n'est pas validée, la part en service reste l'ancienne.
	got, _ := s.Share("f1")
	if got.Epoch != 1 {
		t.Fatalf("époque en service %d avant validation, attendue 1", got.Epoch)
	}

	if err := s.CommitEpoch(2); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Share("f1")
	if got.Epoch != 2 || string(got.Value) != "e2" {
		t.Fatalf("part en service %+v après validation", got)
	}

	var count int
	s.db.QueryRow(`SELECT COUNT(*) FROM shares WHERE file_id = 'f1'`).Scan(&count)
	if count != 1 {
		t.Fatalf("%d parts pour f1 après validation, l'ancienne n'a pas été effacée", count)
	}
}

func TestAbortEpoch(t *testing.T) {
	s := openStore(t)

	s.PutShare("f1", Share{X: 2, Value: []byte("e1"), Epoch: 1})
	s.PutPendingShare("f1", Share{X: 2, Value: []byte("e2"), Epoch: 2})
	s.PutSubShares(2, 4, []SubShare{{FileID: "f1", Value: []byte("d")}})

	if err := s.AbortEpoch(2); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Share("f1")
	if got.Epoch != 1 {
		t.Fatalf("part en service %+v après annulation", got)
	}
	subs, _ := s.SubShares(2)
	if len(subs) != 0 {
		t.Fatalf("%d sous-parts restantes après annulation", len(subs))
	}
}

func TestSubShares(t *testing.T) {
	s := openStore(t)

	s.PutSubShares(5, 1, []SubShare{{FileID: "f1", Value: []byte("a")}, {FileID: "f2", Value: []byte("b")}})
	s.PutSubShares(5, 3, []SubShare{{FileID: "f1", Value: []byte("c")}})
	s.PutSubShares(6, 1, []SubShare{{FileID: "f1", Value: []byte("autre époque")}})

	subs, err := s.SubShares(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 3 {
		t.Fatalf("%d sous-parts pour l'époque 5, attendues 3", len(subs))
	}
	if subs[0].FileID != "f1" || subs[0].FromX != 1 || subs[1].FromX != 3 {
		t.Fatalf("sous-parts mal ordonnées : %+v", subs)
	}

	if err := s.PutSubShares(5, 1, []SubShare{{FileID: "../x", Value: nil}}); !errors.Is(err, ErrInvalidFileID) {
		t.Fatalf("erreur %v, attendue ErrInvalidFileID", err)
	}
}

func TestBlocks(t *testing.T) {
	s := openStore(t)

	for _, i := range []uint32{2, 0, 10, 1} {
		data := bytes.Repeat([]byte{byte(i)}, 1000)
		if err := s.PutBlock("f1", i, bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
	}

	indexes, err := s.BlockIndexes("f1")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(indexes, []uint32{0, 1, 2, 10}) {
		t.Fatalf("numéros de blocs %v", indexes)
	}

	r, err := s.OpenBlock("f1", 10)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(r)
	r.Close()
	if !bytes.Equal(data, bytes.Repeat([]byte{10}, 1000)) {
		t.Fatal("contenu du bloc 10 incorrect")
	}

	if _, err := s.OpenBlock("f1", 3); !errors.Is(err, ErrNotFound) {
		t.Fatalf("erreur %v, attendue ErrNotFound", err)
	}
	if _, err := s.BlockIndexes("absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("erreur %v, attendue ErrNotFound", err)
	}
}

func TestBlockOverwrite(t *testing.T) {
	s := openStore(t)

	s.PutBlock("f1", 0, bytes.NewReader([]byte("v1")))
	s.PutBlock("f1", 0, bytes.NewReader([]byte("v2")))

	r, _ := s.OpenBlock("f1", 0)
	data, _ := io.ReadAll(r)
	r.Close()
	if string(data) != "v2" {
		t.Fatalf("contenu %q, attendu v2", data)
	}

	entries, _ := os.ReadDir(filepath.Join(s.dir, "blocks", "f1"))
	if len(entries) != 1 {
		t.Fatalf("%d fichiers dans le dossier du fichier, fichier temporaire oublié ?", len(entries))
	}
}

func TestInvalidFileID(t *testing.T) {
	s := openStore(t)

	for _, id := range []string{"", "../etc", "a/b", "a b", string(make([]byte, 200))} {
		if err := s.PutBlock(id, 0, bytes.NewReader(nil)); !errors.Is(err, ErrInvalidFileID) {
			t.Errorf("PutBlock(%q) : erreur %v, attendue ErrInvalidFileID", id, err)
		}
		if err := s.PutShare(id, Share{}); !errors.Is(err, ErrInvalidFileID) {
			t.Errorf("PutShare(%q) : erreur %v, attendue ErrInvalidFileID", id, err)
		}
	}
}

func TestSecureDeleteEnabled(t *testing.T) {
	s := openStore(t)

	var secureDelete int
	if err := s.db.QueryRow(`PRAGMA secure_delete`).Scan(&secureDelete); err != nil {
		t.Fatal(err)
	}
	if secureDelete != 1 {
		t.Fatalf("secure_delete = %d, attendu 1", secureDelete)
	}
}

func TestOldShareErasedFromDisk(t *testing.T) {
	s := openStore(t)

	secret := []byte("ANCIENNE-PART-TRES-RECONNAISSABLE")
	s.PutShare("f1", Share{X: 1, Value: secret, Epoch: 1})
	s.PutPendingShare("f1", Share{X: 1, Value: []byte("nouvelle"), Epoch: 2})
	if err := s.CommitEpoch(2); err != nil {
		t.Fatal(err)
	}
	s.Close()

	raw, err := os.ReadFile(filepath.Join(s.dir, "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, secret) {
		t.Fatal("l'ancienne part est encore lisible dans le fichier de la base")
	}
}

func TestReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.PutShare("f1", Share{X: 1, Value: []byte("p"), Epoch: 3})
	s.Close()

	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.Share("f1")
	if err != nil || got.Epoch != 3 {
		t.Fatalf("part %+v après réouverture, erreur %v", got, err)
	}
}
