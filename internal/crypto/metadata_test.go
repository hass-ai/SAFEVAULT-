package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func newUserKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestOwnName(t *testing.T) {
	alice := newUserKey(t)
	key, _ := NamesKey(alice)

	sealed, err := SealName(key, "dossier-médical.pdf")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("dossier")) {
		t.Fatal("le nom apparaît en clair")
	}
	name, err := OpenName(key, sealed)
	if err != nil || name != "dossier-médical.pdf" {
		t.Fatalf("nom %q, erreur %v", name, err)
	}

	// Deux chiffrements du même nom diffèrent (nonce aléatoire) : le coordinateur ne
	// peut pas repérer deux fichiers de même nom.
	again, _ := SealName(key, "dossier-médical.pdf")
	if bytes.Equal(sealed, again) {
		t.Fatal("deux chiffrements identiques")
	}

	bobKey, _ := NamesKey(newUserKey(t))
	if _, err := OpenName(bobKey, sealed); !errors.Is(err, ErrName) {
		t.Fatalf("un autre utilisateur lit le nom : %v", err)
	}
}

func TestSharedName(t *testing.T) {
	bob, charlie := newUserKey(t), newUserKey(t)

	sealed, err := SealNameFor(bob.Public().(ed25519.PublicKey), "rapport.txt")
	if err != nil {
		t.Fatal(err)
	}
	name, err := OpenNameFrom(bob, sealed)
	if err != nil || name != "rapport.txt" {
		t.Fatalf("nom %q, erreur %v", name, err)
	}
	if _, err := OpenNameFrom(charlie, sealed); !errors.Is(err, ErrName) {
		t.Fatalf("charlie lit un nom destiné à bob : %v", err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := OpenNameFrom(bob, sealed); !errors.Is(err, ErrName) {
		t.Fatalf("nom modifié accepté : %v", err)
	}
}

func TestPadding(t *testing.T) {
	for _, n := range []int{0, 1, 100, MinPaddedSize - 8, MinPaddedSize - 7, 1 << 20, 3<<20 + 5} {
		data := make([]byte, n)
		rand.Read(data)
		padded := Pad(data)
		size := len(padded)
		if size < MinPaddedSize || size&(size-1) != 0 || size < n+8 || (size > MinPaddedSize && size/2 >= n+8) {
			t.Fatalf("n = %d : taille arrondie %d", n, size)
		}
		got, err := Unpad(padded)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("n = %d : aller-retour incorrect (%v)", n, err)
		}
	}

	// Deux fichiers de tailles proches ont la même taille visible.
	if PaddedSize(70_000) != PaddedSize(120_000) {
		t.Fatal("les tailles 70 000 et 120 000 devraient être confondues")
	}

	bad := Pad([]byte("abc"))
	bad[0] = 0xff
	if _, err := Unpad(bad); !errors.Is(err, ErrPadding) {
		t.Fatalf("en-tête invalide accepté : %v", err)
	}
}
