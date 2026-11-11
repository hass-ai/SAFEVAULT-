package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"testing/iotest"
)

func testCipher(t testing.TB, fileID string) *FileCipher {
	t.Helper()
	secret := make([]byte, SecretSize)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	key, err := DeriveFileKey(secret, []byte(fileID))
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewFileCipher(key, []byte(fileID))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func randomBytes(t testing.TB, n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRoundTrip(t *testing.T) {
	const bs = 64
	for _, size := range []int{0, 1, bs - 1, bs, bs + 1, 2 * bs, 3*bs + 7} {
		t.Run(fmt.Sprintf("%d octets", size), func(t *testing.T) {
			c := testCipher(t, "f")
			plain := randomBytes(t, size)
			// OneByteReader : vérifie qu'on gère les lectures partielles.
			blocks, err := c.EncryptBlocks(iotest.OneByteReader(bytes.NewReader(plain)), bs)
			if err != nil {
				t.Fatal(err)
			}
			wantBlocks := (size + bs - 1) / bs
			if wantBlocks == 0 {
				wantBlocks = 1
			}
			if len(blocks) != wantBlocks {
				t.Fatalf("%d blocs, attendu %d", len(blocks), wantBlocks)
			}
			for i, b := range blocks {
				if i < len(blocks)-1 && len(b) != bs+Overhead {
					t.Fatalf("bloc %d : %d octets", i, len(b))
				}
			}
			var out bytes.Buffer
			if err := c.DecryptBlocks(blocks, &out); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out.Bytes(), plain) {
				t.Fatal("clair différent après aller-retour")
			}
		})
	}
}

func encrypt(t *testing.T, c *FileCipher, n int) [][]byte {
	t.Helper()
	blocks, err := c.EncryptBlocks(bytes.NewReader(randomBytes(t, n)), 16)
	if err != nil {
		t.Fatal(err)
	}
	return blocks
}

func expectDecryptError(t *testing.T, c *FileCipher, blocks [][]byte) {
	t.Helper()
	if err := c.DecryptBlocks(blocks, &bytes.Buffer{}); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("attendu ErrDecrypt, obtenu %v", err)
	}
}

// Les attaques qu'un nœud de stockage malveillant peut tenter sur les blocs.
func TestAttacks(t *testing.T) {
	t.Run("octet modifié", func(t *testing.T) {
		c := testCipher(t, "f")
		blocks := encrypt(t, c, 40)
		blocks[1][3] ^= 1
		expectDecryptError(t, c, blocks)
	})
	t.Run("blocs échangés", func(t *testing.T) {
		c := testCipher(t, "f")
		blocks := encrypt(t, c, 40)
		blocks[0], blocks[1] = blocks[1], blocks[0]
		expectDecryptError(t, c, blocks)
	})
	t.Run("dernier bloc supprimé", func(t *testing.T) {
		c := testCipher(t, "f")
		blocks := encrypt(t, c, 40)
		expectDecryptError(t, c, blocks[:len(blocks)-1])
	})
	t.Run("bloc ajouté à la fin", func(t *testing.T) {
		c := testCipher(t, "f")
		blocks := encrypt(t, c, 40)
		expectDecryptError(t, c, append(blocks, blocks[0]))
	})
	t.Run("bloc d'un autre fichier", func(t *testing.T) {
		// Même clé (par hypothèse), identifiant différent : le bloc est rejeté.
		key := randomBytes(t, KeySize)
		a, _ := NewFileCipher(key, []byte("a"))
		b, _ := NewFileCipher(key, []byte("b"))
		blocksA := encrypt(t, a, 40)
		blocksB := encrypt(t, b, 40)
		blocksA[0] = blocksB[0]
		expectDecryptError(t, a, blocksA)
	})
	t.Run("mauvaise clé", func(t *testing.T) {
		blocks := encrypt(t, testCipher(t, "f"), 40)
		expectDecryptError(t, testCipher(t, "f"), blocks)
	})
	t.Run("bloc vide", func(t *testing.T) {
		c := testCipher(t, "f")
		expectDecryptError(t, c, [][]byte{{}})
	})
	t.Run("aucun bloc", func(t *testing.T) {
		c := testCipher(t, "f")
		if err := c.DecryptBlocks(nil, &bytes.Buffer{}); !errors.Is(err, ErrNoBlocks) {
			t.Fatalf("attendu ErrNoBlocks, obtenu %v", err)
		}
	})
}

func TestDeriveFileKey(t *testing.T) {
	secret := randomBytes(t, SecretSize)
	k1, _ := DeriveFileKey(secret, []byte("a"))
	k2, _ := DeriveFileKey(secret, []byte("a"))
	k3, _ := DeriveFileKey(secret, []byte("b"))
	if len(k1) != KeySize {
		t.Fatalf("clé de %d octets", len(k1))
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("la dérivation doit être déterministe")
	}
	if bytes.Equal(k1, k3) {
		t.Fatal("deux fichiers doivent avoir deux clés différentes")
	}
	if _, err := DeriveFileKey(secret[:31], nil); err == nil {
		t.Fatal("un secret de 31 octets doit être refusé")
	}
}

func TestBadParameters(t *testing.T) {
	if _, err := NewFileCipher(make([]byte, 16), nil); err == nil {
		t.Error("AES-128 doit être refusé")
	}
	c := testCipher(t, "f")
	if _, err := c.EncryptBlocks(bytes.NewReader(nil), 0); !errors.Is(err, ErrBlockSize) {
		t.Errorf("attendu ErrBlockSize, obtenu %v", err)
	}
}

func TestReadErrorPropagates(t *testing.T) {
	c := testCipher(t, "f")
	boom := errors.New("disque")
	if _, err := c.EncryptBlocks(iotest.ErrReader(boom), 16); !errors.Is(err, boom) {
		t.Fatalf("attendu l'erreur de lecture, obtenu %v", err)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	c := testCipher(b, "f")
	data := randomBytes(b, 16<<20)
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		if _, err := c.EncryptStream(bytes.NewReader(data), DefaultBlockSize, func(uint64, []byte) error { return nil }); err != nil {
			b.Fatal(err)
		}
	}
}
