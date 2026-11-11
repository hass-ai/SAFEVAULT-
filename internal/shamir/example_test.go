package shamir_test

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"safevault/internal/crypto"
	"safevault/internal/shamir"
)

// Parcours complet côté client : secret → clé du fichier → blocs chiffrés,
// parts distribuées, renouvelées, puis reconstruction et déchiffrement.
func Example() {
	const t, n = 3, 5
	fileID := []byte("fichier-42")

	// Dépôt.
	secret, _ := shamir.NewSecret(rand.Reader)
	key, _ := crypto.DeriveFileKey(secret.Bytes(), fileID)
	fc, _ := crypto.NewFileCipher(key, fileID)
	blocks, _ := fc.EncryptBlocks(bytes.NewReader([]byte("bonjour SafeVault")), 8)
	shares, _ := shamir.Split(secret, t, n, rand.Reader) // une part par nœud

	// Deux époques de renouvellement.
	for i := 0; i < 2; i++ {
		shares, _ = shamir.Refresh(shares, t, rand.Reader)
	}

	// Récupération avec les nœuds 2, 4 et 5 seulement.
	got, _ := shamir.Combine([]shamir.Share{shares[1], shares[3], shares[4]}, t)
	key2, _ := crypto.DeriveFileKey(got.Bytes(), fileID)
	fc2, _ := crypto.NewFileCipher(key2, fileID)
	var out bytes.Buffer
	if err := fc2.DecryptBlocks(blocks, &out); err != nil {
		panic(err)
	}
	fmt.Println(len(blocks), "blocs, époque", shares[0].Epoch, ":", out.String())
	// Output: 3 blocs, époque 2 : bonjour SafeVault
}
