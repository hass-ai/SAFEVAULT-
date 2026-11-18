package main

import (
	"fmt"

	"filippo.io/edwards25519"

	"safevault/internal/crypto"
	"safevault/internal/shamir"
)

// stolenShare est une part copiée par l'attaquant sur le disque d'un nœud compromis.
type stolenShare struct {
	X     uint32 `json:"x"`
	Epoch uint64 `json:"epoch"`
	Print string `json:"print"`
	value []byte
}

// attackOutcome est le résultat d'une tentative de l'attaquant avec les parts volées.
type attackOutcome struct {
	Success  bool   `json:"success"`
	Tried    int    `json:"tried"`    // combinaisons de t parts essayées
	Leaked   string `json:"leaked"`   // début du fichier déchiffré, si l'attaque réussit
	Combined string `json:"combined"` // parts qui ont permis de déchiffrer
}

// tryDecrypt joue l'attaquant : il essaie toutes les combinaisons de t parts volées.
// Il ne sait pas quelles parts vont ensemble, il ignore donc les époques. Une
// combinaison réussit si la clé obtenue déchiffre le premier bloc du fichier, volé lui
// aussi sur un nœud compromis (GCM rejette toute mauvaise clé).
func tryDecrypt(stolen []stolenShare, t int, fileID string, block []byte) attackOutcome {
	var out attackOutcome
	for _, combo := range combinations(len(stolen), t) {
		shares := make([]shamir.Share, 0, t)
		seen := make(map[uint32]bool)
		label := ""
		for _, i := range combo {
			s := stolen[i]
			if seen[s.X] {
				break // deux parts du même nœud : même abscisse, inutilisable
			}
			seen[s.X] = true
			value, err := edwards25519.NewScalar().SetCanonicalBytes(s.value)
			if err != nil {
				break
			}
			shares = append(shares, shamir.Share{Index: s.X, Epoch: 0, Value: value})
			label += fmt.Sprintf("node-%d (époque %d) ", s.X, s.Epoch)
		}
		if len(shares) != t {
			continue
		}
		out.Tried++

		secret, err := shamir.Combine(shares, t)
		if err != nil {
			continue
		}
		if plain, ok := decryptFirstBlock(secret, fileID, block); ok {
			out.Success = true
			out.Combined = label
			if len(plain) > 160 {
				plain = plain[:160]
			}
			out.Leaked = string(plain)
			return out
		}
	}
	return out
}

func decryptFirstBlock(secret *edwards25519.Scalar, fileID string, block []byte) ([]byte, bool) {
	key, err := crypto.DeriveFileKey(secret.Bytes(), []byte(fileID))
	if err != nil {
		return nil, false
	}
	fc, err := crypto.NewFileCipher(key, []byte(fileID))
	if err != nil {
		return nil, false
	}
	// Le premier bloc est aussi le dernier pour un petit fichier.
	for _, last := range []bool{true, false} {
		if plain, err := fc.OpenBlock(0, last, block); err == nil {
			return plain, true
		}
	}
	return nil, false
}

// combinations renvoie toutes les combinaisons de k indices parmi n.
func combinations(n, k int) [][]int {
	var out [][]int
	var rec func(start int, cur []int)
	rec = func(start int, cur []int) {
		if len(cur) == k {
			out = append(out, append([]int(nil), cur...))
			return
		}
		for i := start; i < n; i++ {
			rec(i+1, append(cur, i))
		}
	}
	rec(0, nil)
	return out
}
