package shamir

import (
	"errors"
	"fmt"
	"io"

	"filippo.io/edwards25519"
)

// Récupération d'une part perdue (nœud r réinstallé après une panne ou une compromission).
//
// Le nœud r ne peut pas simplement recevoir les parts s_j de t autres nœuds :
// il pourrait alors reconstruire le secret. On masque donc les parts :
//
//  1. chaque nœud aidant i tire δ_i de degré t-1 avec δ_i(r) = 0, et envoie
//     δ_i(j) à chaque autre aidant j ;
//  2. chaque aidant j envoie à r sa part masquée s_j + Σ_i δ_i(j) ;
//  3. r interpole en x = r : (f + Σ δ_i)(r) = f(r) + 0 = s_r.
//
// Le nœud r apprend t points de g = f + Σ δ_i, donc g entier, mais
// g(0) = f(0) + Σ δ_i(0) est masqué par les δ_i(0), aléatoires (dès que t ≥ 2).
// Il n'apprend donc que sa part s_r.
//
// Mêmes contraintes que le renouvellement : les sous-parts δ_i(j) ne doivent
// jamais atteindre r, et tous les aidants doivent appliquer le même ensemble
// de contributions.

// NewRecoveryContribution est exécutée par chaque aidant. Elle tire δ de degré
// t-1 avec δ(lost) = 0 et renvoie δ(j) pour chaque aidant j de helpers.
func NewRecoveryContribution(t int, lost uint32, helpers []uint32, rand io.Reader) (map[uint32]*edwards25519.Scalar, error) {
	if err := checkRecovery(t, lost, helpers); err != nil {
		return nil, err
	}
	delta, err := randomPolynomialWithRoot(scalarFromUint(uint64(lost)), t-1, rand)
	if err != nil {
		return nil, err
	}
	return evalAt(delta, helpers), nil
}

// MaskShare est exécutée par chaque aidant : elle ajoute à sa part les
// sous-parts reçues des autres aidants. Le résultat est envoyé au nœud perdu.
func MaskShare(s Share, received []*edwards25519.Scalar) (Share, error) {
	if s.Value == nil {
		return Share{}, ErrNilValue
	}
	if len(received) == 0 {
		return Share{}, errors.New("shamir : aucune contribution de récupération")
	}
	value := edwards25519.NewScalar().Set(s.Value)
	for _, d := range received {
		if d == nil {
			return Share{}, ErrNilValue
		}
		value.Add(value, d)
	}
	return Share{Index: s.Index, Epoch: s.Epoch, Value: value}, nil
}

// RecoverShare est exécutée par le nœud perdu : elle reconstruit sa part à
// partir d'au moins t parts masquées de la même époque.
func RecoverShare(lost uint32, masked []Share, t int) (Share, error) {
	if lost == 0 {
		return Share{}, ErrZeroIndex
	}
	points, err := selectShares(masked, t)
	if err != nil {
		return Share{}, err
	}
	for _, p := range points {
		if p.Index == lost {
			return Share{}, fmt.Errorf("shamir : le nœud %d ne peut pas s'aider lui-même", lost)
		}
	}
	value := interpolateAt(points, scalarFromUint(uint64(lost)))
	return Share{Index: lost, Epoch: points[0].Epoch, Value: value}, nil
}

// Recover simule localement une récupération complète (MVP local, tests, mesures).
func Recover(lost uint32, helpers []Share, t int, rand io.Reader) (Share, error) {
	if err := validateShares(helpers); err != nil {
		return Share{}, err
	}
	indices := make([]uint32, len(helpers))
	for i, h := range helpers {
		indices[i] = h.Index
	}
	inbox := make(map[uint32][]*edwards25519.Scalar, len(helpers))
	for range helpers {
		contribution, err := NewRecoveryContribution(t, lost, indices, rand)
		if err != nil {
			return Share{}, err
		}
		for j, d := range contribution {
			inbox[j] = append(inbox[j], d)
		}
	}
	masked := make([]Share, len(helpers))
	for i, h := range helpers {
		m, err := MaskShare(h, inbox[h.Index])
		if err != nil {
			return Share{}, err
		}
		masked[i] = m
	}
	return RecoverShare(lost, masked, t)
}

func checkRecovery(t int, lost uint32, helpers []uint32) error {
	if lost == 0 {
		return ErrZeroIndex
	}
	if t < 1 || t > len(helpers) {
		return ErrNotEnoughShares
	}
	if err := validateIndices(helpers); err != nil {
		return err
	}
	for _, h := range helpers {
		if h == lost {
			return fmt.Errorf("shamir : le nœud %d ne peut pas s'aider lui-même", lost)
		}
	}
	return nil
}
