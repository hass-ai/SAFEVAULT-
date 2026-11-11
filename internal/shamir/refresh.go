package shamir

import (
	"errors"
	"io"

	"filippo.io/edwards25519"
)

// Renouvellement proactif (Herzberg, Jarecki, Krawczyk, Yung, 1995).
//
// À chaque époque, chaque nœud i tire un polynôme δ_i de degré t-1 avec
// δ_i(0) = 0, et envoie δ_i(j) au nœud j sur un canal confidentiel. Le nœud j
// remplace sa part par
//
//	s'_j = s_j + Σ_i δ_i(j)
//
// Les nouvelles parts sont sur f' = f + Σ_i δ_i : même secret f'(0) = f(0),
// mais un polynôme nouveau et indépendant de l'ancien. Un attaquant qui a volé
// t-1 parts à l'époque e et t-1 parts à l'époque e+1 ne peut rien en tirer :
// les parts volées sont devenues inutiles.
//
// Coût d'un tour : n² sous-parts échangées (O(n²) par secret).
//
// Point de vigilance : tous les nœuds doivent appliquer les contributions du
// MÊME ensemble de nœuds émetteurs. Si le nœud j additionne δ_1, δ_2, δ_3 et le
// nœud k seulement δ_1, δ_2, leurs parts ne sont plus sur un même polynôme et le
// secret est perdu. Le coordinateur doit donc fixer, pour chaque époque, la
// liste des contributions retenues.

// NewRefreshContribution est exécutée par chaque nœud participant. Elle tire un
// δ de degré t-1 avec δ(0) = 0 et renvoie δ(j) pour chaque indice j de indices
// (y compris l'indice du nœud lui-même). La sous-part destinée à j ne doit
// être envoyée qu'à j.
func NewRefreshContribution(t int, indices []uint32, rand io.Reader) (map[uint32]*edwards25519.Scalar, error) {
	if t < 1 || t > len(indices) {
		return nil, ErrThreshold
	}
	if err := validateIndices(indices); err != nil {
		return nil, err
	}
	delta, err := randomPolynomialWithRoot(edwards25519.NewScalar(), t-1, rand)
	if err != nil {
		return nil, err
	}
	return evalAt(delta, indices), nil
}

// ApplyRefresh calcule la part de l'époque suivante à partir des sous-parts
// δ_i(j) reçues de tous les participants. old n'est pas modifiée.
func ApplyRefresh(old Share, received []*edwards25519.Scalar) (Share, error) {
	if old.Value == nil {
		return Share{}, ErrNilValue
	}
	if len(received) == 0 {
		return Share{}, errors.New("shamir : aucune contribution de renouvellement")
	}
	value := edwards25519.NewScalar().Set(old.Value)
	for _, d := range received {
		if d == nil {
			return Share{}, ErrNilValue
		}
		value.Add(value, d)
	}
	return Share{Index: old.Index, Epoch: old.Epoch + 1, Value: value}, nil
}

// Refresh simule localement un tour complet de renouvellement : chaque détenteur
// de part contribue, puis chacun applique toutes les contributions. Elle sert
// au MVP local, aux tests et aux mesures ; en réparti, chaque nœud n'exécute
// que NewRefreshContribution et ApplyRefresh.
func Refresh(shares []Share, t int, rand io.Reader) ([]Share, error) {
	if err := validateShares(shares); err != nil {
		return nil, err
	}
	indices := make([]uint32, len(shares))
	for i, s := range shares {
		indices[i] = s.Index
	}
	inbox := make(map[uint32][]*edwards25519.Scalar, len(shares))
	for range shares {
		contribution, err := NewRefreshContribution(t, indices, rand)
		if err != nil {
			return nil, err
		}
		for j, d := range contribution {
			inbox[j] = append(inbox[j], d)
		}
	}
	refreshed := make([]Share, len(shares))
	for i, s := range shares {
		r, err := ApplyRefresh(s, inbox[s.Index])
		if err != nil {
			return nil, err
		}
		refreshed[i] = r
	}
	return refreshed, nil
}

func evalAt(p polynomial, indices []uint32) map[uint32]*edwards25519.Scalar {
	values := make(map[uint32]*edwards25519.Scalar, len(indices))
	for _, j := range indices {
		values[j] = p.eval(scalarFromUint(uint64(j)))
	}
	return values
}
