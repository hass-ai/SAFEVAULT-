// Package shamir implémente le partage de secret de Shamir sur le corps des
// scalaires d'edwards25519 (ordre ℓ = 2^252 + 27742317777372353535851937790883648493),
// le renouvellement proactif des parts par polynômes δ (Herzberg et al., 1995)
// et la récupération d'une part perdue.
//
// Conventions :
//   - t est le seuil de reconstruction : le polynôme est de degré t-1,
//     t parts reconstruisent le secret, t-1 parts n'apprennent rien sur lui ;
//   - la part d'un nœud est f(x) évaluée en x = Index, avec Index ≥ 1
//     (f(0) est le secret, on ne distribue donc jamais l'indice 0) ;
//   - chaque part porte son époque : des parts d'époques différentes sont sur
//     des polynômes différents et ne doivent jamais être combinées.
package shamir

import (
	"errors"
	"fmt"
	"io"

	"filippo.io/edwards25519"
)

// Share est la part d'un nœud : le point (Index, Value) du polynôme de l'époque Epoch.
type Share struct {
	Index uint32
	Epoch uint64
	Value *edwards25519.Scalar
}

var (
	ErrThreshold       = errors.New("shamir : seuil invalide, il faut 1 ≤ t ≤ n")
	ErrNotEnoughShares = errors.New("shamir : pas assez de parts pour atteindre le seuil")
	ErrZeroIndex       = errors.New("shamir : l'indice 0 est réservé au secret")
	ErrDuplicateIndex  = errors.New("shamir : indice en double")
	ErrEpochMismatch   = errors.New("shamir : parts d'époques différentes")
	ErrNilValue        = errors.New("shamir : part sans valeur")
)

// NewSecret tire un secret uniforme dans le corps des scalaires.
// La clé AES d'un fichier en est dérivée (voir internal/crypto.DeriveFileKey).
func NewSecret(rand io.Reader) (*edwards25519.Scalar, error) {
	return randomScalar(rand)
}

// Split découpe secret en n parts d'indices 1..n, dont t suffisent à le reconstruire.
// Les parts sont à l'époque 0.
func Split(secret *edwards25519.Scalar, t, n int, rand io.Reader) ([]Share, error) {
	if t < 1 || t > n {
		return nil, ErrThreshold
	}
	if uint64(n) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("shamir : n = %d trop grand", n)
	}
	f, err := randomPolynomial(secret, t-1, rand)
	if err != nil {
		return nil, err
	}
	shares := make([]Share, n)
	for i := range shares {
		index := uint32(i + 1)
		shares[i] = Share{Index: index, Epoch: 0, Value: f.eval(scalarFromUint(uint64(index)))}
	}
	return shares, nil
}

// Combine reconstruit le secret à partir d'au moins t parts de la même époque.
// Seules les t premières parts sont utilisées.
//
// Attention : Combine ne détecte pas une part fausse, elle renvoie alors un
// secret faux. La détection (et l'identification du nœud fautif) relève de la
// vérification des parts (VSS de Feldman ou Pedersen).
func Combine(shares []Share, t int) (*edwards25519.Scalar, error) {
	points, err := selectShares(shares, t)
	if err != nil {
		return nil, err
	}
	return interpolateAt(points, edwards25519.NewScalar()), nil
}

// selectShares vérifie les parts et renvoie les t premières.
func selectShares(shares []Share, t int) ([]Share, error) {
	if t < 1 {
		return nil, ErrThreshold
	}
	if len(shares) < t {
		return nil, ErrNotEnoughShares
	}
	points := shares[:t]
	if err := validateShares(points); err != nil {
		return nil, err
	}
	return points, nil
}

func validateShares(shares []Share) error {
	seen := make(map[uint32]bool, len(shares))
	for _, s := range shares {
		if s.Value == nil {
			return ErrNilValue
		}
		if s.Epoch != shares[0].Epoch {
			return ErrEpochMismatch
		}
		if s.Index == 0 {
			return ErrZeroIndex
		}
		if seen[s.Index] {
			return fmt.Errorf("%w : %d", ErrDuplicateIndex, s.Index)
		}
		seen[s.Index] = true
	}
	return nil
}

func validateIndices(indices []uint32) error {
	if len(indices) == 0 {
		return errors.New("shamir : aucun indice")
	}
	seen := make(map[uint32]bool, len(indices))
	for _, i := range indices {
		if i == 0 {
			return ErrZeroIndex
		}
		if seen[i] {
			return fmt.Errorf("%w : %d", ErrDuplicateIndex, i)
		}
		seen[i] = true
	}
	return nil
}

// interpolateAt évalue en x l'unique polynôme de degré len(points)-1 qui passe
// par les points (interpolation de Lagrange) :
//
//	f(x) = Σ_i y_i · λ_i(x),   λ_i(x) = Π_{j≠i} (x - x_j) / (x_i - x_j)
//
// Les indices sont supposés non nuls et distincts (voir validateShares).
func interpolateAt(points []Share, x *edwards25519.Scalar) *edwards25519.Scalar {
	xs := make([]*edwards25519.Scalar, len(points))
	for i, p := range points {
		xs[i] = scalarFromUint(uint64(p.Index))
	}
	result := edwards25519.NewScalar()
	for i, p := range points {
		num := scalarFromUint(1)
		den := scalarFromUint(1)
		for j := range points {
			if i == j {
				continue
			}
			num.Multiply(num, edwards25519.NewScalar().Subtract(x, xs[j]))
			den.Multiply(den, edwards25519.NewScalar().Subtract(xs[i], xs[j]))
		}
		lambda := edwards25519.NewScalar().Multiply(num, edwards25519.NewScalar().Invert(den))
		result.MultiplyAdd(lambda, p.Value, result)
	}
	return result
}
