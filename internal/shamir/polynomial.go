package shamir

import (
	"encoding/binary"
	"io"

	"filippo.io/edwards25519"
)

// polynomial stocke les coefficients par degré croissant : p[0] est la constante.
type polynomial []*edwards25519.Scalar

// randomPolynomial tire un polynôme de degré degree et de constante constant.
func randomPolynomial(constant *edwards25519.Scalar, degree int, rand io.Reader) (polynomial, error) {
	p := make(polynomial, degree+1)
	p[0] = edwards25519.NewScalar().Set(constant)
	for k := 1; k <= degree; k++ {
		c, err := randomScalar(rand)
		if err != nil {
			return nil, err
		}
		p[k] = c
	}
	return p, nil
}

// randomPolynomialWithRoot tire un polynôme aléatoire de degré degree tel que p(root) = 0.
// On tire a_1..a_degree au hasard puis on fixe a_0 = -Σ a_k·root^k.
//
//   - root = 0 donne les polynômes δ du renouvellement (δ(0) = 0 : le secret ne bouge pas) ;
//   - root = r donne les masques de la récupération de la part r (δ(r) = 0).
func randomPolynomialWithRoot(root *edwards25519.Scalar, degree int, rand io.Reader) (polynomial, error) {
	p, err := randomPolynomial(edwards25519.NewScalar(), degree, rand)
	if err != nil {
		return nil, err
	}
	p[0] = edwards25519.NewScalar().Negate(p.eval(root))
	return p, nil
}

// eval calcule p(x) par la méthode de Horner.
func (p polynomial) eval(x *edwards25519.Scalar) *edwards25519.Scalar {
	result := edwards25519.NewScalar()
	for k := len(p) - 1; k >= 0; k-- {
		result.MultiplyAdd(result, x, p[k])
	}
	return result
}

// randomScalar tire un scalaire uniforme : 64 octets aléatoires réduits modulo ℓ
// (le biais de la réduction est négligeable, de l'ordre de 2^-260).
func randomScalar(rand io.Reader) (*edwards25519.Scalar, error) {
	var b [64]byte
	if _, err := io.ReadFull(rand, b[:]); err != nil {
		return nil, err
	}
	return edwards25519.NewScalar().SetUniformBytes(b[:])
}

// scalarFromUint convertit un entier en scalaire (encodage petit-boutiste).
func scalarFromUint(v uint64) *edwards25519.Scalar {
	var b [32]byte
	binary.LittleEndian.PutUint64(b[:8], v)
	s, err := edwards25519.NewScalar().SetCanonicalBytes(b[:])
	if err != nil {
		panic(err) // impossible : v < 2^64 < ℓ
	}
	return s
}
