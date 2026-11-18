package shamir

// Tests croisés avec go.dedis.ch/kyber/v4/share, implémentation de référence
// de l'EPFL (DEDIS) sur le même groupe edwards25519. Kyber numérote ses parts
// à partir de 0 et les évalue en x = I+1 : notre Index vaut donc I+1.

import (
	"crypto/rand"
	"testing"

	"filippo.io/edwards25519"
	"go.dedis.ch/kyber/v4"
	kybered "go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/share"
)

var suite = kybered.NewBlakeSHA256Ed25519()

func toKyber(t *testing.T, s *edwards25519.Scalar) kyber.Scalar {
	t.Helper()
	k := suite.Scalar()
	if err := k.UnmarshalBinary(s.Bytes()); err != nil {
		t.Fatal(err)
	}
	return k
}

func fromKyber(t *testing.T, k kyber.Scalar) *edwards25519.Scalar {
	t.Helper()
	b, err := k.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	s, err := edwards25519.NewScalar().SetCanonicalBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func toKyberShares(t *testing.T, shares []Share) []*share.PriShare {
	out := make([]*share.PriShare, len(shares))
	for i, s := range shares {
		out[i] = &share.PriShare{I: uint32(s.Index - 1), V: toKyber(t, s.Value)}
	}
	return out
}

// Kyber découpe, nous reconstruisons.
func TestKyberSplitOurCombine(t *testing.T) {
	for _, p := range params {
		secret := suite.Scalar().Pick(suite.RandomStream())
		poly := share.NewPriPoly(suite, uint32(p.t), secret, suite.RandomStream())
		var ours []Share
		for _, ks := range poly.Shares(uint32(p.n)) {
			ours = append(ours, Share{Index: uint32(ks.I) + 1, Value: fromKyber(t, ks.V)})
		}
		got, err := Combine(reversed(ours), p.t)
		if err != nil {
			t.Fatal(err)
		}
		if got.Equal(fromKyber(t, secret)) != 1 {
			t.Fatalf("t=%d n=%d : secret différent de kyber", p.t, p.n)
		}
	}
}

// Nous découpons (et renouvelons), kyber reconstruit.
func TestOurSplitAndRefreshKyberRecover(t *testing.T) {
	for _, p := range params {
		secret := mustSecret(t)
		shares := mustSplit(t, secret, p.t, p.n)
		for epoch := 0; epoch < 3; epoch++ {
			got, err := share.RecoverSecret(suite, toKyberShares(t, shares), uint32(p.t), uint32(p.n))
			if err != nil {
				t.Fatal(err)
			}
			if !got.Equal(toKyber(t, secret)) {
				t.Fatalf("t=%d n=%d époque %d : kyber ne retrouve pas le secret", p.t, p.n, epoch)
			}
			var err2 error
			if shares, err2 = Refresh(shares, p.t, rand.Reader); err2 != nil {
				t.Fatal(err2)
			}
		}
	}
}

// Nos parts sont exactement les évaluations du polynôme : kyber, qui interpole
// le polynôme complet, doit retrouver notre secret comme coefficient constant.
func TestKyberRecoverPolyMatches(t *testing.T) {
	secret := mustSecret(t)
	shares := mustSplit(t, secret, 4, 7)
	poly, err := share.RecoverPriPoly(suite, toKyberShares(t, shares), 4, 7)
	if err != nil {
		t.Fatal(err)
	}
	if !poly.Secret().Equal(toKyber(t, secret)) {
		t.Fatal("le coefficient constant interpolé par kyber diffère")
	}
	if !poly.Eval(0).V.Equal(toKyber(t, shares[0].Value)) {
		t.Fatal("kyber n'évalue pas notre part 1 à la même valeur")
	}
}
