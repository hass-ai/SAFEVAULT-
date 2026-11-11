package shamir

import (
	"crypto/rand"
	"errors"
	"fmt"
	"testing"

	"filippo.io/edwards25519"
)

func mustSecret(t testing.TB) *edwards25519.Scalar {
	t.Helper()
	s, err := NewSecret(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustSplit(t testing.TB, secret *edwards25519.Scalar, th, n int) []Share {
	t.Helper()
	shares, err := Split(secret, th, n, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return shares
}

func reversed(s []Share) []Share {
	out := make([]Share, len(s))
	for i := range s {
		out[i] = s[len(s)-1-i]
	}
	return out
}

var params = []struct{ t, n int }{{1, 1}, {1, 3}, {2, 3}, {3, 5}, {5, 5}, {7, 10}}

func TestSplitCombine(t *testing.T) {
	for _, p := range params {
		t.Run(fmt.Sprintf("t=%d,n=%d", p.t, p.n), func(t *testing.T) {
			secret := mustSecret(t)
			shares := mustSplit(t, secret, p.t, p.n)
			// N'importe quelle fenêtre de t parts consécutives, dans les deux sens.
			for start := 0; start+p.t <= p.n; start++ {
				for _, subset := range [][]Share{shares[start : start+p.t], reversed(shares[start : start+p.t])} {
					got, err := Combine(subset, p.t)
					if err != nil {
						t.Fatal(err)
					}
					if got.Equal(secret) != 1 {
						t.Fatalf("secret faux avec les parts %v", indicesOf(subset))
					}
				}
			}
		})
	}
}

// t-1 parts ne déterminent pas le secret : pour tout secret candidat, il existe
// un polynôme compatible. On le vérifie en interpolant t-1 parts + un faux point
// (0, candidat) : on obtient un polynôme valide de degré t-1.
func TestThresholdMinusOneRevealsNothing(t *testing.T) {
	secret := mustSecret(t)
	shares := mustSplit(t, secret, 3, 5)
	candidate := mustSecret(t)
	fake := []Share{shares[0], shares[1]}
	// Le point (0, candidat) ne passe pas par validateShares : on interpole directement.
	g := []Share{fake[0], fake[1], {Index: 0, Value: candidate}}
	// g passe par les deux vraies parts et vaut candidat en 0 : c'est cohérent.
	if interpolateAt(g, edwards25519.NewScalar()).Equal(candidate) != 1 {
		t.Fatal("interpolation incohérente")
	}
	for _, s := range fake {
		if interpolateAt(g, scalarFromUint(uint64(s.Index))).Equal(s.Value) != 1 {
			t.Fatal("le polynôme candidat ne passe pas par la part")
		}
	}
	// Avec seulement t-1 parts, Combine refuse.
	if _, err := Combine(fake, 3); !errors.Is(err, ErrNotEnoughShares) {
		t.Fatalf("attendu ErrNotEnoughShares, obtenu %v", err)
	}
}

func TestSplitErrors(t *testing.T) {
	secret := mustSecret(t)
	for _, p := range []struct{ t, n int }{{0, 3}, {4, 3}, {-1, 3}} {
		if _, err := Split(secret, p.t, p.n, rand.Reader); !errors.Is(err, ErrThreshold) {
			t.Errorf("t=%d n=%d : attendu ErrThreshold, obtenu %v", p.t, p.n, err)
		}
	}
}

func TestCombineErrors(t *testing.T) {
	shares := mustSplit(t, mustSecret(t), 3, 5)
	refreshed, err := Refresh(shares, 3, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		shares []Share
		want   error
	}{
		"doublon":        {[]Share{shares[0], shares[1], shares[0]}, ErrDuplicateIndex},
		"indice nul":     {[]Share{shares[0], shares[1], {Index: 0, Value: shares[2].Value}}, ErrZeroIndex},
		"époques mêlées": {[]Share{shares[0], shares[1], refreshed[2]}, ErrEpochMismatch},
		"valeur nil":     {[]Share{shares[0], shares[1], {Index: 3}}, ErrNilValue},
		"trop peu":       {shares[:2], ErrNotEnoughShares},
	}
	for name, c := range cases {
		if _, err := Combine(c.shares, 3); !errors.Is(err, c.want) {
			t.Errorf("%s : attendu %v, obtenu %v", name, c.want, err)
		}
	}
}

// Une part corrompue donne un secret faux, sans erreur : c'est la limite que
// la VSS doit lever (G4b).
func TestCorruptedShareGivesWrongSecret(t *testing.T) {
	secret := mustSecret(t)
	shares := mustSplit(t, secret, 3, 5)
	shares[1].Value = edwards25519.NewScalar().Add(shares[1].Value, scalarFromUint(1))
	got, err := Combine(shares, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got.Equal(secret) == 1 {
		t.Fatal("une part corrompue n'aurait pas dû redonner le secret")
	}
}

func TestRefreshKeepsSecret(t *testing.T) {
	for _, p := range params {
		t.Run(fmt.Sprintf("t=%d,n=%d", p.t, p.n), func(t *testing.T) {
			secret := mustSecret(t)
			shares := mustSplit(t, secret, p.t, p.n)
			for epoch := uint64(1); epoch <= 5; epoch++ {
				next, err := Refresh(shares, p.t, rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				for i := range next {
					if next[i].Epoch != epoch || next[i].Index != shares[i].Index {
						t.Fatalf("part %d : époque %d indice %d", i, next[i].Epoch, next[i].Index)
					}
					if p.t > 1 && next[i].Value.Equal(shares[i].Value) == 1 {
						t.Fatalf("la part %d n'a pas changé", next[i].Index)
					}
				}
				got, err := Combine(reversed(next)[:p.t], p.t)
				if err != nil {
					t.Fatal(err)
				}
				if got.Equal(secret) != 1 {
					t.Fatalf("époque %d : secret perdu", epoch)
				}
				shares = next
			}
		})
	}
}

// Le cœur de la sécurité proactive : t-1 parts d'avant le renouvellement
// mélangées à des parts d'après ne redonnent pas le secret.
func TestOldSharesUselessAfterRefresh(t *testing.T) {
	secret := mustSecret(t)
	old := mustSplit(t, secret, 3, 5)
	refreshed, err := Refresh(old, 3, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Même en trichant sur l'époque, le mélange donne un secret faux.
	mixed := []Share{old[0], old[1], refreshed[2]}
	mixed[2].Epoch = 0
	got, err := Combine(mixed, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got.Equal(secret) == 1 {
		t.Fatal("parts d'époques différentes ont redonné le secret")
	}
}

// Si les nœuds n'appliquent pas le même ensemble de contributions, le secret est perdu.
func TestRefreshInconsistentContributionsBreaks(t *testing.T) {
	secret := mustSecret(t)
	shares := mustSplit(t, secret, 3, 3)
	indices := []uint32{1, 2, 3}
	var contributions []map[uint32]*edwards25519.Scalar
	for range shares {
		c, err := NewRefreshContribution(3, indices, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		contributions = append(contributions, c)
	}
	next := make([]Share, 3)
	for i, s := range shares {
		var received []*edwards25519.Scalar
		for k, c := range contributions {
			if s.Index == 3 && k == 0 { // le nœud 3 n'a pas reçu la contribution du nœud 1
				continue
			}
			received = append(received, c[s.Index])
		}
		var err error
		if next[i], err = ApplyRefresh(s, received); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Combine(next, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got.Equal(secret) == 1 {
		t.Fatal("des contributions incohérentes n'auraient pas dû préserver le secret")
	}
}

func TestApplyRefreshDoesNotMutate(t *testing.T) {
	shares := mustSplit(t, mustSecret(t), 2, 3)
	before := edwards25519.NewScalar().Set(shares[0].Value)
	if _, err := ApplyRefresh(shares[0], []*edwards25519.Scalar{scalarFromUint(42)}); err != nil {
		t.Fatal(err)
	}
	if shares[0].Value.Equal(before) != 1 {
		t.Fatal("ApplyRefresh a modifié l'ancienne part")
	}
}

func TestRecoverShare(t *testing.T) {
	for _, p := range []struct{ t, n int }{{2, 3}, {3, 5}, {4, 5}, {7, 10}} {
		t.Run(fmt.Sprintf("t=%d,n=%d", p.t, p.n), func(t *testing.T) {
			secret := mustSecret(t)
			shares := mustSplit(t, secret, p.t, p.n)
			shares, err := Refresh(shares, p.t, rand.Reader) // on récupère aussi après un renouvellement
			if err != nil {
				t.Fatal(err)
			}
			for lostPos := range shares {
				lost := shares[lostPos]
				var helpers []Share
				for i, s := range shares {
					if i != lostPos {
						helpers = append(helpers, s)
					}
				}
				helpers = helpers[:p.t]
				got, err := Recover(lost.Index, helpers, p.t, rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				if got.Index != lost.Index || got.Epoch != lost.Epoch || got.Value.Equal(lost.Value) != 1 {
					t.Fatalf("part %d mal récupérée", lost.Index)
				}
			}
		})
	}
}

// Les parts masquées reçues par le nœud perdu ne redonnent pas le secret.
func TestRecoveryMaskedSharesHideSecret(t *testing.T) {
	secret := mustSecret(t)
	shares := mustSplit(t, secret, 3, 5)
	helpers := shares[1:4]
	indices := indicesOf(helpers)
	inbox := map[uint32][]*edwards25519.Scalar{}
	for range helpers {
		c, err := NewRecoveryContribution(3, 1, indices, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		for j, d := range c {
			inbox[j] = append(inbox[j], d)
		}
	}
	var masked []Share
	for _, h := range helpers {
		m, err := MaskShare(h, inbox[h.Index])
		if err != nil {
			t.Fatal(err)
		}
		masked = append(masked, m)
	}
	got, err := Combine(masked, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got.Equal(secret) == 1 {
		t.Fatal("les parts masquées révèlent le secret")
	}
	recovered, err := RecoverShare(1, masked, 3)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Value.Equal(shares[0].Value) != 1 {
		t.Fatal("part 1 mal récupérée")
	}
}

func TestRecoveryErrors(t *testing.T) {
	shares := mustSplit(t, mustSecret(t), 3, 5)
	if _, err := Recover(2, shares[:3], 3, rand.Reader); err == nil {
		t.Error("le nœud perdu ne doit pas faire partie des aidants")
	}
	if _, err := Recover(1, shares[1:3], 3, rand.Reader); !errors.Is(err, ErrNotEnoughShares) {
		t.Errorf("attendu ErrNotEnoughShares, obtenu %v", err)
	}
	if _, err := Recover(0, shares[1:4], 3, rand.Reader); !errors.Is(err, ErrZeroIndex) {
		t.Errorf("attendu ErrZeroIndex, obtenu %v", err)
	}
}

func TestPolynomialWithRoot(t *testing.T) {
	for _, root := range []uint64{0, 1, 7, 1 << 31} {
		r := scalarFromUint(root)
		p, err := randomPolynomialWithRoot(r, 4, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if p.eval(r).Equal(edwards25519.NewScalar()) != 1 {
			t.Fatalf("p(%d) ≠ 0", root)
		}
	}
}

func indicesOf(shares []Share) []uint32 {
	out := make([]uint32, len(shares))
	for i, s := range shares {
		out[i] = s.Index
	}
	return out
}

// Mesures pour le rapport : le coût du renouvellement croît en n² par secret.
//
//	go test ./internal/shamir -bench . -benchmem
func BenchmarkSplit(b *testing.B) {
	secret := mustSecret(b)
	for _, n := range []int{5, 10, 20, 50} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				mustSplit(b, secret, n/2+1, n)
			}
		})
	}
}

func BenchmarkCombine(b *testing.B) {
	secret := mustSecret(b)
	for _, n := range []int{5, 10, 20, 50} {
		th := n/2 + 1
		shares := mustSplit(b, secret, th, n)
		b.Run(fmt.Sprintf("t=%d", th), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := Combine(shares, th); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkRefresh(b *testing.B) {
	secret := mustSecret(b)
	for _, n := range []int{5, 10, 20, 50} {
		th := n/2 + 1
		shares := mustSplit(b, secret, th, n)
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := Refresh(shares, th, rand.Reader); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(n*n), "sous-parts/tour")
		})
	}
}
