package access

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	pb "safevault/proto"
)

const fileID = "fichier-1"

var t0 = time.Unix(1_800_000_000, 0)

type user struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newUser(t *testing.T) user {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return user{priv, pub}
}

// ctx renvoie un contexte où owner possède le fichier et où revoked donne les retraits.
func ctx(owner user, revoked map[string]int64) Context {
	return Context{
		FileID: fileID,
		Owners: []Owner{{Key: owner.pub}},
		RevokedAt: func(grantee []byte) (int64, bool, error) {
			at, ok := revoked[string(grantee)]
			return at, ok, nil
		},
		Now: t0.Add(time.Minute),
	}
}

func TestOwnerGrant(t *testing.T) {
	alice, bob := newUser(t), newUser(t)
	g := NewGrant(alice.priv, fileID, bob.pub, Read|Write, t0, time.Time{}, nil)

	rights, err := VerifyGrantFor(g, bob.pub, Read, ctx(alice, nil))
	if err != nil || rights != Read|Write {
		t.Fatalf("droits = %v, err = %v ; attendu rw", rights, err)
	}
	if _, err := VerifyGrantFor(g, bob.pub, Delete, ctx(alice, nil)); !errors.Is(err, ErrRights) {
		t.Fatalf("droit d accordé à tort : %v", err)
	}
	if _, err := VerifyGrantFor(g, alice.pub, Read, ctx(alice, nil)); !errors.Is(err, ErrWrongHolder) {
		t.Fatalf("autorisation acceptée pour une autre clé : %v", err)
	}
}

func TestGrantRefused(t *testing.T) {
	alice, bob, mallory := newUser(t), newUser(t), newUser(t)
	c := ctx(alice, nil)

	// Signée par quelqu'un qui n'est pas propriétaire (un coordinateur tricheur).
	forged := NewGrant(mallory.priv, fileID, bob.pub, Read, t0, time.Time{}, nil)
	if _, err := VerifyGrant(forged, c); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("autorisation sans chaîne vers le propriétaire acceptée : %v", err)
	}
	// Émetteur remplacé par la clé d'alice : la signature ne correspond plus.
	forged.IssuerPublicKey = alice.pub
	if _, err := VerifyGrant(forged, c); !errors.Is(err, ErrSignature) {
		t.Fatalf("signature falsifiée acceptée : %v", err)
	}
	// Droits modifiés après signature.
	g := NewGrant(alice.priv, fileID, bob.pub, Read, t0, time.Time{}, nil)
	g.Rights = All
	if _, err := VerifyGrant(g, c); !errors.Is(err, ErrSignature) {
		t.Fatalf("droits modifiés acceptés : %v", err)
	}
	// Autre fichier.
	other := NewGrant(alice.priv, "autre", bob.pub, Read, t0, time.Time{}, nil)
	if _, err := VerifyGrant(other, c); !errors.Is(err, ErrWrongFile) {
		t.Fatalf("autorisation d'un autre fichier acceptée : %v", err)
	}
	// Droits inconnus.
	bad := NewGrant(alice.priv, fileID, bob.pub, 1<<10, t0, time.Time{}, nil)
	if _, err := VerifyGrant(bad, c); !errors.Is(err, ErrMalformed) {
		t.Fatalf("droits inconnus acceptés : %v", err)
	}
}

func TestExpiry(t *testing.T) {
	alice, bob := newUser(t), newUser(t)
	g := NewGrant(alice.priv, fileID, bob.pub, Read, t0, t0.Add(time.Hour), nil)
	c := ctx(alice, nil)
	if _, err := VerifyGrant(g, c); err != nil {
		t.Fatal(err)
	}
	c.Now = t0.Add(2 * time.Hour)
	if _, err := VerifyGrant(g, c); !errors.Is(err, ErrExpired) {
		t.Fatalf("autorisation expirée acceptée : %v", err)
	}
	future := NewGrant(alice.priv, fileID, bob.pub, Read, t0.Add(time.Hour), time.Time{}, nil)
	if _, err := VerifyGrant(future, ctx(alice, nil)); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("autorisation datée dans le futur acceptée : %v", err)
	}
}

func TestDelegation(t *testing.T) {
	alice, bob, carol, dave := newUser(t), newUser(t), newUser(t), newUser(t)
	c := ctx(alice, nil)

	// bob peut repartager (s) en lecture et écriture, pendant un jour.
	bobGrant := NewGrant(alice.priv, fileID, bob.pub, Read|Write|Share, t0, t0.Add(24*time.Hour), nil)

	ok := NewGrant(bob.priv, fileID, carol.pub, Read, t0, t0.Add(time.Hour), bobGrant)
	if rights, err := VerifyGrantFor(ok, carol.pub, Read, c); err != nil || rights != Read {
		t.Fatalf("délégation valable refusée : %v", err)
	}
	// Plus de droits que bob.
	more := NewGrant(bob.priv, fileID, carol.pub, Read|Delete, t0, t0.Add(time.Hour), bobGrant)
	if _, err := VerifyGrant(more, c); !errors.Is(err, ErrDelegation) {
		t.Fatalf("délégation au-delà des droits acceptée : %v", err)
	}
	// Plus longtemps que bob.
	longer := NewGrant(bob.priv, fileID, carol.pub, Read, t0, time.Time{}, bobGrant)
	if _, err := VerifyGrant(longer, c); !errors.Is(err, ErrDelegation) {
		t.Fatalf("délégation sans limite acceptée sous un accès limité : %v", err)
	}
	// carol (sans s) ne peut pas repartager.
	chained := NewGrant(carol.priv, fileID, dave.pub, Read, t0, t0.Add(time.Hour), ok)
	if _, err := VerifyGrant(chained, c); !errors.Is(err, ErrDelegation) {
		t.Fatalf("repartage sans le droit s accepté : %v", err)
	}
	// Chaîne dont le parent n'est pas l'autorisation de l'émetteur.
	stolen := NewGrant(dave.priv, fileID, carol.pub, Read, t0, t0.Add(time.Hour), bobGrant)
	if _, err := VerifyGrant(stolen, c); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("autorisation d'un autre utilisée comme parent : %v", err)
	}
}

func TestManagerGivesAnyRights(t *testing.T) {
	alice, bob, carol := newUser(t), newUser(t), newUser(t)
	c := ctx(alice, nil)
	bobGrant := NewGrant(alice.priv, fileID, bob.pub, Read|Manage, t0, time.Time{}, nil)
	g := NewGrant(bob.priv, fileID, carol.pub, Read|Write|Delete, t0, time.Time{}, bobGrant)
	if rights, err := VerifyGrant(g, c); err != nil || rights != Read|Write|Delete {
		t.Fatalf("un co-administrateur doit pouvoir donner tous les droits : %v", err)
	}
	// Il peut aussi retirer un accès.
	r := NewRevocation(bob.priv, fileID, carol.pub, t0.Add(time.Second), bobGrant)
	if err := VerifyRevocation(r, c); err != nil {
		t.Fatalf("retrait par un co-administrateur refusé : %v", err)
	}
	// Mais pas avec un simple droit s.
	sharer := NewGrant(alice.priv, fileID, bob.pub, Read|Share, t0, time.Time{}, nil)
	r = NewRevocation(bob.priv, fileID, carol.pub, t0.Add(time.Second), sharer)
	if err := VerifyRevocation(r, c); !errors.Is(err, ErrRights) {
		t.Fatalf("retrait sans le droit m accepté : %v", err)
	}
}

func TestChainTooLong(t *testing.T) {
	alice := newUser(t)
	c := ctx(alice, nil)
	issuer := alice
	var parent *pb.Grant
	for i := 0; i < maxChain+1; i++ {
		next := newUser(t)
		parent = NewGrant(issuer.priv, fileID, next.pub, Read|Share, t0, time.Time{}, parent)
		issuer = next
	}
	if _, err := VerifyGrant(parent, c); !errors.Is(err, ErrTooLong) {
		t.Fatalf("chaîne trop longue acceptée : %v", err)
	}
}

func TestRevocationCascades(t *testing.T) {
	alice, bob, carol := newUser(t), newUser(t), newUser(t)
	bobGrant := NewGrant(alice.priv, fileID, bob.pub, Read|Share, t0, time.Time{}, nil)
	carolGrant := NewGrant(bob.priv, fileID, carol.pub, Read, t0, time.Time{}, bobGrant)

	r := NewRevocation(alice.priv, fileID, bob.pub, t0.Add(time.Second), nil)
	if err := VerifyRevocation(r, ctx(alice, nil)); err != nil {
		t.Fatal(err)
	}
	c := ctx(alice, map[string]int64{string(bob.pub): r.RevokedAt})
	if _, err := VerifyGrant(bobGrant, c); !errors.Is(err, ErrRevoked) {
		t.Fatalf("autorisation retirée acceptée : %v", err)
	}
	if _, err := VerifyGrant(carolGrant, c); !errors.Is(err, ErrRevoked) {
		t.Fatalf("autorisation qui découle d'un accès retiré acceptée : %v", err)
	}
	// Une autorisation émise après le retrait rouvre l'accès.
	again := NewGrant(alice.priv, fileID, bob.pub, Read, t0.Add(2*time.Second), time.Time{}, nil)
	if _, err := VerifyGrant(again, c); err != nil {
		t.Fatalf("nouveau partage après retrait refusé : %v", err)
	}
	// Un retrait signé par un autre que le propriétaire est refusé.
	forged := NewRevocation(carol.priv, fileID, bob.pub, t0, nil)
	if err := VerifyRevocation(forged, ctx(alice, nil)); err == nil {
		t.Fatal("retrait signé par un tiers accepté")
	}
}

func TestTransfer(t *testing.T) {
	alice, bob, carol := newUser(t), newUser(t), newUser(t)
	before := NewGrant(alice.priv, fileID, carol.pub, Read, t0, time.Time{}, nil)
	tr := NewTransfer(alice.priv, fileID, bob.pub, t0.Add(10*time.Second))
	if err := VerifyTransfer(tr, ctx(alice, nil)); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTransfer(NewTransfer(carol.priv, fileID, carol.pub, t0), ctx(alice, nil)); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("transfert par un non-propriétaire accepté : %v", err)
	}

	after := Context{
		FileID: fileID,
		Owners: []Owner{{Key: bob.pub}, {Key: alice.pub, Until: tr.TransferredAt}},
		Now:    t0.Add(time.Minute),
	}
	// Les autorisations d'alice signées avant le transfert restent valables...
	if _, err := VerifyGrant(before, after); err != nil {
		t.Fatalf("autorisation antérieure au transfert refusée : %v", err)
	}
	// ... pas celles signées après.
	late := NewGrant(alice.priv, fileID, carol.pub, Read, t0.Add(20*time.Second), time.Time{}, nil)
	if _, err := VerifyGrant(late, after); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("autorisation d'un ancien propriétaire acceptée : %v", err)
	}
	if rights, err := Authorize(bob.pub, nil, All, after); err != nil || rights != All {
		t.Fatalf("le nouveau propriétaire doit avoir tous les droits : %v", err)
	}
}

func TestExpiryOfChain(t *testing.T) {
	alice, bob, carol := newUser(t), newUser(t), newUser(t)
	parent := NewGrant(alice.priv, fileID, bob.pub, Read|Share, t0, t0.Add(time.Hour), nil)
	child := NewGrant(bob.priv, fileID, carol.pub, Read, t0, t0.Add(30*time.Minute), parent)
	if got := Expiry(child); got != t0.Add(30*time.Minute).Unix() {
		t.Fatalf("Expiry = %d", got)
	}
	if got := Expiry(NewGrant(alice.priv, fileID, bob.pub, Read, t0, time.Time{}, nil)); got != 0 {
		t.Fatalf("Expiry sans limite = %d", got)
	}
}

func TestParseRights(t *testing.T) {
	for in, want := range map[string]uint32{"r": Read, "w": Read | Write, "rwsdm": All, "MD": Read | Manage | Delete} {
		got, err := ParseRights(in)
		if err != nil || got != want {
			t.Errorf("ParseRights(%q) = %v, %v ; attendu %v", in, got, err, want)
		}
	}
	if _, err := ParseRights("rx"); err == nil {
		t.Error("droit inconnu accepté")
	}
	if got := RightsString(Read | Share); got != "r-s--" {
		t.Errorf("RightsString = %q", got)
	}
}

func TestFingerprint(t *testing.T) {
	a, b := newUser(t), newUser(t)
	fa := Fingerprint(a.pub)
	if fa != Fingerprint(a.pub) || fa == Fingerprint(b.pub) || len(fa) != 39 {
		t.Fatalf("empreinte inattendue : %q", fa)
	}
}
