package access

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func TestGrant(t *testing.T) {
	alice, bob, mallory := newKey(t), newKey(t), newKey(t)
	now := time.Now()
	g := NewGrant(alice, "f1", pub(bob), now, time.Hour)

	if err := VerifyGrantFor(g, "f1", pub(alice), pub(bob), now); err != nil {
		t.Fatalf("autorisation valide refusée : %v", err)
	}

	cases := map[string]struct {
		err   error
		check func() error
	}{
		"autre fichier":      {ErrWrongFile, func() error { return VerifyGrant(g, "f2", pub(alice), now) }},
		"autre propriétaire": {ErrWrongOwner, func() error { return VerifyGrant(g, "f1", pub(mallory), now) }},
		"autre détenteur":    {ErrWrongHolder, func() error { return VerifyGrantFor(g, "f1", pub(alice), pub(mallory), now) }},
		"expirée":            {ErrExpired, func() error { return VerifyGrant(g, "f1", pub(alice), now.Add(2*time.Hour)) }},
		"dans le futur":      {ErrNotYetValid, func() error { return VerifyGrant(g, "f1", pub(alice), now.Add(-time.Hour)) }},
		"nil":                {ErrMalformed, func() error { return VerifyGrant(nil, "f1", pub(alice), now) }},
	}
	for name, c := range cases {
		if err := c.check(); !errors.Is(err, c.err) {
			t.Errorf("%s : erreur %v, attendue %v", name, err, c.err)
		}
	}
}

func TestGrantTampering(t *testing.T) {
	alice, bob, mallory := newKey(t), newKey(t), newKey(t)
	now := time.Now()

	// Changer le destinataire ou prolonger l'expiration casse la signature.
	g := NewGrant(alice, "f1", pub(bob), now, time.Hour)
	g.GranteePublicKey = pub(mallory)
	if err := VerifyGrant(g, "f1", pub(alice), now); !errors.Is(err, ErrSignature) {
		t.Errorf("destinataire modifié : erreur %v", err)
	}
	g = NewGrant(alice, "f1", pub(bob), now, time.Hour)
	g.ExpiresAt += 3600
	if err := VerifyGrant(g, "f1", pub(alice), now); !errors.Is(err, ErrSignature) {
		t.Errorf("expiration modifiée : erreur %v", err)
	}

	// Une autorisation fabriquée par quelqu'un d'autre (le coordinateur par exemple)
	// en se faisant passer pour le propriétaire est refusée.
	forged := NewGrant(mallory, "f1", pub(mallory), now, time.Hour)
	forged.OwnerPublicKey = pub(alice)
	if err := VerifyGrant(forged, "f1", pub(alice), now); !errors.Is(err, ErrSignature) {
		t.Errorf("autorisation fabriquée : erreur %v", err)
	}
}

func TestRevocation(t *testing.T) {
	alice, bob, mallory := newKey(t), newKey(t), newKey(t)
	r := NewRevocation(alice, "f1", pub(bob), time.Now())
	if err := VerifyRevocation(r, pub(alice)); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRevocation(r, pub(mallory)); !errors.Is(err, ErrWrongOwner) {
		t.Errorf("erreur %v, attendue ErrWrongOwner", err)
	}
	r.RevokedAt--
	if err := VerifyRevocation(r, pub(alice)); !errors.Is(err, ErrSignature) {
		t.Errorf("erreur %v, attendue ErrSignature", err)
	}
}

func TestFingerprint(t *testing.T) {
	k := pub(newKey(t))
	f := Fingerprint(k)
	if len(f) != 39 || f != Fingerprint(k) || f == Fingerprint(pub(newKey(t))) {
		t.Fatalf("empreinte inattendue %q", f)
	}
}
