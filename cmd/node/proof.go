package main

import (
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "safevault/proto"
)

// Étiquettes des preuves, une par appel : une signature faite pour un appel
// ne peut pas être réutilisée pour un autre.
const (
	labelPutShare  = "safevault/putshare/v1"
	labelGetShare  = "safevault/getshare/v1"
	labelPutBlocks = "safevault/putblocks/v1"
	labelGetBlocks = "safevault/getblocks/v1"
)

// proofMaxAge est l'écart maximal accepté entre l'horodatage d'une preuve et l'heure du nœud.
const proofMaxAge = 2 * time.Minute

// proofVerifier vérifie les preuves d'identité et refuse celles déjà utilisées.
type proofVerifier struct {
	now func() time.Time

	mu        sync.Mutex
	seen      map[string]time.Time // nonce déjà vu → date d'expiration
	lastPurge time.Time
}

func newProofVerifier() *proofVerifier {
	return &proofVerifier{now: time.Now, seen: make(map[string]time.Time)}
}

// verify contrôle la preuve p d'une requête de type label pour le nœud x, le fichier fileID
// et l'époque epoch. Elle renvoie une erreur gRPC Unauthenticated si la preuve est refusée.
func (v *proofVerifier) verify(label string, x uint32, fileID string, epoch uint64, p *pb.Proof) error {
	if p == nil {
		return status.Error(codes.Unauthenticated, "preuve d'identité manquante")
	}
	if len(p.PublicKey) != ed25519.PublicKeySize || len(p.Signature) != ed25519.SignatureSize {
		return status.Error(codes.Unauthenticated, "preuve d'identité mal formée")
	}
	if len(p.Nonce) < 8 || len(p.Nonce) > 64 {
		return status.Error(codes.Unauthenticated, "nonce de taille invalide")
	}

	now := v.now()
	signedAt := time.Unix(p.Timestamp, 0)
	if signedAt.Before(now.Add(-proofMaxAge)) || signedAt.After(now.Add(proofMaxAge)) {
		return status.Error(codes.Unauthenticated, "preuve d'identité expirée")
	}

	message := fmt.Sprintf("%d|%s|%d|%d|%x", x, fileID, epoch, p.Timestamp, p.Nonce)
	data := append([]byte(label), 0)
	data = append(data, message...)
	if !ed25519.Verify(ed25519.PublicKey(p.PublicKey), data, p.Signature) {
		return status.Error(codes.Unauthenticated, "signature invalide")
	}

	// La preuve n'est enregistrée qu'une fois vérifiée, pour qu'un tiers ne puisse pas
	// « griller » le nonce d'un client avec une fausse signature.
	key := string(p.PublicKey) + string(p.Nonce)
	v.mu.Lock()
	defer v.mu.Unlock()
	if now.Sub(v.lastPurge) > 10*time.Second {
		for k, expiry := range v.seen {
			if now.After(expiry) {
				delete(v.seen, k)
			}
		}
		v.lastPurge = now
	}
	if _, replayed := v.seen[key]; replayed {
		return status.Error(codes.Unauthenticated, "preuve d'identité déjà utilisée")
	}
	v.seen[key] = signedAt.Add(proofMaxAge)
	return nil
}
