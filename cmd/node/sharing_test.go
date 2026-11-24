package main

import (
	"context"
	"crypto/ed25519"
	"io"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"safevault/internal/access"
	pb "safevault/proto"
)

func publicKey(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

// sharedFile dépose une part et un bloc pour alice et renvoie le nœud.
func sharedFile(t *testing.T, alice ed25519.PrivateKey) *testNode {
	t.Helper()
	n := startNode(t)
	putShare(t, n, alice, "f1", 1, []byte("part"))
	if _, err := putBlocks(t, n, alice, "f1", 1, func(i int) []byte {
		if i == 0 {
			return []byte("bloc chiffré")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func getShareAs(n *testNode, key ed25519.PrivateKey, grant *pb.Grant) error {
	_, err := n.node.GetShare(context.Background(), &pb.GetShareRequest{
		FileId: "f1", Epoch: 1, Proof: proof(key, labelGetShare, "f1", 1), Grant: grant,
	})
	return err
}

func getBlocksAs(n *testNode, key ed25519.PrivateKey, grant *pb.Grant) error {
	stream, err := n.node.GetBlocks(context.Background(), &pb.GetBlocksRequest{
		FileId: "f1", Proof: proof(key, labelGetBlocks, "f1", 0), Grant: grant,
	})
	if err != nil {
		return err
	}
	for {
		if _, err := stream.Recv(); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
	}
}

func TestGranteeCanRead(t *testing.T) {
	alice, bob := newUserKey(t), newUserKey(t)
	n := sharedFile(t, alice)
	grant := access.NewGrant(alice, "f1", publicKey(bob), time.Now(), time.Hour)

	if err := getShareAs(n, bob, grant); err != nil {
		t.Fatalf("bob ne peut pas lire sa part : %v", err)
	}
	if err := getBlocksAs(n, bob, grant); err != nil {
		t.Fatalf("bob ne peut pas lire les blocs : %v", err)
	}
	// Sans autorisation, bob est refusé.
	wantCode(t, getShareAs(n, bob, nil), codes.PermissionDenied)
}

func TestGrantRefused(t *testing.T) {
	alice, bob, charlie := newUserKey(t), newUserKey(t), newUserKey(t)
	n := sharedFile(t, alice)
	now := time.Now()

	// Charlie présente l'autorisation de bob : elle n'est pas pour sa clé.
	bobGrant := access.NewGrant(alice, "f1", publicKey(bob), now, time.Hour)
	wantCode(t, getShareAs(n, charlie, bobGrant), codes.PermissionDenied)

	// Le coordinateur (ou charlie) fabrique une autorisation au nom d'alice.
	forged := access.NewGrant(charlie, "f1", publicKey(charlie), now, time.Hour)
	forged.OwnerPublicKey = publicKey(alice)
	wantCode(t, getShareAs(n, charlie, forged), codes.PermissionDenied)

	// Une autorisation signée par charlie pour lui-même : charlie n'est pas le propriétaire.
	self := access.NewGrant(charlie, "f1", publicKey(charlie), now, time.Hour)
	wantCode(t, getShareAs(n, charlie, self), codes.PermissionDenied)

	// Une autorisation expirée.
	expired := access.NewGrant(alice, "f1", publicKey(bob), now.Add(-2*time.Hour), time.Hour)
	wantCode(t, getShareAs(n, bob, expired), codes.PermissionDenied)

	// Une autorisation pour un autre fichier.
	other := access.NewGrant(alice, "f2", publicKey(bob), now, time.Hour)
	wantCode(t, getBlocksAs(n, bob, other), codes.PermissionDenied)
}

func TestRevocation(t *testing.T) {
	alice, bob := newUserKey(t), newUserKey(t)
	n := sharedFile(t, alice)
	now := time.Now()
	grant := access.NewGrant(alice, "f1", publicKey(bob), now, time.Hour)
	if err := getShareAs(n, bob, grant); err != nil {
		t.Fatal(err)
	}

	// Bob ne peut pas révoquer à la place d'alice.
	_, err := n.node.Revoke(context.Background(), &pb.RevokeRequest{
		Revocation: access.NewRevocation(bob, "f1", publicKey(bob), now)})
	wantCode(t, err, codes.PermissionDenied)

	// Alice révoque : l'autorisation déjà émise ne marche plus, ni pour la part ni pour les blocs.
	revocation := access.NewRevocation(alice, "f1", publicKey(bob), now.Add(time.Second))
	if _, err := n.node.Revoke(context.Background(), &pb.RevokeRequest{Revocation: revocation}); err != nil {
		t.Fatal(err)
	}
	wantCode(t, getShareAs(n, bob, grant), codes.PermissionDenied)
	wantCode(t, getBlocksAs(n, bob, grant), codes.PermissionDenied)

	// Rejouer la révocation ne change rien.
	if _, err := n.node.Revoke(context.Background(), &pb.RevokeRequest{Revocation: revocation}); err != nil {
		t.Fatal(err)
	}

	// Une nouvelle autorisation, émise après la révocation, rouvre l'accès.
	renewed := access.NewGrant(alice, "f1", publicKey(bob), now.Add(5*time.Second), time.Hour)
	if err := getShareAs(n, bob, renewed); err != nil {
		t.Fatalf("nouvelle autorisation refusée : %v", err)
	}
}

func TestRevokeUnknownFile(t *testing.T) {
	alice, bob := newUserKey(t), newUserKey(t)
	n := startNode(t)
	_, err := n.node.Revoke(context.Background(), &pb.RevokeRequest{
		Revocation: access.NewRevocation(alice, "absent", publicKey(bob), time.Now())})
	wantCode(t, err, codes.NotFound)
}
