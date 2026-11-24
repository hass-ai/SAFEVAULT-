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

// readGrant crée une autorisation de lecture d'une heure.
func readGrant(issuer ed25519.PrivateKey, fileID string, grantee ed25519.PrivateKey, at time.Time) *pb.Grant {
	return access.NewGrant(issuer, fileID, publicKey(grantee), access.Read, at, at.Add(time.Hour), nil)
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
	grant := readGrant(alice, "f1", bob, time.Now())

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
	bobGrant := readGrant(alice, "f1", bob, now)
	wantCode(t, getShareAs(n, charlie, bobGrant), codes.PermissionDenied)

	// Le coordinateur (ou charlie) fabrique une autorisation au nom d'alice.
	forged := readGrant(charlie, "f1", charlie, now)
	forged.IssuerPublicKey = publicKey(alice)
	wantCode(t, getShareAs(n, charlie, forged), codes.PermissionDenied)

	// Une autorisation signée par charlie pour lui-même : charlie n'est pas le propriétaire.
	self := readGrant(charlie, "f1", charlie, now)
	wantCode(t, getShareAs(n, charlie, self), codes.PermissionDenied)

	// Une autorisation expirée.
	expired := access.NewGrant(alice, "f1", publicKey(bob), access.Read, now.Add(-2*time.Hour), now.Add(-time.Hour), nil)
	wantCode(t, getShareAs(n, bob, expired), codes.PermissionDenied)

	// Une autorisation pour un autre fichier.
	other := readGrant(alice, "f2", bob, now)
	wantCode(t, getBlocksAs(n, bob, other), codes.PermissionDenied)
}

func TestRevocation(t *testing.T) {
	alice, bob := newUserKey(t), newUserKey(t)
	n := sharedFile(t, alice)
	now := time.Now()
	grant := readGrant(alice, "f1", bob, now)
	if err := getShareAs(n, bob, grant); err != nil {
		t.Fatal(err)
	}

	// Bob ne peut pas révoquer à la place d'alice.
	_, err := n.node.Revoke(context.Background(), &pb.RevokeRequest{
		Revocation: access.NewRevocation(bob, "f1", publicKey(bob), now, nil)})
	wantCode(t, err, codes.PermissionDenied)

	// Alice révoque : l'autorisation déjà émise ne marche plus, ni pour la part ni pour les blocs.
	revocation := access.NewRevocation(alice, "f1", publicKey(bob), now.Add(time.Second), nil)
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
	renewed := readGrant(alice, "f1", bob, now.Add(5*time.Second))
	if err := getShareAs(n, bob, renewed); err != nil {
		t.Fatalf("nouvelle autorisation refusée : %v", err)
	}
}

func TestRevokeUnknownFile(t *testing.T) {
	alice, bob := newUserKey(t), newUserKey(t)
	n := startNode(t)
	_, err := n.node.Revoke(context.Background(), &pb.RevokeRequest{
		Revocation: access.NewRevocation(alice, "absent", publicKey(bob), time.Now(), nil)})
	wantCode(t, err, codes.NotFound)
}

// putVersion dépose la part et un bloc de la version v de f1 au nom de key.
func putVersion(n *testNode, key ed25519.PrivateKey, v uint32, grant *pb.Grant, data string) error {
	_, err := n.node.PutShare(context.Background(), &pb.PutShareRequest{
		FileId: "f1", Share: &pb.Share{X: testX, Value: []byte("part v"), Epoch: 1},
		Proof: proof(key, labelPutShare, "f1", 1), Version: v, Grant: grant,
	})
	if err != nil {
		return err
	}
	stream, err := n.node.PutBlocks(context.Background())
	if err != nil {
		return err
	}
	err = stream.Send(&pb.Block{FileId: "f1", Index: 0, Data: []byte(data), Version: v,
		Proof: proof(key, labelPutBlocks, "f1", 1)})
	if err != nil {
		return err
	}
	_, err = stream.CloseAndRecv()
	return err
}

func readBlock0(t *testing.T, n *testNode, key ed25519.PrivateKey, v uint32, grant *pb.Grant) string {
	t.Helper()
	stream, err := n.node.GetBlocks(context.Background(), &pb.GetBlocksRequest{
		FileId: "f1", Proof: proof(key, labelGetBlocks, "f1", 0), Grant: grant, Version: v,
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	return string(b.Data)
}

func TestVersions(t *testing.T) {
	alice, bob, charlie := newUserKey(t), newUserKey(t), newUserKey(t)
	n := sharedFile(t, alice)
	now := time.Now()

	// Lecture seule : bob ne peut pas déposer de version.
	wantCode(t, putVersion(n, bob, 2, readGrant(alice, "f1", bob, now), "v2"), codes.PermissionDenied)

	// Avec le droit w, il peut.
	writer := access.NewGrant(alice, "f1", publicKey(bob), access.Read|access.Write, now, time.Time{}, nil)
	if err := putVersion(n, bob, 2, writer, "version 2"); err != nil {
		t.Fatalf("dépôt d'une version avec le droit w refusé : %v", err)
	}
	// Les deux versions restent lisibles, chacune sous sa clé de stockage.
	if got := readBlock0(t, n, alice, 1, nil); got != "bloc chiffré" {
		t.Fatalf("version 1 = %q", got)
	}
	if got := readBlock0(t, n, alice, 2, nil); got != "version 2" {
		t.Fatalf("version 2 = %q", got)
	}
	// Personne d'autre ne peut écraser la version 2, pas même le propriétaire.
	wantCode(t, putVersion(n, alice, 2, nil, "écrasée"), codes.PermissionDenied)
	// Ni réclamer le fichier en déposant une « version 1 ».
	wantCode(t, putVersion(n, charlie, 1, nil, "pirate"), codes.PermissionDenied)
}

func TestDelegatedAccess(t *testing.T) {
	alice, bob, carol := newUserKey(t), newUserKey(t), newUserKey(t)
	n := sharedFile(t, alice)
	now := time.Now()

	bobGrant := access.NewGrant(alice, "f1", publicKey(bob), access.Read|access.Share, now, time.Time{}, nil)
	carolGrant := access.NewGrant(bob, "f1", publicKey(carol), access.Read, now, time.Time{}, bobGrant)
	if err := getShareAs(n, carol, carolGrant); err != nil {
		t.Fatalf("accès repartagé refusé : %v", err)
	}
	// Retirer bob coupe aussi carol.
	r := access.NewRevocation(alice, "f1", publicKey(bob), now.Add(time.Second), nil)
	if _, err := n.node.Revoke(context.Background(), &pb.RevokeRequest{Revocation: r}); err != nil {
		t.Fatal(err)
	}
	wantCode(t, getShareAs(n, carol, carolGrant), codes.PermissionDenied)
}

func TestDeleteFile(t *testing.T) {
	alice, bob := newUserKey(t), newUserKey(t)
	n := sharedFile(t, alice)
	now := time.Now()
	del := func(key ed25519.PrivateKey, grant *pb.Grant) error {
		_, err := n.node.DeleteFile(context.Background(), &pb.DeleteFileRequest{
			FileId: "f1", Proof: proof(key, labelDelete, "f1", 0), Grant: grant})
		return err
	}
	wantCode(t, del(bob, readGrant(alice, "f1", bob, now)), codes.PermissionDenied)

	deleter := access.NewGrant(alice, "f1", publicKey(bob), access.Read|access.Delete, now, time.Time{}, nil)
	if err := del(bob, deleter); err != nil {
		t.Fatalf("suppression avec le droit d refusée : %v", err)
	}
	wantCode(t, getShareAs(n, alice, nil), codes.NotFound)
	if _, err := n.store.Share("f1_v1"); err == nil {
		t.Fatal("la part existe encore après la suppression")
	}
	if _, err := n.store.BlockIndexes("f1_v1"); err == nil {
		t.Fatal("les blocs existent encore après la suppression")
	}
}

func TestTransferOwnership(t *testing.T) {
	alice, bob, carol := newUserKey(t), newUserKey(t), newUserKey(t)
	n := sharedFile(t, alice)
	now := time.Now()
	before := readGrant(alice, "f1", carol, now)

	transfer := func(tr *pb.Transfer) error {
		_, err := n.node.TransferOwnership(context.Background(), &pb.TransferRequest{Transfer: tr})
		return err
	}
	// Bob ne peut pas se donner le fichier.
	wantCode(t, transfer(access.NewTransfer(bob, "f1", publicKey(bob), now)), codes.PermissionDenied)

	if err := transfer(access.NewTransfer(alice, "f1", publicKey(bob), now.Add(time.Second))); err != nil {
		t.Fatal(err)
	}
	// Bob est propriétaire, alice ne l'est plus ; l'accès donné avant par alice reste.
	if err := getShareAs(n, bob, nil); err != nil {
		t.Fatalf("le nouveau propriétaire ne peut pas lire : %v", err)
	}
	wantCode(t, getShareAs(n, alice, nil), codes.PermissionDenied)
	if err := getShareAs(n, carol, before); err != nil {
		t.Fatalf("autorisation antérieure au transfert refusée : %v", err)
	}
	// Une autorisation signée par alice après le transfert ne vaut rien.
	wantCode(t, getShareAs(n, carol, readGrant(alice, "f1", carol, now.Add(time.Minute))), codes.PermissionDenied)
}
