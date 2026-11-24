package main

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"safevault/internal/access"
	pb "safevault/proto"
)

// readyFileFor dépose et confirme un fichier pour l'utilisateur connecté dans ctx.
func readyFileFor(t *testing.T, c *testCoordinator, ctx context.Context) string {
	t.Helper()
	file, err := c.coord.CreateFile(ctx, &pb.CreateFileRequest{EncryptedName: []byte("nom chiffré"), Size: 100})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.coord.ConfirmUpload(ctx, &pb.ConfirmUploadRequest{FileId: file.FileId, Manifest: manifestFor(1, 100)})
	if err != nil {
		t.Fatal(err)
	}
	return file.FileId
}

func TestShareFile(t *testing.T) {
	c := startCoordinator(t)
	c.allNodesUp(t)
	aliceKey, bobKey := registerUser(t, c, "alice"), registerUser(t, c, "bob")
	charlieKey := registerUser(t, c, "charlie")
	alice, _ := loginToken(t, c, "alice", aliceKey)
	bob, _ := loginToken(t, c, "bob", bobKey)
	charlie, _ := loginToken(t, c, "charlie", charlieKey)
	fileID := readyFileFor(t, c, alice)

	// La clé de bob donnée par le coordinateur est bien la sienne.
	key, err := c.coord.GetUserKey(alice, &pb.GetUserKeyRequest{Username: "bob"})
	if err != nil || string(key.PublicKey) != string(bobKey.Public().(ed25519.PublicKey)) {
		t.Fatalf("clé de bob : %v", err)
	}

	// Avant le partage, bob ne voit pas le fichier.
	_, err = c.coord.GetFile(bob, &pb.GetFileRequest{FileId: fileID})
	wantCode(t, err, codes.NotFound, "GetFile de bob avant partage")

	grant := access.NewGrant(aliceKey, fileID, key.PublicKey, time.Now(), time.Hour)
	_, err = c.coord.ShareFile(alice, &pb.ShareFileRequest{Grantee: "bob", Grant: grant, EncryptedName: []byte("nom pour bob")})
	if err != nil {
		t.Fatal(err)
	}

	// Bob voit le fichier, avec le nom chiffré pour lui, et reçoit l'autorisation.
	list, err := c.coord.ListFiles(bob, &pb.ListFilesRequest{})
	if err != nil || len(list.Files) != 1 {
		t.Fatalf("fichiers de bob : %+v, %v", list, err)
	}
	f := list.Files[0]
	if f.FileId != fileID || !f.Shared || f.Owner != "alice" || string(f.EncryptedName) != "nom pour bob" {
		t.Fatalf("fichier partagé vu par bob : %+v", f)
	}
	got, err := c.coord.GetFile(bob, &pb.GetFileRequest{FileId: fileID})
	if err != nil || got.Grant == nil || string(got.Grant.Signature) != string(grant.Signature) {
		t.Fatalf("GetFile de bob : %+v, %v", got, err)
	}
	// Le propriétaire, lui, ne reçoit pas d'autorisation.
	if own, _ := c.coord.GetFile(alice, &pb.GetFileRequest{FileId: fileID}); own.Grant != nil {
		t.Fatal("autorisation renvoyée au propriétaire")
	}
	// Charlie ne voit toujours rien.
	_, err = c.coord.GetFile(charlie, &pb.GetFileRequest{FileId: fileID})
	wantCode(t, err, codes.NotFound, "GetFile de charlie")

	// Alice retire le partage : bob ne voit plus le fichier.
	if _, err := c.coord.RevokeShare(alice, &pb.RevokeShareRequest{FileId: fileID, Grantee: "bob"}); err != nil {
		t.Fatal(err)
	}
	_, err = c.coord.GetFile(bob, &pb.GetFileRequest{FileId: fileID})
	wantCode(t, err, codes.NotFound, "GetFile de bob après retrait")
	if list, _ := c.coord.ListFiles(bob, &pb.ListFilesRequest{}); len(list.Files) != 0 {
		t.Fatalf("bob voit encore %d fichier(s)", len(list.Files))
	}
}

func TestShareFileRefused(t *testing.T) {
	c := startCoordinator(t)
	c.allNodesUp(t)
	aliceKey, bobKey := registerUser(t, c, "alice"), registerUser(t, c, "bob")
	registerUser(t, c, "charlie")
	alice, _ := loginToken(t, c, "alice", aliceKey)
	bob, _ := loginToken(t, c, "bob", bobKey)
	fileID := readyFileFor(t, c, alice)
	bobPub := bobKey.Public().(ed25519.PublicKey)
	now := time.Now()
	share := func(ctx context.Context, grantee string, g *pb.Grant) error {
		_, err := c.coord.ShareFile(ctx, &pb.ShareFileRequest{Grantee: grantee, Grant: g, EncryptedName: []byte("n")})
		return err
	}

	// Bob ne peut pas partager le fichier d'alice, même avec une autorisation qu'il signe.
	wantCode(t, share(bob, "bob", access.NewGrant(bobKey, fileID, bobPub, now, time.Hour)),
		codes.InvalidArgument, "partage par bob")
	// L'autorisation est faite pour bob mais annoncée pour charlie.
	wantCode(t, share(alice, "charlie", access.NewGrant(aliceKey, fileID, bobPub, now, time.Hour)),
		codes.InvalidArgument, "destinataire incohérent")
	// Autorisation expirée.
	wantCode(t, share(alice, "bob", access.NewGrant(aliceKey, fileID, bobPub, now.Add(-2*time.Hour), time.Hour)),
		codes.InvalidArgument, "autorisation expirée")
	// Destinataire inconnu.
	wantCode(t, share(alice, "inconnu", access.NewGrant(aliceKey, fileID, bobPub, now, time.Hour)),
		codes.NotFound, "destinataire inconnu")
	// Fichier inconnu.
	wantCode(t, share(alice, "bob", access.NewGrant(aliceKey, "absent", bobPub, now, time.Hour)),
		codes.NotFound, "fichier inconnu")
	// Partage avec soi-même.
	alicePub := aliceKey.Public().(ed25519.PublicKey)
	wantCode(t, share(alice, "alice", access.NewGrant(aliceKey, fileID, alicePub, now, time.Hour)),
		codes.InvalidArgument, "partage avec soi-même")

	// Bob ne peut pas retirer un partage d'alice.
	_, err := c.coord.RevokeShare(bob, &pb.RevokeShareRequest{FileId: fileID, Grantee: "bob"})
	wantCode(t, err, codes.NotFound, "retrait par bob")

	_, err = c.coord.GetUserKey(alice, &pb.GetUserKeyRequest{Username: "inconnu"})
	wantCode(t, err, codes.NotFound, "clé d'un inconnu")
}
