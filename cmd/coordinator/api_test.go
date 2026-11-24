package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"regexp"
	"testing"

	"google.golang.org/grpc/codes"
	grpcmd "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "safevault/proto"
)

// sign signe comme le client SafeVault : étiquette || 0x00 || message.
func sign(key ed25519.PrivateKey, label string, message []byte) []byte {
	return ed25519.Sign(key, signedMessage(label, message))
}

func registerUser(t *testing.T, c *testCoordinator, name string) ed25519.PrivateKey {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	_, err := c.coord.Register(testContext(t), &pb.RegisterRequest{
		Username:  name,
		PublicKey: pub,
		Signature: sign(key, labelRegister, append([]byte(name), pub...)),
	})
	if err != nil {
		t.Fatalf("inscription de %s : %v", name, err)
	}
	return key
}

// loginToken se connecte comme le client et renvoie un contexte avec le jeton, et le jeton.
func loginToken(t *testing.T, c *testCoordinator, name string, key ed25519.PrivateKey) (context.Context, string) {
	t.Helper()
	ctx := testContext(t)
	ch, err := c.coord.GetChallenge(ctx, &pb.GetChallengeRequest{Username: name})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.coord.Login(ctx, &pb.LoginRequest{
		Username: name, Challenge: ch.Challenge, Signature: sign(key, labelLogin, ch.Challenge),
	})
	if err != nil {
		t.Fatalf("connexion de %s : %v", name, err)
	}
	return withToken(ctx, resp.Token), resp.Token
}

func withToken(ctx context.Context, token string) context.Context {
	return grpcmd.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}

func wantCode(t *testing.T, err error, want codes.Code, what string) {
	t.Helper()
	if got := status.Code(err); got != want {
		t.Fatalf("%s : %s (%v), attendu %s", what, got, err, want)
	}
}

// ---------- Inscription et connexion (SV-26) ----------

func TestRegisterLoginAndAuthenticatedCall(t *testing.T) {
	c := startCoordinator(t)
	key := registerUser(t, c, "alice")
	ctx, _ := loginToken(t, c, "alice", key)
	resp, err := c.coord.ListFiles(ctx, &pb.ListFilesRequest{})
	if err != nil {
		t.Fatalf("appel authentifié refusé : %v", err)
	}
	if len(resp.Files) != 0 {
		t.Fatalf("nouvel utilisateur avec des fichiers : %v", resp.Files)
	}
}

func TestRegisterRejects(t *testing.T) {
	c := startCoordinator(t)
	registerUser(t, c, "alice")
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	ctx := testContext(t)

	good := func(name string) *pb.RegisterRequest {
		return &pb.RegisterRequest{Username: name, PublicKey: pub,
			Signature: sign(key, labelRegister, append([]byte(name), pub...))}
	}
	_, err := c.coord.Register(ctx, good("alice"))
	wantCode(t, err, codes.AlreadyExists, "nom déjà pris")

	bad := good("bob")
	bad.Signature = sign(key, labelRegister, append([]byte("mallory"), pub...))
	_, err = c.coord.Register(ctx, bad)
	wantCode(t, err, codes.InvalidArgument, "signature d'un autre nom")

	bad = good("bob")
	bad.Signature = sign(key, labelLogin, append([]byte("bob"), pub...))
	_, err = c.coord.Register(ctx, bad)
	wantCode(t, err, codes.InvalidArgument, "signature avec une autre étiquette")

	_, err = c.coord.Register(ctx, good("nom avec espaces"))
	wantCode(t, err, codes.InvalidArgument, "nom invalide")

	_, err = c.coord.Register(ctx, &pb.RegisterRequest{Username: "carol", PublicKey: []byte("court")})
	wantCode(t, err, codes.InvalidArgument, "clé de mauvaise taille")
}

func TestLoginRejects(t *testing.T) {
	c := startCoordinator(t)
	key := registerUser(t, c, "alice")
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	ctx := testContext(t)

	// Mauvaise clé : refus, et le défi est brûlé.
	ch, _ := c.coord.GetChallenge(ctx, &pb.GetChallengeRequest{Username: "alice"})
	_, err := c.coord.Login(ctx, &pb.LoginRequest{Username: "alice", Challenge: ch.Challenge,
		Signature: sign(otherKey, labelLogin, ch.Challenge)})
	wantCode(t, err, codes.Unauthenticated, "signature d'une autre clé")
	_, err = c.coord.Login(ctx, &pb.LoginRequest{Username: "alice", Challenge: ch.Challenge,
		Signature: sign(key, labelLogin, ch.Challenge)})
	wantCode(t, err, codes.Unauthenticated, "défi brûlé par l'échec précédent")

	// Défi réutilisé après une connexion réussie.
	ch, _ = c.coord.GetChallenge(ctx, &pb.GetChallengeRequest{Username: "alice"})
	req := &pb.LoginRequest{Username: "alice", Challenge: ch.Challenge, Signature: sign(key, labelLogin, ch.Challenge)}
	if _, err := c.coord.Login(ctx, req); err != nil {
		t.Fatal(err)
	}
	_, err = c.coord.Login(ctx, req)
	wantCode(t, err, codes.Unauthenticated, "rejeu d'une connexion")

	// Défi inventé par le client.
	fake := make([]byte, 32)
	_, err = c.coord.Login(ctx, &pb.LoginRequest{Username: "alice", Challenge: fake, Signature: sign(key, labelLogin, fake)})
	wantCode(t, err, codes.Unauthenticated, "défi inventé")

	// Utilisateur inconnu : un défi est quand même donné, la connexion échoue.
	ch, err = c.coord.GetChallenge(ctx, &pb.GetChallengeRequest{Username: "inconnu"})
	if err != nil || len(ch.Challenge) != challengeSize {
		t.Fatalf("défi pour un nom inconnu : %v, %d octets", err, len(ch.GetChallenge()))
	}
	_, err = c.coord.Login(ctx, &pb.LoginRequest{Username: "inconnu", Challenge: ch.Challenge,
		Signature: sign(key, labelLogin, ch.Challenge)})
	wantCode(t, err, codes.Unauthenticated, "utilisateur inconnu")
}

func TestTokenRequired(t *testing.T) {
	c := startCoordinator(t)
	c.allNodesUp(t)
	for name, ctx := range map[string]context.Context{
		"sans jeton":     testContext(t),
		"jeton inventé":  withToken(testContext(t), "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"),
		"schéma inconnu": grpcmd.AppendToOutgoingContext(testContext(t), "authorization", "Basic abc"),
	} {
		_, err := c.coord.ListFiles(ctx, &pb.ListFilesRequest{})
		wantCode(t, err, codes.Unauthenticated, name+", ListFiles")
		_, err = c.coord.CreateFile(ctx, &pb.CreateFileRequest{EncryptedName: []byte("x"), Size: 1})
		wantCode(t, err, codes.Unauthenticated, name+", CreateFile")
		_, err = c.coord.ConfirmUpload(ctx, &pb.ConfirmUploadRequest{FileId: "x"})
		wantCode(t, err, codes.Unauthenticated, name+", ConfirmUpload")
		_, err = c.coord.GetFile(ctx, &pb.GetFileRequest{FileId: "x"})
		wantCode(t, err, codes.Unauthenticated, name+", GetFile")
	}
}

// ---------- Fichiers (SV-16) ----------

// manifestFor construit le manifeste d'un fichier de size octets découpé en blocks blocs.
func manifestFor(blocks int, size uint64) *pb.Manifest {
	m := &pb.Manifest{BlockCount: uint32(blocks), Size: size}
	for i := 0; i < blocks; i++ {
		h := sha256.Sum256([]byte{byte(i)})
		m.BlockHashes = append(m.BlockHashes, h[:])
	}
	return m
}

var fileIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

func TestUploadThenDownloadInfo(t *testing.T) {
	c := startCoordinator(t)
	c.allNodesUp(t)
	ctx, _ := loginToken(t, c, "alice", registerUser(t, c, "alice"))

	file, err := c.coord.CreateFile(ctx, &pb.CreateFileRequest{EncryptedName: []byte("rapport.pdf"), Size: 3000})
	if err != nil {
		t.Fatal(err)
	}
	if !fileIDPattern.MatchString(file.FileId) {
		t.Fatalf("identifiant %q : attendu 22 caractères base64url", file.FileId)
	}
	if file.Epoch != 1 || file.T != 3 || file.N != 5 || len(file.Nodes) != 5 {
		t.Fatalf("réponse CreateFile : %+v", file)
	}
	for i, n := range file.Nodes {
		if n.X != uint32(i+1) {
			t.Fatalf("nœud %d d'abscisse %d : le client donne la part d'indice x au nœud x", i, n.X)
		}
	}

	// Avant confirmation, le fichier n'est ni listé ni lisible.
	_, err = c.coord.GetFile(ctx, &pb.GetFileRequest{FileId: file.FileId})
	wantCode(t, err, codes.FailedPrecondition, "GetFile avant ConfirmUpload")

	_, err = c.coord.ConfirmUpload(ctx, &pb.ConfirmUploadRequest{FileId: file.FileId, Manifest: manifestFor(3, 3000)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.coord.ConfirmUpload(ctx, &pb.ConfirmUploadRequest{FileId: file.FileId, Manifest: manifestFor(3, 3000)})
	wantCode(t, err, codes.FailedPrecondition, "deuxième ConfirmUpload")

	list, err := c.coord.ListFiles(ctx, &pb.ListFilesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Files) != 1 || list.Files[0].FileId != file.FileId || string(list.Files[0].EncryptedName) != "rapport.pdf" ||
		list.Files[0].Size != 3000 {
		t.Fatalf("ListFiles : %+v", list.Files)
	}

	got, err := c.coord.GetFile(ctx, &pb.GetFileRequest{FileId: file.FileId})
	if err != nil {
		t.Fatal(err)
	}
	if got.Epoch != 1 || got.T != 3 || len(got.Nodes) != 5 || got.Manifest.BlockCount != 3 ||
		len(got.Manifest.BlockHashes) != 3 || got.Manifest.Size != 3000 {
		t.Fatalf("GetFile : %+v", got)
	}
}

func TestConfirmUploadRejectsBadManifest(t *testing.T) {
	c := startCoordinator(t)
	c.allNodesUp(t)
	ctx, _ := loginToken(t, c, "alice", registerUser(t, c, "alice"))
	file, err := c.coord.CreateFile(ctx, &pb.CreateFileRequest{EncryptedName: []byte("a"), Size: 100})
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.coord.ConfirmUpload(ctx, &pb.ConfirmUploadRequest{FileId: file.FileId})
	wantCode(t, err, codes.InvalidArgument, "sans manifeste")
	bad := manifestFor(2, 100)
	bad.BlockCount = 5
	_, err = c.coord.ConfirmUpload(ctx, &pb.ConfirmUploadRequest{FileId: file.FileId, Manifest: bad})
	wantCode(t, err, codes.InvalidArgument, "nombre de blocs incohérent")
	_, err = c.coord.ConfirmUpload(ctx, &pb.ConfirmUploadRequest{FileId: file.FileId, Manifest: manifestFor(1, 99)})
	wantCode(t, err, codes.InvalidArgument, "taille différente de CreateFile")
	_, err = c.coord.ConfirmUpload(ctx, &pb.ConfirmUploadRequest{FileId: "inconnu", Manifest: manifestFor(1, 100)})
	wantCode(t, err, codes.NotFound, "fichier inconnu")
}

func TestOtherUserCannotTouchFile(t *testing.T) {
	c := startCoordinator(t)
	c.allNodesUp(t)
	alice, _ := loginToken(t, c, "alice", registerUser(t, c, "alice"))
	bob, _ := loginToken(t, c, "bob", registerUser(t, c, "bob"))

	file, err := c.coord.CreateFile(alice, &pb.CreateFileRequest{EncryptedName: []byte("a"), Size: 10})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.coord.ConfirmUpload(bob, &pb.ConfirmUploadRequest{FileId: file.FileId, Manifest: manifestFor(1, 10)})
	wantCode(t, err, codes.NotFound, "ConfirmUpload par un autre utilisateur")

	if _, err := c.coord.ConfirmUpload(alice, &pb.ConfirmUploadRequest{FileId: file.FileId, Manifest: manifestFor(1, 10)}); err != nil {
		t.Fatal(err)
	}
	_, err = c.coord.GetFile(bob, &pb.GetFileRequest{FileId: file.FileId})
	wantCode(t, err, codes.NotFound, "GetFile par un autre utilisateur")
	list, err := c.coord.ListFiles(bob, &pb.ListFilesRequest{})
	if err != nil || len(list.Files) != 0 {
		t.Fatalf("bob voit %v (%v)", list.GetFiles(), err)
	}
}

func TestCreateFileNeedsAllNodesUp(t *testing.T) {
	c := startCoordinator(t)
	ctx, _ := loginToken(t, c, "alice", registerUser(t, c, "alice"))

	// Au démarrage, aucun nœud n'a encore répondu.
	_, err := c.coord.CreateFile(ctx, &pb.CreateFileRequest{EncryptedName: []byte("a"), Size: 1})
	wantCode(t, err, codes.Unavailable, "nœuds jamais vus")

	c.setNodes(t, true, true, false, true, true)
	_, err = c.coord.CreateFile(ctx, &pb.CreateFileRequest{EncryptedName: []byte("a"), Size: 1})
	wantCode(t, err, codes.Unavailable, "nœud 3 en panne")

	_, err = c.coord.CreateFile(ctx, &pb.CreateFileRequest{EncryptedName: []byte(""), Size: 1})
	wantCode(t, err, codes.InvalidArgument, "nom vide")
}

func TestGetFileWorksWithNodesDownAndListsUpNodesFirst(t *testing.T) {
	c := startCoordinator(t)
	c.allNodesUp(t)
	ctx, _ := loginToken(t, c, "alice", registerUser(t, c, "alice"))
	file, err := c.coord.CreateFile(ctx, &pb.CreateFileRequest{EncryptedName: []byte("a"), Size: 10})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.coord.ConfirmUpload(ctx, &pb.ConfirmUploadRequest{FileId: file.FileId, Manifest: manifestFor(1, 10)}); err != nil {
		t.Fatal(err)
	}

	// n - t = 2 pannes : la récupération doit rester possible.
	c.setNodes(t, false, true, false, true, true)
	got, err := c.coord.GetFile(ctx, &pb.GetFileRequest{FileId: file.FileId})
	if err != nil {
		t.Fatal(err)
	}
	var xs []uint32
	for _, n := range got.Nodes {
		xs = append(xs, n.X)
	}
	want := []uint32{2, 4, 5, 1, 3}
	for i := range want {
		if xs[i] != want[i] {
			t.Fatalf("ordre des nœuds %v, attendu %v (en service d'abord)", xs, want)
		}
	}
}
