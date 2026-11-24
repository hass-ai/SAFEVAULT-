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

// person est un utilisateur de test inscrit et connecté.
type person struct {
	key ed25519.PrivateKey
	pub ed25519.PublicKey
	ctx context.Context
}

func newPerson(t *testing.T, c *testCoordinator, name string) person {
	t.Helper()
	key := registerUser(t, c, name)
	ctx, _ := loginToken(t, c, name, key)
	return person{key, key.Public().(ed25519.PublicKey), ctx}
}

func share(c *testCoordinator, from person, grantee string, g *pb.Grant) error {
	_, err := c.coord.ShareFile(from.ctx, &pb.ShareFileRequest{Grantee: grantee, Grant: g, EncryptedName: []byte("nom pour " + grantee)})
	return err
}

func revoke(c *testCoordinator, from person, fileID, grantee string, granteeKey ed25519.PublicKey, at time.Time, authority *pb.Grant) error {
	r := access.NewRevocation(from.key, fileID, granteeKey, at, authority)
	_, err := c.coord.RevokeShare(from.ctx, &pb.RevokeShareRequest{FileId: fileID, Grantee: grantee, Revocation: r})
	return err
}

func TestShareFile(t *testing.T) {
	c := startCoordinator(t)
	c.allNodesUp(t)
	alice, bob, charlie := newPerson(t, c, "alice"), newPerson(t, c, "bob"), newPerson(t, c, "charlie")
	fileID := readyFileFor(t, c, alice.ctx)

	// La clé de bob donnée par le coordinateur est bien la sienne.
	key, err := c.coord.GetUserKey(alice.ctx, &pb.GetUserKeyRequest{Username: "bob"})
	if err != nil || string(key.PublicKey) != string(bob.pub) {
		t.Fatalf("clé de bob : %v", err)
	}

	// Avant le partage, bob ne voit pas le fichier.
	_, err = c.coord.GetFile(bob.ctx, &pb.GetFileRequest{FileId: fileID})
	wantCode(t, err, codes.NotFound, "GetFile de bob avant partage")

	now := time.Now()
	grant := access.NewGrant(alice.key, fileID, bob.pub, access.Read, now, now.Add(time.Hour), nil)
	if err := share(c, alice, "bob", grant); err != nil {
		t.Fatal(err)
	}

	// Bob voit le fichier, avec le nom chiffré pour lui, ses droits, et reçoit l'autorisation.
	list, err := c.coord.ListFiles(bob.ctx, &pb.ListFilesRequest{})
	if err != nil || len(list.Files) != 1 {
		t.Fatalf("fichiers de bob : %+v, %v", list, err)
	}
	f := list.Files[0]
	if f.FileId != fileID || !f.Shared || f.Owner != "alice" || string(f.EncryptedName) != "nom pour bob" ||
		f.Rights != access.Read || f.ExpiresAt != grant.ExpiresAt || f.Version != 1 {
		t.Fatalf("fichier partagé vu par bob : %+v", f)
	}
	got, err := c.coord.GetFile(bob.ctx, &pb.GetFileRequest{FileId: fileID})
	if err != nil || got.Grant == nil || string(got.Grant.Signature) != string(grant.Signature) || got.Rights != access.Read {
		t.Fatalf("GetFile de bob : %+v, %v", got, err)
	}
	// Le propriétaire, lui, ne reçoit pas d'autorisation et a tous les droits.
	if own, _ := c.coord.GetFile(alice.ctx, &pb.GetFileRequest{FileId: fileID}); own.Grant != nil || own.Rights != access.All {
		t.Fatal("le propriétaire doit avoir tous les droits, sans autorisation")
	}
	_, err = c.coord.GetFile(charlie.ctx, &pb.GetFileRequest{FileId: fileID})
	wantCode(t, err, codes.NotFound, "GetFile de charlie")

	// Bob (lecture seule) ne peut ni voir les accès, ni retirer, ni supprimer, ni renommer.
	_, err = c.coord.ListAccess(bob.ctx, &pb.ListAccessRequest{FileId: fileID})
	wantCode(t, err, codes.PermissionDenied, "ListAccess par un lecteur")
	_, err = c.coord.RemoveFile(bob.ctx, &pb.RemoveFileRequest{FileId: fileID})
	wantCode(t, err, codes.PermissionDenied, "RemoveFile par un lecteur")
	_, err = c.coord.RenameFile(bob.ctx, &pb.RenameFileRequest{FileId: fileID})
	wantCode(t, err, codes.PermissionDenied, "RenameFile par un lecteur")
	_, err = c.coord.CreateVersion(bob.ctx, &pb.CreateVersionRequest{FileId: fileID, Size: 100})
	wantCode(t, err, codes.PermissionDenied, "CreateVersion par un lecteur")

	// Alice retire l'accès : bob ne voit plus le fichier.
	if err := revoke(c, alice, fileID, "bob", bob.pub, time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	_, err = c.coord.GetFile(bob.ctx, &pb.GetFileRequest{FileId: fileID})
	wantCode(t, err, codes.NotFound, "GetFile de bob après retrait")
	if list, _ := c.coord.ListFiles(bob.ctx, &pb.ListFilesRequest{}); len(list.Files) != 0 {
		t.Fatalf("bob voit encore %d fichier(s)", len(list.Files))
	}
	// L'ancienne autorisation, renvoyée telle quelle, est refusée.
	wantCode(t, share(c, alice, "bob", grant), codes.InvalidArgument, "autorisation antérieure au retrait")
}

func TestShareFileRefused(t *testing.T) {
	c := startCoordinator(t)
	c.allNodesUp(t)
	alice, bob := newPerson(t, c, "alice"), newPerson(t, c, "bob")
	newPerson(t, c, "charlie")
	fileID := readyFileFor(t, c, alice.ctx)
	now := time.Now()
	grant := func(from person, file string, to ed25519.PublicKey, at time.Time) *pb.Grant {
		return access.NewGrant(from.key, file, to, access.Read, at, at.Add(time.Hour), nil)
	}

	// Bob ne peut pas partager le fichier d'alice avec une autorisation qu'il signe.
	wantCode(t, share(c, bob, "bob", grant(bob, fileID, bob.pub, now)), codes.PermissionDenied, "partage par bob")
	// Bob envoie une autorisation signée par alice : ce n'est pas lui qui l'a signée.
	wantCode(t, share(c, bob, "bob", grant(alice, fileID, bob.pub, now)), codes.InvalidArgument, "émetteur ≠ appelant")
	// L'autorisation est faite pour bob mais annoncée pour charlie.
	wantCode(t, share(c, alice, "charlie", grant(alice, fileID, bob.pub, now)), codes.InvalidArgument, "destinataire incohérent")
	// Autorisation expirée.
	wantCode(t, share(c, alice, "bob", grant(alice, fileID, bob.pub, now.Add(-2*time.Hour))), codes.InvalidArgument, "expirée")
	// Destinataire inconnu, fichier inconnu.
	wantCode(t, share(c, alice, "inconnu", grant(alice, fileID, bob.pub, now)), codes.NotFound, "destinataire inconnu")
	wantCode(t, share(c, alice, "bob", grant(alice, "absent", bob.pub, now)), codes.NotFound, "fichier inconnu")
	// Partage avec le propriétaire.
	wantCode(t, share(c, alice, "alice", grant(alice, fileID, alice.pub, now)), codes.InvalidArgument, "partage avec soi-même")

	// Bob ne peut pas retirer un accès au fichier d'alice.
	wantCode(t, revoke(c, bob, fileID, "bob", bob.pub, now, nil), codes.NotFound, "retrait par bob")

	_, err := c.coord.GetUserKey(alice.ctx, &pb.GetUserKeyRequest{Username: "inconnu"})
	wantCode(t, err, codes.NotFound, "clé d'un inconnu")
}

func TestVersionsByWriter(t *testing.T) {
	c := startCoordinator(t)
	c.allNodesUp(t)
	alice, bob := newPerson(t, c, "alice"), newPerson(t, c, "bob")
	fileID := readyFileFor(t, c, alice.ctx)
	writer := access.NewGrant(alice.key, fileID, bob.pub, access.Read|access.Write, time.Now(), time.Time{}, nil)
	if err := share(c, alice, "bob", writer); err != nil {
		t.Fatal(err)
	}

	v, err := c.coord.CreateVersion(bob.ctx, &pb.CreateVersionRequest{FileId: fileID, Size: 200})
	if err != nil || v.Version != 2 || len(v.Nodes) != 5 {
		t.Fatalf("CreateVersion : %+v, %v", v, err)
	}
	// Seul l'auteur confirme sa version.
	_, err = c.coord.ConfirmUpload(alice.ctx, &pb.ConfirmUploadRequest{FileId: fileID, Version: 2, Manifest: manifestFor(2, 200)})
	wantCode(t, err, codes.NotFound, "confirmation par un autre que l'auteur")
	_, err = c.coord.ConfirmUpload(bob.ctx, &pb.ConfirmUploadRequest{FileId: fileID, Version: 2, Manifest: manifestFor(2, 200)})
	if err != nil {
		t.Fatal(err)
	}

	// La version 2 est la version actuelle ; la version 1 reste lisible.
	cur, err := c.coord.GetFile(alice.ctx, &pb.GetFileRequest{FileId: fileID})
	if err != nil || cur.Version != 2 || cur.CurrentVersion != 2 || cur.Manifest.BlockCount != 2 {
		t.Fatalf("version actuelle : %+v, %v", cur, err)
	}
	old, err := c.coord.GetFile(bob.ctx, &pb.GetFileRequest{FileId: fileID, Version: 1})
	if err != nil || old.Version != 1 || old.Manifest.BlockCount != 1 {
		t.Fatalf("version 1 : %+v, %v", old, err)
	}
	_, err = c.coord.GetFile(bob.ctx, &pb.GetFileRequest{FileId: fileID, Version: 9})
	wantCode(t, err, codes.NotFound, "version inexistante")

	versions, err := c.coord.ListVersions(bob.ctx, &pb.ListVersionsRequest{FileId: fileID})
	if err != nil || len(versions.Versions) != 2 || versions.Versions[1].Author != "bob" || versions.Versions[0].Author != "alice" {
		t.Fatalf("ListVersions : %+v, %v", versions, err)
	}
}

func TestDelegationAndCoAdmin(t *testing.T) {
	c := startCoordinator(t)
	c.allNodesUp(t)
	alice, bob, carol, dave := newPerson(t, c, "alice"), newPerson(t, c, "bob"), newPerson(t, c, "carol"), newPerson(t, c, "dave")
	fileID := readyFileFor(t, c, alice.ctx)
	now := time.Now()

	// bob peut repartager en lecture ; dave est co-administrateur.
	bobGrant := access.NewGrant(alice.key, fileID, bob.pub, access.Read|access.Share, now, time.Time{}, nil)
	daveGrant := access.NewGrant(alice.key, fileID, dave.pub, access.Read|access.Manage, now, time.Time{}, nil)
	if err := share(c, alice, "bob", bobGrant); err != nil {
		t.Fatal(err)
	}
	if err := share(c, alice, "dave", daveGrant); err != nil {
		t.Fatal(err)
	}

	// bob ne peut pas donner plus que ses droits...
	tooMuch := access.NewGrant(bob.key, fileID, carol.pub, access.Read|access.Write, now, time.Time{}, bobGrant)
	wantCode(t, share(c, bob, "carol", tooMuch), codes.PermissionDenied, "délégation au-delà des droits")
	// ... mais peut partager en lecture.
	carolGrant := access.NewGrant(bob.key, fileID, carol.pub, access.Read, now, time.Time{}, bobGrant)
	if err := share(c, bob, "carol", carolGrant); err != nil {
		t.Fatal(err)
	}

	entries, err := c.coord.ListAccess(dave.ctx, &pb.ListAccessRequest{FileId: fileID})
	if err != nil || len(entries.Entries) != 4 || !entries.Entries[0].Owner || entries.Entries[0].Username != "alice" {
		t.Fatalf("ListAccess : %+v, %v", entries, err)
	}
	for _, e := range entries.Entries {
		if e.Username == "carol" && e.GrantedBy != "bob" {
			t.Fatalf("carol a reçu son accès de %q, attendu bob", e.GrantedBy)
		}
	}

	// bob (sans m) ne peut pas retirer d'accès ; dave (m) peut retirer celui de bob, et
	// l'accès de carol, qui en découle, tombe avec.
	wantCode(t, revoke(c, bob, fileID, "carol", carol.pub, time.Now(), bobGrant), codes.PermissionDenied, "retrait par bob")
	if err := revoke(c, dave, fileID, "bob", bob.pub, time.Now(), daveGrant); err != nil {
		t.Fatal(err)
	}
	for _, p := range []person{bob, carol} {
		if list, _ := c.coord.ListFiles(p.ctx, &pb.ListFilesRequest{}); len(list.Files) != 0 {
			t.Fatalf("le fichier reste visible après le retrait en cascade : %+v", list.Files)
		}
	}

	// dave renomme pour tout le monde, puis supprime... non : il n'a pas le droit d.
	_, err = c.coord.RenameFile(dave.ctx, &pb.RenameFileRequest{FileId: fileID, Names: []*pb.UserName{
		{Username: "alice", EncryptedName: []byte("nouveau pour alice")},
		{Username: "dave", EncryptedName: []byte("nouveau pour dave")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	list, _ := c.coord.ListFiles(alice.ctx, &pb.ListFilesRequest{})
	if string(list.Files[0].EncryptedName) != "nouveau pour alice" {
		t.Fatalf("nom non remplacé : %q", list.Files[0].EncryptedName)
	}
	_, err = c.coord.RemoveFile(dave.ctx, &pb.RemoveFileRequest{FileId: fileID})
	wantCode(t, err, codes.PermissionDenied, "suppression sans le droit d")
}

func TestRemoveAndTransfer(t *testing.T) {
	c := startCoordinator(t)
	c.allNodesUp(t)
	alice, bob, carol := newPerson(t, c, "alice"), newPerson(t, c, "bob"), newPerson(t, c, "carol")
	fileID := readyFileFor(t, c, alice.ctx)
	now := time.Now()

	// Transfert : signé par alice pour bob.
	tr := access.NewTransfer(alice.key, fileID, bob.pub, now)
	_, err := c.coord.TransferFile(carol.ctx, &pb.TransferFileRequest{NewOwner: "carol", Transfer: tr, EncryptedName: []byte("n")})
	wantCode(t, err, codes.NotFound, "transfert par un tiers")
	_, err = c.coord.TransferFile(alice.ctx, &pb.TransferFileRequest{NewOwner: "carol", Transfer: tr, EncryptedName: []byte("n")})
	wantCode(t, err, codes.InvalidArgument, "transfert annoncé pour un autre")

	// alice garde un accès en lecture, signé avant le transfert.
	keep := access.NewGrant(alice.key, fileID, alice.pub, access.Read|access.Write, now, time.Time{}, nil)
	_, err = c.coord.TransferFile(alice.ctx, &pb.TransferFileRequest{NewOwner: "bob", Transfer: tr, EncryptedName: []byte("nom pour bob")})
	if err != nil {
		t.Fatal(err)
	}
	if err := share(c, alice, "alice", keep); err != nil {
		t.Fatalf("accès conservé par l'ancienne propriétaire refusé : %v", err)
	}
	got, err := c.coord.GetFile(alice.ctx, &pb.GetFileRequest{FileId: fileID})
	if err != nil || got.Rights != access.Read|access.Write {
		t.Fatalf("droits d'alice après transfert : %+v, %v", got, err)
	}
	own, err := c.coord.GetFile(bob.ctx, &pb.GetFileRequest{FileId: fileID})
	if err != nil || own.Rights != access.All || own.Grant != nil {
		t.Fatalf("bob doit être propriétaire : %+v, %v", own, err)
	}
	// alice ne peut plus partager ni supprimer.
	late := access.NewGrant(alice.key, fileID, carol.pub, access.Read, time.Now().Add(time.Second), time.Time{}, nil)
	wantCode(t, share(c, alice, "carol", late), codes.PermissionDenied, "partage par l'ancienne propriétaire")
	_, err = c.coord.RemoveFile(alice.ctx, &pb.RemoveFileRequest{FileId: fileID})
	wantCode(t, err, codes.PermissionDenied, "suppression par l'ancienne propriétaire")

	// bob supprime : plus personne ne voit le fichier.
	if _, err := c.coord.RemoveFile(bob.ctx, &pb.RemoveFileRequest{FileId: fileID}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []person{alice, bob} {
		_, err := c.coord.GetFile(p.ctx, &pb.GetFileRequest{FileId: fileID})
		wantCode(t, err, codes.NotFound, "GetFile après suppression")
	}
}

func TestGroups(t *testing.T) {
	c := startCoordinator(t)
	alice, bob := newPerson(t, c, "alice"), newPerson(t, c, "bob")
	newPerson(t, c, "carol")

	if _, err := c.coord.CreateGroup(alice.ctx, &pb.CreateGroupRequest{Name: "projet"}); err != nil {
		t.Fatal(err)
	}
	_, err := c.coord.CreateGroup(alice.ctx, &pb.CreateGroupRequest{Name: "projet"})
	wantCode(t, err, codes.AlreadyExists, "groupe en double")
	_, err = c.coord.CreateGroup(alice.ctx, &pb.CreateGroupRequest{Name: "nom invalide !"})
	wantCode(t, err, codes.InvalidArgument, "nom invalide")

	for _, u := range []string{"bob", "carol"} {
		if _, err := c.coord.AddGroupMember(alice.ctx, &pb.GroupMemberRequest{Group: "projet", Username: u}); err != nil {
			t.Fatal(err)
		}
	}
	_, err = c.coord.AddGroupMember(alice.ctx, &pb.GroupMemberRequest{Group: "projet", Username: "inconnu"})
	wantCode(t, err, codes.NotFound, "membre inconnu")
	// Les groupes sont propres à chacun : bob ne touche pas à celui d'alice.
	_, err = c.coord.AddGroupMember(bob.ctx, &pb.GroupMemberRequest{Group: "projet", Username: "bob"})
	wantCode(t, err, codes.NotFound, "groupe d'un autre")

	if _, err := c.coord.RemoveGroupMember(alice.ctx, &pb.GroupMemberRequest{Group: "projet", Username: "carol"}); err != nil {
		t.Fatal(err)
	}
	groups, err := c.coord.ListGroups(alice.ctx, &pb.ListGroupsRequest{})
	if err != nil || len(groups.Groups) != 1 || len(groups.Groups[0].Members) != 1 ||
		groups.Groups[0].Members[0].Username != "bob" || string(groups.Groups[0].Members[0].PublicKey) != string(bob.pub) {
		t.Fatalf("ListGroups : %+v, %v", groups, err)
	}
	if other, _ := c.coord.ListGroups(bob.ctx, &pb.ListGroupsRequest{}); len(other.Groups) != 0 {
		t.Fatal("bob voit les groupes d'alice")
	}
	if _, err := c.coord.DeleteGroup(alice.ctx, &pb.DeleteGroupRequest{Name: "projet"}); err != nil {
		t.Fatal(err)
	}
	_, err = c.coord.DeleteGroup(alice.ctx, &pb.DeleteGroupRequest{Name: "projet"})
	wantCode(t, err, codes.NotFound, "groupe déjà supprimé")
}
