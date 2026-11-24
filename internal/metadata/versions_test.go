package metadata

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestVersions(t *testing.T) {
	s, clock := openStore(t)
	addNodes(t, s, 5)
	alice, bob := newUser(t, s, "alice"), newUser(t, s, "bob")

	// Pas de nouvelle version d'un fichier non confirmé.
	createFile(t, s, "f1", alice, 100)
	if _, err := s.CreateVersion("f1", bob, 200); !errors.Is(err, ErrConflict) {
		t.Fatalf("version d'un dépôt non confirmé : %v", err)
	}
	mustNil(t, s.ConfirmUpload("f1", 1, alice, newManifest(1, 100)))

	clock.advance(time.Minute)
	v, err := s.CreateVersion("f1", bob, 200)
	if err != nil || v != 2 {
		t.Fatalf("CreateVersion = %d, %v", v, err)
	}
	// Tant qu'elle n'est pas confirmée, la version 1 reste la version actuelle.
	if f, _ := s.File("f1"); f.CurrentVersion != 1 || f.Size != 100 {
		t.Fatalf("version actuelle avant confirmation : %+v", f)
	}
	if err := s.ConfirmUpload("f1", 2, alice, newManifest(2, 200)); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("confirmation par un autre que l'auteur : %v", err)
	}
	mustNil(t, s.ConfirmUpload("f1", 2, bob, newManifest(2, 200)))
	if f, _ := s.File("f1"); f.CurrentVersion != 2 || f.Size != 200 {
		t.Fatalf("version actuelle après confirmation : %+v", f)
	}

	m, info, err := s.Manifest("f1", 0)
	if err != nil || m.BlockCount != 2 || info.Number != 2 || info.Author != "bob" {
		t.Fatalf("manifeste actuel : %+v %+v %v", m, info, err)
	}
	m, info, err = s.Manifest("f1", 1)
	if err != nil || m.BlockCount != 1 || info.Author != "alice" {
		t.Fatalf("manifeste de la version 1 : %+v %+v %v", m, info, err)
	}
	versions, err := s.Versions("f1")
	if err != nil || len(versions) != 2 {
		t.Fatalf("Versions : %+v, %v", versions, err)
	}

	// Une version en attente bloque les renouvellements, et un renouvellement bloque les
	// nouvelles versions.
	if _, err := s.CreateVersion("f1", alice, 300); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginEpoch(); !errors.Is(err, ErrConflict) {
		t.Fatalf("renouvellement avec une version en attente : %v", err)
	}
	clock.advance(2 * time.Hour)
	if n, err := s.DeleteStalePending(clock.now().Add(-time.Hour)); err != nil || n != 1 {
		t.Fatalf("DeleteStalePending = %d, %v", n, err)
	}
	if _, err := s.BeginEpoch(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateVersion("f1", alice, 300); !errors.Is(err, ErrConflict) {
		t.Fatalf("nouvelle version pendant un renouvellement : %v", err)
	}
}

func TestTransferAndDelete(t *testing.T) {
	s, _ := openStore(t)
	addNodes(t, s, 5)
	alice, bob := newUser(t, s, "alice"), newUser(t, s, "bob")
	readyFile(t, s, "f1", alice)
	mustNil(t, s.PutGrant("f1", bob, []byte("g"), []byte("n")))
	mustNil(t, s.PutRevocation("f1", make([]byte, 32), 10))

	mustNil(t, s.TransferFile("f1", bob, 1234, []byte("nom pour bob")))
	f, _ := s.File("f1")
	if f.OwnerID != bob || string(f.Name) != "nom pour bob" {
		t.Fatalf("après transfert : %+v", f)
	}
	if _, err := s.Grant("f1", bob); !errors.Is(err, ErrNotFound) {
		t.Fatal("le nouveau propriétaire garde un partage inutile")
	}
	prev, err := s.PreviousOwners("f1")
	u, _ := s.UserByID(alice)
	if err != nil || len(prev) != 1 || string(prev[0].PublicKey) != string(u.PublicKey) || prev[0].Until != 1234 {
		t.Fatalf("anciens propriétaires : %+v, %v", prev, err)
	}

	mustNil(t, s.DeleteFile("f1"))
	if _, err := s.File("f1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("fichier encore présent")
	}
	for _, table := range []string{"versions", "version_blocks", "grants", "revocations", "previous_owners", "file_nodes"} {
		var n int
		s.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n)
		if n != 0 {
			t.Errorf("%d ligne(s) restent dans %s", n, table)
		}
	}
}

func TestGroupsStore(t *testing.T) {
	s, _ := openStore(t)
	alice, bob, carol := newUser(t, s, "alice"), newUser(t, s, "bob"), newUser(t, s, "carol")
	mustNil(t, s.CreateGroup(alice, "equipe"))
	mustNil(t, s.CreateGroup(alice, "vide"))
	if err := s.CreateGroup(alice, "equipe"); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("groupe en double : %v", err)
	}
	mustNil(t, s.CreateGroup(bob, "equipe")) // même nom, autre propriétaire
	mustNil(t, s.AddGroupMember(alice, "equipe", bob))
	mustNil(t, s.AddGroupMember(alice, "equipe", carol))
	mustNil(t, s.AddGroupMember(alice, "equipe", carol)) // sans effet
	mustNil(t, s.RemoveGroupMember(alice, "equipe", carol))
	if err := s.RemoveGroupMember(alice, "equipe", carol); !errors.Is(err, ErrNotFound) {
		t.Fatalf("retrait d'un non-membre : %v", err)
	}
	groups, err := s.Groups(alice)
	if err != nil || len(groups) != 2 || groups[0].Name != "equipe" || len(groups[0].Members) != 1 ||
		groups[0].Members[0].Username != "bob" || len(groups[1].Members) != 0 {
		t.Fatalf("Groups : %+v, %v", groups, err)
	}
	mustNil(t, s.DeleteGroup(alice, "equipe"))
	if err := s.AddGroupMember(alice, "equipe", bob); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ajout à un groupe supprimé : %v", err)
	}
}

// TestMigrationFromV2 vérifie qu'un fichier déposé avec le schéma 2 devient la version 1
// de ce fichier, avec son manifeste et ses partages.
func TestMigrationFromV2(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "coordinator.db")+"?_pragma=foreign_keys(ON)")
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{schemaV1, schemaV2,
		`INSERT INTO epochs (number, state, started_at) VALUES (1, 'committed', 0)`,
		`INSERT INTO users (id, username, public_key, created_at) VALUES (1, 'alice', zeroblob(32), 0)`,
		`INSERT INTO users (id, username, public_key, created_at) VALUES (2, 'bob', randomblob(32), 0)`,
		`INSERT INTO files (file_id, owner_id, name, size, t, n, epoch, status, created_at, confirmed_at)
			VALUES ('f1', 1, x'00', 65536, 3, 5, 1, 'ready', 10, 20)`,
		`INSERT INTO manifests (file_id, block_count, nonce_prefix, size) VALUES ('f1', 1, x'', 65536)`,
		`INSERT INTO blocks (file_id, idx, sha256) VALUES ('f1', 0, zeroblob(32))`,
		`INSERT INTO grants (file_id, grantee_id, signed_grant, encrypted_name, created_at) VALUES ('f1', 2, x'01', x'02', 30)`,
		`PRAGMA user_version = 2`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	s, _ := openStoreIn(t, dir)
	m, v, err := s.Manifest("f1", 0)
	if err != nil || m.BlockCount != 1 || len(m.BlockHashes) != 1 || v.Number != 1 || v.Author != "alice" {
		t.Fatalf("manifeste migré : %+v %+v %v", m, v, err)
	}
	if f, _ := s.File("f1"); f.CurrentVersion != 1 {
		t.Fatalf("version actuelle : %d", f.CurrentVersion)
	}
	if shared, err := s.FilesSharedWith(2); err != nil || len(shared) != 1 {
		t.Fatalf("partage perdu : %+v, %v", shared, err)
	}
}
