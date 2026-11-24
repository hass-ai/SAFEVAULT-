package metadata

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// readyFile crée et confirme le fichier id pour owner.
func readyFile(t *testing.T, s *Store, id string, owner int64) {
	t.Helper()
	createFile(t, s, id, owner, 100)
	if err := s.ConfirmUpload(id, owner, newManifest(1, 100)); err != nil {
		t.Fatal(err)
	}
}

func TestGrants(t *testing.T) {
	s, _ := openStore(t)
	addNodes(t, s, 5)
	alice, bob, charlie := newUser(t, s, "alice"), newUser(t, s, "bob"), newUser(t, s, "charlie")
	readyFile(t, s, "f1", alice)

	if err := s.PutGrant("f1", alice, bob, []byte("autorisation"), []byte("nom pour bob")); err != nil {
		t.Fatal(err)
	}
	g, err := s.Grant("f1", bob)
	if err != nil || string(g) != "autorisation" {
		t.Fatalf("autorisation %q, erreur %v", g, err)
	}
	if _, err := s.Grant("f1", charlie); !errors.Is(err, ErrNotFound) {
		t.Fatalf("charlie a une autorisation : %v", err)
	}

	shared, err := s.FilesSharedWith(bob)
	if err != nil || len(shared) != 1 {
		t.Fatalf("fichiers partagés avec bob : %+v, erreur %v", shared, err)
	}
	if shared[0].ID != "f1" || shared[0].Owner != "alice" || string(shared[0].EncryptedName) != "nom pour bob" {
		t.Fatalf("partage inattendu %+v", shared[0])
	}

	// Un nouveau partage avec bob remplace l'ancien.
	if err := s.PutGrant("f1", alice, bob, []byte("autorisation 2"), []byte("nom")); err != nil {
		t.Fatal(err)
	}
	if g, _ := s.Grant("f1", bob); string(g) != "autorisation 2" {
		t.Fatalf("autorisation non remplacée : %q", g)
	}

	// Seul le propriétaire peut retirer le partage.
	if err := s.DeleteGrant("f1", charlie, bob); !errors.Is(err, ErrNotFound) {
		t.Fatalf("charlie retire un partage d'alice : %v", err)
	}
	if err := s.DeleteGrant("f1", alice, bob); err != nil {
		t.Fatal(err)
	}
	if shared, _ := s.FilesSharedWith(bob); len(shared) != 0 {
		t.Fatalf("partage toujours visible après retrait : %+v", shared)
	}
	if err := s.DeleteGrant("f1", alice, bob); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second retrait : %v", err)
	}
}

func TestPutGrantRules(t *testing.T) {
	s, _ := openStore(t)
	addNodes(t, s, 5)
	alice, bob := newUser(t, s, "alice"), newUser(t, s, "bob")
	readyFile(t, s, "f1", alice)
	createFile(t, s, "pending", alice, 100)

	cases := map[string]struct {
		fileID         string
		owner, grantee int64
		want           error
	}{
		"fichier inconnu":       {"absent", alice, bob, ErrNotFound},
		"pas le propriétaire":   {"f1", bob, alice, ErrNotOwner},
		"dépôt non confirmé":    {"pending", alice, bob, ErrConflict},
		"partage avec soi-même": {"f1", alice, alice, ErrInvalidArgument},
	}
	for name, c := range cases {
		if err := s.PutGrant(c.fileID, c.owner, c.grantee, []byte("g"), []byte("n")); !errors.Is(err, c.want) {
			t.Errorf("%s : erreur %v, attendue %v", name, err, c.want)
		}
	}
}

func TestUserByID(t *testing.T) {
	s, _ := openStore(t)
	alice := newUser(t, s, "alice")
	u, err := s.UserByID(alice)
	if err != nil || u.Username != "alice" || len(u.PublicKey) != 32 {
		t.Fatalf("utilisateur %+v, erreur %v", u, err)
	}
	if _, err := s.UserByID(999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("erreur %v, attendue ErrNotFound", err)
	}
}

// TestMigrationFromV1 vérifie qu'une base créée par la version précédente du coordinateur
// est mise à jour sans perdre ses données.
func TestMigrationFromV1(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "coordinator.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{schemaV1,
		`INSERT INTO epochs (number, state, started_at) VALUES (1, 'committed', 0)`,
		`INSERT INTO users (id, username, public_key, created_at) VALUES (1, 'alice', zeroblob(32), 0)`,
		`PRAGMA user_version = 1`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	s, _ := openStoreIn(t, dir)
	var version int
	s.db.QueryRow(`PRAGMA user_version`).Scan(&version)
	if version != schemaVersion {
		t.Fatalf("version %d après migration, attendue %d", version, schemaVersion)
	}
	if u, err := s.UserByName("alice"); err != nil || u.ID != 1 {
		t.Fatalf("utilisateur perdu pendant la migration : %+v, %v", u, err)
	}
	if _, err := s.FilesSharedWith(1); err != nil {
		t.Fatalf("table des partages absente : %v", err)
	}
}
