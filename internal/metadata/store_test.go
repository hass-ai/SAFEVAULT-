package metadata

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testClock est une horloge réglable pour tester les expirations.
type testClock struct{ t time.Time }

func (c *testClock) now() time.Time               { return c.t }
func (c *testClock) advance(d time.Duration)      { c.t = c.t.Add(d) }
func newTestClock() *testClock                    { return &testClock{t: time.Unix(1_800_000_000, 0)} }
func openStore(t *testing.T) (*Store, *testClock) { return openStoreIn(t, t.TempDir()) }

func openStoreIn(t *testing.T, dir string) (*Store, *testClock) {
	t.Helper()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	clock := newTestClock()
	s.now = clock.now
	return s, clock
}

func newPublicKey(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func newUser(t *testing.T, s *Store, name string) int64 {
	t.Helper()
	id, err := s.CreateUser(name, newPublicKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// addNodes enregistre les nœuds 1..n.
func addNodes(t *testing.T, s *Store, n uint32) []uint32 {
	t.Helper()
	var xs []uint32
	for x := uint32(1); x <= n; x++ {
		if err := s.UpsertNode(x, "node-"+string(rune('0'+x))+":7444"); err != nil {
			t.Fatal(err)
		}
		xs = append(xs, x)
	}
	return xs
}

func newManifest(blocks int, size uint64) Manifest {
	m := Manifest{BlockCount: uint32(blocks), NoncePrefix: []byte("prefixe"), Size: size}
	for i := 0; i < blocks; i++ {
		h := sha256.Sum256([]byte{byte(i)})
		m.BlockHashes = append(m.BlockHashes, h[:])
	}
	return m
}

// ---------- Schéma ----------

func TestOpenCreatesSchemaAndFirstEpoch(t *testing.T) {
	dir := t.TempDir()
	s, _ := openStoreIn(t, dir)

	if _, err := os.Stat(filepath.Join(dir, DBFile)); err != nil {
		t.Fatalf("fichier de base absent : %v", err)
	}
	epoch, err := s.CurrentEpoch()
	if err != nil {
		t.Fatal(err)
	}
	if epoch != 1 {
		t.Fatalf("époque initiale %d, attendue 1", epoch)
	}
}

func TestReopenKeepsData(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser("alice", newPublicKey(t)); err != nil {
		t.Fatal(err)
	}
	s.Close()

	// La deuxième ouverture ne doit ni échouer ni recréer le schéma (ni une deuxième époque 1).
	s2, _ := openStoreIn(t, dir)
	if _, err := s2.UserByName("alice"); err != nil {
		t.Fatalf("utilisateur perdu après réouverture : %v", err)
	}
	var epochs int
	if err := s2.db.QueryRow(`SELECT COUNT(*) FROM epochs`).Scan(&epochs); err != nil {
		t.Fatal(err)
	}
	if epochs != 1 {
		t.Fatalf("%d époques après réouverture, attendue 1", epochs)
	}
}

func TestOpenRefusesNewerSchema(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	s.Close()

	if s, err := Open(dir); err == nil {
		s.Close()
		t.Fatal("une base d'une version future doit être refusée")
	}
}

func TestForeignKeysEnforced(t *testing.T) {
	s, _ := openStore(t)
	_, err := s.db.Exec(`INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, 42, 0, 0)`,
		make([]byte, 32))
	if err == nil {
		t.Fatal("une session d'un utilisateur inexistant doit être refusée")
	}
}

// TestNoSecretColumns vérifie la garantie G3 au niveau du schéma : aucune colonne
// ne porte un nom de clé, de part, de secret ou de jeton en clair.
func TestNoSecretColumns(t *testing.T) {
	s, _ := openStore(t)
	allowed := map[string]bool{"public_key": true, "token_hash": true}
	forbidden := []string{"key", "share", "secret", "token", "password", "plain"}

	rows, err := s.db.Query(`SELECT m.name, p.name FROM sqlite_master m, pragma_table_info(m.name) p
		WHERE m.type = 'table'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns := 0
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil {
			t.Fatal(err)
		}
		columns++
		if allowed[column] {
			continue
		}
		for _, word := range forbidden {
			if strings.Contains(strings.ToLower(column), word) {
				t.Errorf("colonne suspecte %s.%s", table, column)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if columns == 0 {
		t.Fatal("aucune colonne lue")
	}
}

// ---------- Utilisateurs ----------

func TestCreateUserAndLookup(t *testing.T) {
	s, _ := openStore(t)
	pub := newPublicKey(t)
	id, err := s.CreateUser("alice", pub)
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.UserByName("alice")
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != id || u.Username != "alice" || !bytes.Equal(u.PublicKey, pub) {
		t.Fatalf("utilisateur lu %+v", u)
	}
	if _, err := s.UserByName("bob"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("utilisateur inconnu : %v, attendu ErrNotFound", err)
	}
}

func TestCreateUserRejectsDuplicates(t *testing.T) {
	s, _ := openStore(t)
	pub := newPublicKey(t)
	if _, err := s.CreateUser("alice", pub); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser("alice", newPublicKey(t)); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("même nom : %v, attendu ErrAlreadyExists", err)
	}
	if _, err := s.CreateUser("bob", pub); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("même clé : %v, attendu ErrAlreadyExists", err)
	}
}

func TestCreateUserRejectsInvalidInput(t *testing.T) {
	s, _ := openStore(t)
	if _, err := s.CreateUser("", newPublicKey(t)); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("nom vide : %v", err)
	}
	if _, err := s.CreateUser("alice", []byte("courte")); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("clé de mauvaise taille : %v", err)
	}
}

// ---------- Défis ----------

func TestChallengeSingleUse(t *testing.T) {
	s, clock := openStore(t)
	alice := newUser(t, s, "alice")
	challenge := []byte("defi-aleatoire-de-32-octets-.....")

	if err := s.PutChallenge(alice, challenge, clock.now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeChallenge(alice, challenge); err != nil {
		t.Fatalf("premier usage : %v", err)
	}
	if err := s.ConsumeChallenge(alice, challenge); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deuxième usage : %v, attendu ErrNotFound", err)
	}
}

func TestChallengeExpired(t *testing.T) {
	s, clock := openStore(t)
	alice := newUser(t, s, "alice")
	challenge := []byte("defi")

	if err := s.PutChallenge(alice, challenge, clock.now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	clock.advance(time.Minute)
	if err := s.ConsumeChallenge(alice, challenge); !errors.Is(err, ErrExpired) {
		t.Fatalf("défi expiré : %v, attendu ErrExpired", err)
	}
	// Même expiré, le défi a été consommé.
	if err := s.ConsumeChallenge(alice, challenge); !errors.Is(err, ErrNotFound) {
		t.Fatalf("défi expiré réutilisé : %v, attendu ErrNotFound", err)
	}
}

func TestChallengeBoundToUser(t *testing.T) {
	s, clock := openStore(t)
	alice := newUser(t, s, "alice")
	bob := newUser(t, s, "bob")
	challenge := []byte("defi")

	if err := s.PutChallenge(alice, challenge, clock.now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeChallenge(bob, challenge); !errors.Is(err, ErrNotFound) {
		t.Fatalf("défi d'alice utilisé par bob : %v, attendu ErrNotFound", err)
	}
}

func TestChallengeStoredHashed(t *testing.T) {
	s, clock := openStore(t)
	alice := newUser(t, s, "alice")
	challenge := []byte("defi-en-clair")
	if err := s.PutChallenge(alice, challenge, clock.now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	if err := s.db.QueryRow(`SELECT hash FROM challenges`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, challenge) || !bytes.Equal(stored, digest(challenge)) {
		t.Fatal("le défi doit être stocké sous forme d'empreinte SHA-256")
	}
}

// ---------- Sessions ----------

func TestSessionLifecycle(t *testing.T) {
	s, clock := openStore(t)
	alice := newUser(t, s, "alice")
	token := []byte("jeton-opaque")

	if err := s.PutSession(token, alice, clock.now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err := s.SessionUser(token)
	if err != nil || got != alice {
		t.Fatalf("SessionUser = %d, %v ; attendu %d", got, err, alice)
	}
	if _, err := s.SessionUser([]byte("autre-jeton")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("jeton inconnu : %v", err)
	}

	clock.advance(time.Hour)
	if _, err := s.SessionUser(token); !errors.Is(err, ErrExpired) {
		t.Fatalf("jeton expiré : %v, attendu ErrExpired", err)
	}
}

func TestDeleteSession(t *testing.T) {
	s, clock := openStore(t)
	alice := newUser(t, s, "alice")
	token := []byte("jeton")
	if err := s.PutSession(token, alice, clock.now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSession(token); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionUser(token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("jeton révoqué : %v, attendu ErrNotFound", err)
	}
}

func TestPurgeExpired(t *testing.T) {
	s, clock := openStore(t)
	alice := newUser(t, s, "alice")
	now := clock.now()
	mustNil(t, s.PutChallenge(alice, []byte("vieux-defi"), now.Add(time.Minute)))
	mustNil(t, s.PutChallenge(alice, []byte("defi-valide"), now.Add(time.Hour)))
	mustNil(t, s.PutSession([]byte("vieux-jeton"), alice, now.Add(time.Minute)))
	mustNil(t, s.PutSession([]byte("jeton-valide"), alice, now.Add(time.Hour)))

	clock.advance(2 * time.Minute)
	removed, err := s.PurgeExpired()
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Fatalf("%d lignes supprimées, attendu 2", removed)
	}
	if _, err := s.SessionUser([]byte("jeton-valide")); err != nil {
		t.Fatalf("jeton valide supprimé : %v", err)
	}
}

func mustNil(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// ---------- Nœuds et époques ----------

func TestNodes(t *testing.T) {
	s, clock := openStore(t)
	addNodes(t, s, 3)
	if err := s.UpsertNode(2, "nouvelle-adresse:7444"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeStatus(3, NodeUp, clock.now()); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeStatus(9, NodeUp, clock.now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("nœud inconnu : %v", err)
	}
	if err := s.SetNodeStatus(1, "bizarre", clock.now()); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("état invalide : %v", err)
	}

	nodes, err := s.Nodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 3 {
		t.Fatalf("%d nœuds, attendu 3", len(nodes))
	}
	if nodes[0].Status != NodeUnknown || !nodes[0].LastSeen.IsZero() {
		t.Fatalf("nœud 1 : %+v", nodes[0])
	}
	if nodes[1].Address != "nouvelle-adresse:7444" {
		t.Fatalf("adresse du nœud 2 : %q", nodes[1].Address)
	}
	if nodes[2].Status != NodeUp || !nodes[2].LastSeen.Equal(clock.now()) {
		t.Fatalf("nœud 3 : %+v", nodes[2])
	}
}

func TestOnlyOnePreparingEpoch(t *testing.T) {
	s, _ := openStore(t)
	mustNil(t, execErr(s, `INSERT INTO epochs (number, state, started_at) VALUES (2, 'preparing', 0)`))
	if err := execErr(s, `INSERT INTO epochs (number, state, started_at) VALUES (3, 'preparing', 0)`); err == nil {
		t.Fatal("deux époques en préparation doivent être refusées")
	}
	// Une époque en préparation n'est pas l'époque courante.
	if epoch, _ := s.CurrentEpoch(); epoch != 1 {
		t.Fatalf("époque courante %d, attendue 1", epoch)
	}
}

func execErr(s *Store, query string) error {
	_, err := s.db.Exec(query)
	return err
}

// ---------- Fichiers ----------

// createFile crée un fichier en attente pour owner, sur les nœuds 1..5.
func createFile(t *testing.T, s *Store, id string, owner int64, size uint64) {
	t.Helper()
	f := File{ID: id, OwnerID: owner, Name: []byte("rapport.pdf"), Size: size, T: 3, N: 5, Epoch: 1}
	if err := s.CreateFile(f, []uint32{1, 2, 3, 4, 5}); err != nil {
		t.Fatal(err)
	}
}

func TestCreateConfirmAndRead(t *testing.T) {
	s, _ := openStore(t)
	addNodes(t, s, 5)
	alice := newUser(t, s, "alice")
	createFile(t, s, "f1", alice, 100)

	f, err := s.File("f1")
	if err != nil {
		t.Fatal(err)
	}
	if f.Status != FilePending || f.OwnerID != alice || f.T != 3 || f.N != 5 || f.Epoch != 1 ||
		string(f.Name) != "rapport.pdf" || f.Size != 100 {
		t.Fatalf("fichier lu %+v", f)
	}

	want := newManifest(4, 100)
	if err := s.ConfirmUpload("f1", 1, alice, want); err != nil {
		t.Fatal(err)
	}
	f, _ = s.File("f1")
	if f.Status != FileReady {
		t.Fatalf("statut après confirmation : %s", f.Status)
	}

	got, err := s.manifest("f1")
	if err != nil {
		t.Fatal(err)
	}
	if got.BlockCount != 4 || got.Size != 100 || !bytes.Equal(got.NoncePrefix, want.NoncePrefix) ||
		len(got.BlockHashes) != 4 {
		t.Fatalf("manifeste lu %+v", got)
	}
	for i := range want.BlockHashes {
		if !bytes.Equal(got.BlockHashes[i], want.BlockHashes[i]) {
			t.Fatalf("empreinte du bloc %d différente", i)
		}
	}

	nodes, err := s.FileNodes("f1")
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 5 || nodes[0].X != 1 || nodes[4].X != 5 {
		t.Fatalf("nœuds du fichier : %+v", nodes)
	}
}

func TestCreateFileRejects(t *testing.T) {
	s, _ := openStore(t)
	addNodes(t, s, 5)
	alice := newUser(t, s, "alice")
	createFile(t, s, "f1", alice, 10)

	base := File{ID: "f2", OwnerID: alice, Name: []byte("x"), Size: 1, T: 3, N: 5, Epoch: 1}
	cases := []struct {
		name  string
		f     File
		nodes []uint32
		want  error
	}{
		{"identifiant déjà pris", withID(base, "f1"), []uint32{1, 2, 3, 4, 5}, ErrAlreadyExists},
		{"t > n", withT(base, 6), []uint32{1, 2, 3, 4, 5}, ErrInvalidArgument},
		{"t < 2", withT(base, 1), []uint32{1, 2, 3, 4, 5}, ErrInvalidArgument},
		{"nombre de nœuds ≠ n", base, []uint32{1, 2, 3}, ErrInvalidArgument},
		{"nœud en double", base, []uint32{1, 2, 3, 4, 4}, ErrInvalidArgument},
		{"nœud inconnu", base, []uint32{1, 2, 3, 4, 9}, ErrNotFound},
	}
	for _, c := range cases {
		if err := s.CreateFile(c.f, c.nodes); !errors.Is(err, c.want) {
			t.Errorf("%s : %v, attendu %v", c.name, err, c.want)
		}
	}
	// Aucun des refus ne doit laisser de trace.
	if _, err := s.File("f2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("fichier refusé mais enregistré : %v", err)
	}
}

func withID(f File, id string) File { f.ID = id; return f }
func withT(f File, t uint32) File   { f.T = t; return f }

func TestConfirmUploadRejects(t *testing.T) {
	s, _ := openStore(t)
	addNodes(t, s, 5)
	alice := newUser(t, s, "alice")
	bob := newUser(t, s, "bob")
	createFile(t, s, "f1", alice, 100)

	badHash := newManifest(2, 100)
	badHash.BlockHashes[1] = []byte("trop court")
	cases := []struct {
		name   string
		fileID string
		owner  int64
		m      Manifest
		want   error
	}{
		{"fichier inconnu", "inconnu", alice, newManifest(1, 100), ErrNotFound},
		{"autre utilisateur", "f1", bob, newManifest(1, 100), ErrNotOwner},
		{"nombre de blocs incohérent", "f1", alice, Manifest{BlockCount: 3, NoncePrefix: []byte("p"), Size: 100}, ErrInvalidArgument},
		{"empreinte de mauvaise taille", "f1", alice, badHash, ErrInvalidArgument},
		{"taille différente de CreateFile", "f1", alice, newManifest(1, 99), ErrInvalidArgument},
	}
	for _, c := range cases {
		if err := s.ConfirmUpload(c.fileID, 1, c.owner, c.m); !errors.Is(err, c.want) {
			t.Errorf("%s : %v, attendu %v", c.name, err, c.want)
		}
	}

	if err := s.ConfirmUpload("f1", 1, alice, newManifest(1, 100)); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmUpload("f1", 1, alice, newManifest(1, 100)); !errors.Is(err, ErrConflict) {
		t.Fatalf("deuxième confirmation : %v, attendu ErrConflict", err)
	}
}

func TestFilesByOwnerOnlyReadyAndOwn(t *testing.T) {
	s, clock := openStore(t)
	addNodes(t, s, 5)
	alice := newUser(t, s, "alice")
	bob := newUser(t, s, "bob")

	createFile(t, s, "a1", alice, 1)
	clock.advance(time.Second)
	createFile(t, s, "a2", alice, 1)
	createFile(t, s, "a-pending", alice, 1)
	createFile(t, s, "b1", bob, 1)
	for _, c := range []struct {
		id    string
		owner int64
	}{{"a1", alice}, {"a2", alice}, {"b1", bob}} {
		mustNil(t, s.ConfirmUpload(c.id, 1, c.owner, newManifest(1, 1)))
	}

	files, err := s.FilesByOwner(alice)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0].ID != "a1" || files[1].ID != "a2" {
		t.Fatalf("fichiers d'alice : %+v", files)
	}
	if _, err := s.manifest("a-pending"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("manifeste d'un fichier non confirmé : %v", err)
	}
}

// ---------- Renouvellement (états des époques) ----------

func TestEpochTransitions(t *testing.T) {
	s, _ := openStore(t)
	e, err := s.BeginEpoch()
	if err != nil || e != 2 {
		t.Fatalf("BeginEpoch = %d, %v ; attendu 2", e, err)
	}
	if _, err := s.BeginEpoch(); !errors.Is(err, ErrConflict) {
		t.Fatalf("deux renouvellements à la fois : %v", err)
	}
	if err := s.FinishCommit(e); !errors.Is(err, ErrConflict) {
		t.Fatalf("validation sans décision : %v", err)
	}
	mustNil(t, s.DecideCommit(e))
	if err := s.AbortEpoch(e); !errors.Is(err, ErrConflict) {
		t.Fatalf("abandon après la décision : %v", err)
	}
	active, ok, err := s.ActiveEpoch()
	if err != nil || !ok || active.State != EpochCommitting {
		t.Fatalf("ActiveEpoch = %+v, %v, %v", active, ok, err)
	}
	mustNil(t, s.FinishCommit(e))
	if epoch, _ := s.CurrentEpoch(); epoch != 2 {
		t.Fatalf("époque courante %d, attendue 2", epoch)
	}
	if _, ok, _ := s.ActiveEpoch(); ok {
		t.Fatal("renouvellement encore actif après validation")
	}
}

func TestDeleteStalePending(t *testing.T) {
	s, clock := openStore(t)
	addNodes(t, s, 5)
	alice := newUser(t, s, "alice")
	createFile(t, s, "vieux", alice, 1)
	createFile(t, s, "confirme", alice, 1)
	mustNil(t, s.ConfirmUpload("confirme", 1, alice, newManifest(1, 1)))
	clock.advance(2 * time.Hour)
	createFile(t, s, "recent", alice, 1)

	n, err := s.DeleteStalePending(clock.now().Add(-time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("DeleteStalePending = %d, %v ; attendu 1", n, err)
	}
	if _, err := s.File("vieux"); !errors.Is(err, ErrNotFound) {
		t.Fatal("le vieux dépôt non confirmé devrait être supprimé")
	}
	for _, id := range []string{"confirme", "recent"} {
		if _, err := s.File(id); err != nil {
			t.Fatalf("%s supprimé à tort : %v", id, err)
		}
	}
}

// manifest renvoie le manifeste de la version actuelle.
func (s *Store) manifest(fileID string) (Manifest, error) {
	m, _, err := s.Manifest(fileID, 0)
	return m, err
}
