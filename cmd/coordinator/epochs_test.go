package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"

	"safevault/internal/metadata"
)

// fakeNode simule un nœud : il note les étapes reçues et peut échouer à une étape.
type fakeNode struct {
	x      uint32
	mu     sync.Mutex
	calls  []string
	failOn string // "prepare", "commit" ou "abort"
}

func (n *fakeNode) X() uint32 { return n.x }
func (n *fakeNode) do(step string, epoch uint64) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls = append(n.calls, fmt.Sprintf("%s %d", step, epoch))
	if n.failOn == step {
		return errors.New("nœud injoignable")
	}
	return nil
}
func (n *fakeNode) Prepare(_ context.Context, e uint64) error { return n.do("prepare", e) }
func (n *fakeNode) Commit(_ context.Context, e uint64) error  { return n.do("commit", e) }
func (n *fakeNode) Abort(_ context.Context, e uint64) error   { return n.do("abort", e) }

func (n *fakeNode) history() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.calls)
}

func newEpochTest(t *testing.T) (*metadata.Store, []*fakeNode, *epochManager) {
	t.Helper()
	store, err := metadata.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	var nodes []*fakeNode
	var participants []participant
	for x := uint32(1); x <= 5; x++ {
		n := &fakeNode{x: x}
		nodes = append(nodes, n)
		participants = append(participants, n)
	}
	return store, nodes, newEpochManager(store, participants)
}

func wantHistory(t *testing.T, nodes []*fakeNode, want ...string) {
	t.Helper()
	for _, n := range nodes {
		if got := n.history(); !slices.Equal(got, want) {
			t.Fatalf("nœud %d a reçu %v, attendu %v", n.x, got, want)
		}
	}
}

func wantEpoch(t *testing.T, store *metadata.Store, current uint64) {
	t.Helper()
	got, err := store.CurrentEpoch()
	if err != nil || got != current {
		t.Fatalf("époque courante %d (%v), attendue %d", got, err, current)
	}
	if _, active, _ := store.ActiveEpoch(); active {
		t.Fatal("un renouvellement est resté en cours")
	}
}

func TestRefreshCommitsOnAllNodes(t *testing.T) {
	store, nodes, m := newEpochTest(t)
	epoch, err := m.refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if epoch != 2 {
		t.Fatalf("nouvelle époque %d, attendue 2", epoch)
	}
	wantHistory(t, nodes, "prepare 2", "commit 2")
	wantEpoch(t, store, 2)
}

func TestRefreshAbortsWhenOneNodeCannotPrepare(t *testing.T) {
	store, nodes, m := newEpochTest(t)
	nodes[3].failOn = "prepare"
	if _, err := m.refresh(context.Background()); err == nil {
		t.Fatal("le renouvellement aurait dû échouer")
	}
	// Personne n'a reçu COMMIT : tout le monde garde ses parts de l'époque 1.
	wantHistory(t, nodes, "prepare 2", "abort 2")
	wantEpoch(t, store, 1)

	// Le renouvellement suivant utilise un numéro neuf.
	nodes[3].failOn = ""
	epoch, err := m.refresh(context.Background())
	if err != nil || epoch != 3 {
		t.Fatalf("deuxième essai : époque %d, %v ; attendue 3", epoch, err)
	}
	wantEpoch(t, store, 3)
}

func TestCommitFailureIsFinishedByRecover(t *testing.T) {
	store, nodes, m := newEpochTest(t)
	nodes[1].failOn = "commit"
	if _, err := m.refresh(context.Background()); err == nil {
		t.Fatal("le renouvellement aurait dû signaler le nœud injoignable")
	}
	// La décision est prise : l'époque reste en committing, jamais abandonnée.
	active, ok, _ := store.ActiveEpoch()
	if !ok || active.State != metadata.EpochCommitting {
		t.Fatalf("état après un COMMIT manqué : %+v", active)
	}

	nodes[1].failOn = ""
	if err := m.recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := nodes[1].history(); !slices.Equal(got, []string{"prepare 2", "commit 2", "commit 2"}) {
		t.Fatalf("nœud 2 : %v", got)
	}
	wantEpoch(t, store, 2)
}

// TestCrashAtEachStep simule un arrêt du coordinateur à chaque étape, puis un
// redémarrage : il ne doit jamais rester d'époque mélangée (critère de SV-56).
func TestCrashAtEachStep(t *testing.T) {
	t.Run("après BeginEpoch", func(t *testing.T) {
		store, nodes, m := newEpochTest(t)
		begin(t, store)
		mustRecover(t, m)
		wantHistory(t, nodes, "abort 2")
		wantEpoch(t, store, 1)
	})
	t.Run("pendant PREPARE", func(t *testing.T) {
		store, nodes, m := newEpochTest(t)
		begin(t, store)
		_ = nodes[0].Prepare(context.Background(), 2) // un seul nœud a préparé
		mustRecover(t, m)
		if got := nodes[0].history(); !slices.Equal(got, []string{"prepare 2", "abort 2"}) {
			t.Fatalf("nœud 1 : %v", got)
		}
		wantEpoch(t, store, 1)
	})
	t.Run("après la décision, avant COMMIT", func(t *testing.T) {
		store, nodes, m := newEpochTest(t)
		begin(t, store)
		if err := store.DecideCommit(2); err != nil {
			t.Fatal(err)
		}
		mustRecover(t, m)
		wantHistory(t, nodes, "commit 2")
		wantEpoch(t, store, 2)
	})
	t.Run("pendant COMMIT", func(t *testing.T) {
		store, nodes, m := newEpochTest(t)
		begin(t, store)
		if err := store.DecideCommit(2); err != nil {
			t.Fatal(err)
		}
		_ = nodes[0].Commit(context.Background(), 2) // un seul nœud a basculé
		mustRecover(t, m)
		if got := nodes[0].history(); !slices.Equal(got, []string{"commit 2", "commit 2"}) {
			t.Fatalf("nœud 1 : %v (COMMIT doit être idempotent côté nœud)", got)
		}
		wantEpoch(t, store, 2)
	})
	t.Run("rien en cours", func(t *testing.T) {
		store, nodes, m := newEpochTest(t)
		mustRecover(t, m)
		wantHistory(t, nodes)
		wantEpoch(t, store, 1)
	})
}

// begin enregistre le début d'un renouvellement, comme le ferait refresh avant un crash.
func begin(t *testing.T, store *metadata.Store) {
	t.Helper()
	if _, err := store.BeginEpoch(); err != nil {
		t.Fatal(err)
	}
}

func mustRecover(t *testing.T, m *epochManager) {
	t.Helper()
	if err := m.recover(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshBlockedByPendingUploadAndBlocksUploads(t *testing.T) {
	store, _, m := newEpochTest(t)
	for x := uint32(1); x <= 5; x++ {
		if err := store.UpsertNode(x, fmt.Sprintf("node-%d:7444", x)); err != nil {
			t.Fatal(err)
		}
	}
	owner, err := store.CreateUser("alice", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f := metadata.File{ID: "f1", OwnerID: owner, Name: []byte("a"), Size: 1, T: 3, N: 5, Epoch: 1}
	if err := store.CreateFile(f, []uint32{1, 2, 3, 4, 5}); err != nil {
		t.Fatal(err)
	}

	// Dépôt en cours : pas de renouvellement.
	if _, err := m.refresh(context.Background()); !errors.Is(err, errRenewalBusy) {
		t.Fatalf("renouvellement avec un dépôt non confirmé : %v", err)
	}

	// Dépôt confirmé : le renouvellement passe et le fichier suit la nouvelle époque.
	if err := store.ConfirmUpload("f1", owner, metadata.Manifest{Size: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := store.File("f1")
	if got.Epoch != 2 {
		t.Fatalf("époque du fichier %d, attendue 2", got.Epoch)
	}

	// Pendant un renouvellement, aucun nouveau dépôt.
	begin(t, store)
	f.ID = "f2"
	if err := store.CreateFile(f, []uint32{1, 2, 3, 4, 5}); !errors.Is(err, metadata.ErrConflict) {
		t.Fatalf("dépôt pendant un renouvellement : %v", err)
	}
}
