package main

import (
	"context"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"filippo.io/edwards25519"
	"google.golang.org/grpc/codes"

	"safevault/internal/shamir"
	"safevault/internal/storage"
	pb "safevault/proto"
)

const testT = 3

// testCluster est un ensemble de nœuds qui partagent la même CA, comme en Docker Compose.
type testCluster struct {
	nodes        []*testNode
	coordinators []pb.EpochClient // un client Epoch par nœud, avec le certificat "coordinator"
}

func startCluster(t *testing.T, n int) *testCluster {
	t.Helper()
	pki := newPKI(t)
	c := &testCluster{}
	for x := 1; x <= n; x++ {
		node := startNodeWith(t, pki, uint32(x))
		c.nodes = append(c.nodes, node)
		c.coordinators = append(c.coordinators, node.epochAs(t, coordinatorName))
	}
	return c
}

func (c *testCluster) participants() []*pb.Participant {
	var ps []*pb.Participant
	for _, n := range c.nodes {
		ps = append(ps, &pb.Participant{X: n.x, Address: n.addr})
	}
	return ps
}

// deposit partage un secret neuf entre les nœuds pour le fichier fileID, à l'époque epoch,
// comme le ferait le client.
func (c *testCluster) deposit(t *testing.T, fileID string, epoch uint64) *edwards25519.Scalar {
	t.Helper()
	secret, _ := shamir.NewSecret(rand.Reader)
	shares, err := shamir.Split(secret, testT, len(c.nodes), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for i, n := range c.nodes {
		err := n.store.PutShare(fileID, storage.Share{X: shares[i].Index, Value: shares[i].Value.Bytes(), Epoch: epoch})
		if err != nil {
			t.Fatal(err)
		}
	}
	return secret
}

// prepareAll appelle Prepare en parallèle sur tous les nœuds, comme le coordinateur.
func (c *testCluster) prepareAll(t *testing.T, ctx context.Context, epoch uint64, participants []*pb.Participant) []error {
	t.Helper()
	errs := make([]error, len(c.nodes))
	var wg sync.WaitGroup
	for i, client := range c.coordinators {
		wg.Go(func() {
			_, errs[i] = client.Prepare(ctx, &pb.PrepareRequest{Epoch: epoch, T: testT, Participants: participants})
		})
	}
	wg.Wait()
	return errs
}

func (c *testCluster) commitAll(t *testing.T, epoch uint64) {
	t.Helper()
	for _, client := range c.coordinators {
		if _, err := client.Commit(context.Background(), &pb.EpochRequest{Epoch: epoch}); err != nil {
			t.Fatal(err)
		}
	}
}

// shares renvoie la part en service de fileID sur chaque nœud.
func (c *testCluster) shares(t *testing.T, fileID string) []shamir.Share {
	t.Helper()
	var out []shamir.Share
	for _, n := range c.nodes {
		s, err := n.store.Share(fileID)
		if err != nil {
			t.Fatal(err)
		}
		value, err := edwards25519.NewScalar().SetCanonicalBytes(s.Value)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, shamir.Share{Index: s.X, Epoch: s.Epoch, Value: value})
	}
	return out
}

func combine(t *testing.T, shares ...shamir.Share) *edwards25519.Scalar {
	t.Helper()
	secret, err := shamir.Combine(shares, testT)
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

// TestRenewal déroule un renouvellement complet entre 5 nœuds et vérifie les propriétés
// de la page Garanties : clé inchangée, parts toutes nouvelles, parts d'époques mélangées
// inutiles (G2), anciennes parts effacées.
func TestRenewal(t *testing.T) {
	c := startCluster(t, 5)
	secrets := map[string]*edwards25519.Scalar{
		"f1": c.deposit(t, "f1", 1),
		"f2": c.deposit(t, "f2", 1),
	}
	before := c.shares(t, "f1")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for i, err := range c.prepareAll(t, ctx, 2, c.participants()) {
		if err != nil {
			t.Fatalf("Prepare sur le nœud %d : %v", i+1, err)
		}
	}

	// Avant le Commit, les parts en service sont toujours celles de l'époque 1.
	if s := c.shares(t, "f1"); s[0].Epoch != 1 || s[0].Value.Equal(before[0].Value) != 1 {
		t.Fatal("la part en service a changé avant le Commit")
	}

	c.commitAll(t, 2)
	after := c.shares(t, "f1")

	for i := range after {
		if after[i].Epoch != 2 {
			t.Fatalf("nœud %d : part à l'époque %d après le Commit", i+1, after[i].Epoch)
		}
		if after[i].Value.Equal(before[i].Value) == 1 {
			t.Fatalf("nœud %d : part inchangée après le renouvellement", i+1)
		}
	}

	// La clé ne change pas : n'importe quels 3 nœuds la retrouvent.
	for fileID, secret := range secrets {
		s := c.shares(t, fileID)
		if combine(t, s[0], s[1], s[2]).Equal(secret) != 1 || combine(t, s[4], s[2], s[3]).Equal(secret) != 1 {
			t.Fatalf("%s : la clé a changé pendant le renouvellement", fileID)
		}
	}

	// G2 : deux anciennes parts + une nouvelle ne redonnent pas la clé.
	mixed := []shamir.Share{before[0], before[1], after[2]}
	for i := range mixed {
		mixed[i].Epoch = 0 // on force le mélange, que Combine refuserait sinon
	}
	if combine(t, mixed...).Equal(secrets["f1"]) == 1 {
		t.Fatal("des parts d'époques différentes redonnent la clé")
	}

	// Les sous-parts ne servent plus : elles sont effacées au Commit.
	for i, n := range c.nodes {
		if subs, _ := n.store.SubShares(2); len(subs) != 0 {
			t.Fatalf("nœud %d : %d sous-parts restantes après le Commit", i+1, len(subs))
		}
	}
}

// TestRenewalTwice vérifie qu'on peut enchaîner les époques.
func TestRenewalTwice(t *testing.T) {
	c := startCluster(t, 5)
	secret := c.deposit(t, "f1", 1)

	for epoch := uint64(2); epoch <= 3; epoch++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		for _, err := range c.prepareAll(t, ctx, epoch, c.participants()) {
			if err != nil {
				t.Fatal(err)
			}
		}
		cancel()
		c.commitAll(t, epoch)
	}
	s := c.shares(t, "f1")
	if s[0].Epoch != 3 || combine(t, s[1], s[3], s[4]).Equal(secret) != 1 {
		t.Fatal("clé perdue après deux renouvellements")
	}
}

// TestRenewalAbort vérifie qu'un renouvellement abandonné laisse les parts en service intactes.
func TestRenewalAbort(t *testing.T) {
	c := startCluster(t, 5)
	secret := c.deposit(t, "f1", 1)
	before := c.shares(t, "f1")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c.prepareAll(t, ctx, 2, c.participants())
	for _, client := range c.coordinators {
		if _, err := client.Abort(context.Background(), &pb.EpochRequest{Epoch: 2}); err != nil {
			t.Fatal(err)
		}
	}

	after := c.shares(t, "f1")
	for i := range after {
		if after[i].Epoch != 1 || after[i].Value.Equal(before[i].Value) != 1 {
			t.Fatalf("nœud %d : part modifiée par un renouvellement abandonné", i+1)
		}
		if ok, _ := c.nodes[i].store.HasPending(2); ok {
			t.Fatalf("nœud %d : part en attente restante après l'abandon", i+1)
		}
	}
	if combine(t, after[0], after[1], after[2]).Equal(secret) != 1 {
		t.Fatal("clé perdue après un abandon")
	}
}

// TestRenewalMissingParticipant vérifie qu'un participant arrêté fait échouer Prepare au
// lieu de produire des parts incohérentes.
func TestRenewalMissingParticipant(t *testing.T) {
	c := startCluster(t, 5)
	c.deposit(t, "f1", 1)

	// Le participant 5 est annoncé mais ne contribue pas : on n'appelle Prepare que sur 1 à 4.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c.coordinators = c.coordinators[:4]
	c.nodes = c.nodes[:4]
	failed := 0
	for _, err := range c.prepareAll(t, ctx, 2, append(c.participants(), &pb.Participant{X: 5, Address: "127.0.0.1:1"})) {
		if err != nil {
			failed++
		}
	}
	if failed != 4 {
		t.Fatalf("%d Prepare en échec sur 4 alors qu'un participant manque", failed)
	}
	for i, n := range c.nodes {
		if ok, _ := n.store.HasPending(2); ok {
			t.Fatalf("nœud %d : part en attente calculée sans toutes les contributions", i+1)
		}
	}
}

// TestPrepareIdempotent vérifie qu'un second Prepare de la même époque ne retire pas δ.
func TestPrepareIdempotent(t *testing.T) {
	c := startCluster(t, 3)
	secret := c.deposit(t, "f1", 1)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for range 2 {
		for _, err := range c.prepareAll(t, ctx, 2, c.participants()) {
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	c.commitAll(t, 2)
	s := c.shares(t, "f1")
	if combine(t, s...).Equal(secret) != 1 {
		t.Fatal("clé perdue après un Prepare répété")
	}
}

// TestEpochRequiresCoordinator vérifie que seul le coordinateur pilote les époques.
func TestEpochRequiresCoordinator(t *testing.T) {
	n := startNode(t)
	ctx := context.Background()
	req := &pb.EpochRequest{Epoch: 2}

	_, err := pb.NewEpochClient(n.pki.dial(t, n.addr, nil)).Commit(ctx, req)
	wantCode(t, err, codes.Unauthenticated)

	_, err = n.epochAs(t, "node-1").Abort(ctx, req)
	wantCode(t, err, codes.PermissionDenied)

	_, err = n.epochAs(t, "node-1").Prepare(ctx, &pb.PrepareRequest{Epoch: 2, T: 1,
		Participants: []*pb.Participant{{X: testX, Address: n.addr}}})
	wantCode(t, err, codes.PermissionDenied)
}

func TestPrepareInvalid(t *testing.T) {
	n := startNode(t)
	client := n.epochAs(t, coordinatorName)
	self := &pb.Participant{X: testX, Address: n.addr}

	cases := map[string]*pb.PrepareRequest{
		"époque nulle":       {T: 1, Participants: []*pb.Participant{self}},
		"nœud absent":        {Epoch: 2, T: 1, Participants: []*pb.Participant{{X: 1, Address: "a:1"}}},
		"seuil trop grand":   {Epoch: 2, T: 2, Participants: []*pb.Participant{self}},
		"participant double": {Epoch: 2, T: 1, Participants: []*pb.Participant{self, self}},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := client.Prepare(context.Background(), req)
			wantCode(t, err, codes.InvalidArgument)
		})
	}
}
