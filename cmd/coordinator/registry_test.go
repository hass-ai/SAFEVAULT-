package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"safevault/internal/metadata"
)

func TestParseNodes(t *testing.T) {
	nodes, err := parseNodes("1=node-1:7444, 2=10.0.0.2:7444,")
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 || nodes[1] != "node-1:7444" || nodes[2] != "10.0.0.2:7444" {
		t.Fatalf("nœuds lus : %v", nodes)
	}
	for _, bad := range []string{"", "0=node:1", "a=node:1", "1=", "1=sans-port", "1=a:1,1=b:1", "1=a:1,2=a:1"} {
		if _, err := parseNodes(bad); err == nil {
			t.Errorf("NODES=%q devrait être refusé", bad)
		}
	}
}

func TestDefaultNodes(t *testing.T) {
	if got := defaultNodes(3); got != "1=node-1:7444,2=node-2:7444,3=node-3:7444" {
		t.Fatalf("defaultNodes(3) = %q", got)
	}
}

// newTestRegistry crée un registre sur une base temporaire avec les nœuds 1..3 et une sonde réglable.
func newTestRegistry(t *testing.T, probe probeFunc, interval time.Duration) (*registry, *metadata.Store) {
	t.Helper()
	store, err := metadata.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	r := newRegistry(store, probe, interval)
	if err := r.register(map[uint32]string{1: "n1:1", 2: "n2:1", 3: "n3:1"}); err != nil {
		t.Fatal(err)
	}
	return r, store
}

func nodeStatus(t *testing.T, store *metadata.Store, x uint32) string {
	t.Helper()
	nodes, err := store.Nodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.X == x {
			return n.Status
		}
	}
	t.Fatalf("nœud %d absent", x)
	return ""
}

func TestRegistryMarksDownAfterConsecutiveFailures(t *testing.T) {
	var node2Down atomic.Bool
	probe := func(ctx context.Context, address string) error {
		if address == "n2:1" && node2Down.Load() {
			return errors.New("injoignable")
		}
		return nil
	}
	r, store := newTestRegistry(t, probe, time.Second)
	ctx := context.Background()

	r.checkAll(ctx)
	if nodeStatus(t, store, 2) != metadata.NodeUp {
		t.Fatal("nœud 2 devrait être en service")
	}

	node2Down.Store(true)
	r.checkAll(ctx)
	if nodeStatus(t, store, 2) != metadata.NodeUp {
		t.Fatal("un seul échec ne doit pas suffire à déclarer la panne")
	}
	r.checkAll(ctx)
	if nodeStatus(t, store, 2) != metadata.NodeDown {
		t.Fatal("deux échecs consécutifs : le nœud 2 devrait être en panne")
	}
	if nodeStatus(t, store, 1) != metadata.NodeUp {
		t.Fatal("les autres nœuds doivent rester en service")
	}

	node2Down.Store(false)
	r.checkAll(ctx)
	if nodeStatus(t, store, 2) != metadata.NodeUp {
		t.Fatal("le nœud 2 répond à nouveau : il devrait être en service")
	}
}

// TestRegistryRunDetectsFailureQuickly reproduit le critère de SV-51 : un nœud arrêté
// est marqué hors service en quelques intervalles.
func TestRegistryRunDetectsFailureQuickly(t *testing.T) {
	var down atomic.Bool
	probe := func(ctx context.Context, address string) error {
		if down.Load() {
			return errors.New("injoignable")
		}
		return nil
	}
	r, store := newTestRegistry(t, probe, 20*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.run(ctx)

	waitStatus(t, store, 1, metadata.NodeUp)
	down.Store(true)
	start := time.Now()
	waitStatus(t, store, 1, metadata.NodeDown)
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("panne détectée en %s", elapsed)
	}
}

func waitStatus(t *testing.T, store *metadata.Store, x uint32, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if nodeStatus(t, store, x) == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("nœud %d jamais passé à %s", x, want)
}

// TestTLSProbe vérifie la sonde réelle contre un serveur TLS local.
func TestTLSProbe(t *testing.T) {
	pki := newTestPKI(t)
	certPath, keyPath := writeServerCert(t, pki, "node-1")
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// La poignée de main se fait à la première lecture.
			go func() { conn.Read(make([]byte, 1)); conn.Close() }()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := tlsProbe(pki.pool())(ctx, listener.Addr().String()); err != nil {
		t.Fatalf("nœud en service vu en panne : %v", err)
	}

	// Une autre CA : le certificat du nœud ne doit pas être accepté.
	other := newTestPKI(t)
	if err := tlsProbe(other.pool())(ctx, listener.Addr().String()); err == nil {
		t.Fatal("nœud signé par une CA inconnue accepté")
	}

	// Port fermé.
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := closed.Addr().String()
	closed.Close()
	if err := tlsProbe(pki.pool())(ctx, addr); err == nil {
		t.Fatal("port fermé vu en service")
	}
}
