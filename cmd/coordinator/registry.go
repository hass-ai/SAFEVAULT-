package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"safevault/internal/metadata"
)

// failuresBeforeDown est le nombre d'échecs consécutifs avant de déclarer un nœud en
// panne : un seul paquet perdu ne doit pas faire tomber un nœud.
const failuresBeforeDown = 2

// parseNodes lit la liste statique des nœuds, au format "1=node-1:7444,2=node-2:7444".
func parseNodes(value string) (map[uint32]string, error) {
	nodes := make(map[uint32]string)
	addresses := make(map[string]bool)
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		xText, address, ok := strings.Cut(item, "=")
		x, err := strconv.ParseUint(xText, 10, 32)
		if !ok || err != nil || x == 0 || address == "" {
			return nil, fmt.Errorf("NODES : entrée %q invalide, format attendu x=hôte:port", item)
		}
		if _, _, err := net.SplitHostPort(address); err != nil {
			return nil, fmt.Errorf("NODES : adresse %q invalide", address)
		}
		if _, dup := nodes[uint32(x)]; dup || addresses[address] {
			return nil, fmt.Errorf("NODES : x = %d ou adresse %q en double", x, address)
		}
		nodes[uint32(x)] = address
		addresses[address] = true
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("NODES : aucun nœud")
	}
	return nodes, nil
}

// defaultNodes renvoie la liste des nœuds de Docker Compose : x = node-x:7444, pour x = 1..n.
func defaultNodes(n uint32) string {
	items := make([]string, n)
	for x := uint32(1); x <= n; x++ {
		items[x-1] = fmt.Sprintf("%d=node-%d:7444", x, x)
	}
	return strings.Join(items, ",")
}

// probeFunc vérifie qu'un nœud répond. Remplaçable dans les tests.
type probeFunc func(ctx context.Context, address string) error

// tlsProbe vérifie qu'un nœud accepte une connexion TLS 1.3 avec un certificat signé
// par la CA et valable pour son nom. Le nœud n'expose pas encore de service de santé
// (voir docs/proposals/rpc-coordinateur-noeud.md) : la poignée de main TLS prouve au
// moins que le processus tourne et possède la clé de son certificat.
func tlsProbe(pool *x509.CertPool) probeFunc {
	return func(ctx context.Context, address string) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		dialer := &tls.Dialer{Config: &tls.Config{
			RootCAs:    pool,
			ServerName: host,
			MinVersion: tls.VersionTLS13,
		}}
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			return err
		}
		return conn.Close()
	}
}

// registry suit l'état des nœuds de stockage par des sondes périodiques (heartbeats)
// et enregistre leur état dans la base.
type registry struct {
	store    *metadata.Store
	probe    probeFunc
	interval time.Duration
	timeout  time.Duration
	now      func() time.Time

	mu       sync.Mutex
	failures map[uint32]int // échecs consécutifs par nœud
}

func newRegistry(store *metadata.Store, probe probeFunc, interval time.Duration) *registry {
	return &registry{
		store:    store,
		probe:    probe,
		interval: interval,
		timeout:  interval / 2,
		now:      time.Now,
		failures: make(map[uint32]int),
	}
}

// register enregistre les nœuds de la configuration dans la base.
func (r *registry) register(nodes map[uint32]string) error {
	for x, address := range nodes {
		if err := r.store.UpsertNode(x, address); err != nil {
			return fmt.Errorf("nœud %d : %w", x, err)
		}
	}
	return nil
}

// run sonde tous les nœuds à chaque intervalle, jusqu'à l'annulation de ctx.
func (r *registry) run(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		r.checkAll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// checkAll sonde tous les nœuds en parallèle et met leur état à jour.
func (r *registry) checkAll(ctx context.Context) {
	nodes, err := r.store.Nodes()
	if err != nil {
		log.Printf("registre : lecture des nœuds : %v", err)
		return
	}
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			probeCtx, cancel := context.WithTimeout(ctx, r.timeout)
			defer cancel()
			r.record(n, r.probe(probeCtx, n.Address))
		}()
	}
	wg.Wait()
}

// record applique le résultat d'une sonde : en service dès qu'il répond, en panne après
// failuresBeforeDown échecs consécutifs. Les changements d'état sont journalisés.
func (r *registry) record(n metadata.Node, probeErr error) {
	r.mu.Lock()
	newStatus := n.Status
	lastSeen := n.LastSeen
	if probeErr == nil {
		r.failures[n.X] = 0
		newStatus = metadata.NodeUp
		lastSeen = r.now()
	} else {
		r.failures[n.X]++
		if r.failures[n.X] >= failuresBeforeDown {
			newStatus = metadata.NodeDown
		}
	}
	r.mu.Unlock()

	if err := r.store.SetNodeStatus(n.X, newStatus, lastSeen); err != nil {
		log.Printf("registre : nœud %d : %v", n.X, err)
		return
	}
	if newStatus != n.Status {
		log.Printf("registre : nœud x=%d %s -> %s", n.X, n.Status, newStatus)
	}
}

// uploadNodes renvoie les nœuds x = 1..n qui recevront les parts d'un nouveau fichier.
// Le partage de Shamir du client donne la part d'indice x au nœud x : il faut donc que
// ces n nœuds soient tous en service, sinon le dépôt est refusé.
func (r *registry) uploadNodes(n uint32) ([]metadata.Node, error) {
	nodes, err := r.store.Nodes()
	if err != nil {
		return nil, internalError(err)
	}
	byX := make(map[uint32]metadata.Node)
	for _, node := range nodes {
		byX[node.X] = node
	}
	selected := make([]metadata.Node, 0, n)
	for x := uint32(1); x <= n; x++ {
		node, ok := byX[x]
		if !ok || node.Status != metadata.NodeUp {
			return nil, status.Errorf(codes.Unavailable,
				"dépôt impossible : le nœud x = %d n'est pas en service", x)
		}
		selected = append(selected, node)
	}
	return selected, nil
}
