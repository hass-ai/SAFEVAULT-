package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"safevault/internal/metadata"
	pb "safevault/proto"
)

// purgeInterval est la période de suppression des défis et sessions expirés.
const purgeInterval = time.Minute

// pendingTTL est le délai après lequel un dépôt jamais confirmé est supprimé.
const pendingTTL = time.Hour

// coordinatorServer implémente le service Coordinator.
type coordinatorServer struct {
	pb.UnimplementedCoordinatorServer

	store    *metadata.Store
	registry *registry
	n, t     uint32           // paramètres de Shamir, fixes pour tout le déploiement en V1
	now      func() time.Time // horloge, remplaçable dans les tests
}

func newCoordinatorServer(store *metadata.Store, reg *registry, n, t uint32) *coordinatorServer {
	return &coordinatorServer{store: store, registry: reg, n: n, t: t, now: time.Now}
}

// coordinator regroupe ce qui tourne dans le processus : serveur gRPC, health check,
// base et registre des nœuds.
type coordinator struct {
	grpc     *grpc.Server
	health   *health.Server
	store    *metadata.Store
	server   *coordinatorServer
	registry *registry
	epochs   *epochManager

	renewalInterval time.Duration
}

// setup ouvre la base (et crée le schéma), enregistre les nœuds, charge les certificats
// et prépare le serveur gRPC. Le health check ne passe à SERVING que si la base répond.
func setup(cfg Config) (*coordinator, error) {
	store, err := metadata.Open(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("ouverture de la base : %w", err)
	}
	c, err := setupWithStore(cfg, store)
	if err != nil {
		store.Close()
		return nil, err
	}
	return c, nil
}

func setupWithStore(cfg Config, store *metadata.Store) (*coordinator, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := store.Ping(ctx); err != nil {
		return nil, fmt.Errorf("la base ne répond pas : %w", err)
	}

	cert, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf("certificat TLS : %w", err)
	}
	pool, err := loadCA(cfg.CAPath)
	if err != nil {
		return nil, err
	}

	reg := newRegistry(store, tlsProbe(pool), cfg.HeartbeatInterval)
	if err := reg.register(cfg.Nodes); err != nil {
		return nil, err
	}

	healthServer := health.NewServer()
	coord := newCoordinatorServer(store, reg, cfg.N, cfg.T)
	server := newGRPCServer(cert, coord, healthServer)
	// "" désigne l'état global du serveur, l'autre nom l'état du service Coordinator.
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus(pb.Coordinator_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)

	epochs := newEpochManager(store, newNodeParticipants(cfg.Nodes, cfg.T, cert, pool))

	return &coordinator{grpc: server, health: healthServer, store: store, server: coord, registry: reg,
		epochs: epochs, renewalInterval: cfg.RenewalInterval}, nil
}

// loadCA lit le certificat de la CA interne, qui sert à vérifier les nœuds.
func loadCA(path string) (*x509.CertPool, error) {
	caPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("certificat de la CA : %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("certificat de la CA invalide")
	}
	return pool, nil
}

// runBackground lance les tâches de fond (heartbeats, purge, renouvellements) jusqu'à
// l'annulation de ctx.
func (c *coordinator) runBackground(ctx context.Context) {
	go c.registry.run(ctx)
	go c.runRenewals(ctx)
	go func() {
		ticker := time.NewTicker(purgeInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := c.store.PurgeExpired(); err != nil {
					log.Printf("purge des sessions : %v", err)
				}
				if n, err := c.store.DeleteStalePending(time.Now().Add(-pendingTTL)); err != nil {
					log.Printf("purge des dépôts abandonnés : %v", err)
				} else if n > 0 {
					log.Printf("purge : %d dépôts jamais confirmés supprimés", n)
				}
			}
		}
	}()
}

// newGRPCServer crée le serveur gRPC du coordinateur, en TLS 1.3, avec le service
// Coordinator et le health check standard de gRPC. Ordre des intercepteurs :
// journalisation (qui voit aussi les refus), puis authentification.
func newGRPCServer(cert tls.Certificate, coord *coordinatorServer, healthServer *health.Server) *grpc.Server {
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	server := grpc.NewServer(
		grpc.Creds(creds),
		grpc.ChainUnaryInterceptor(logUnary, coord.authUnary),
	)
	pb.RegisterCoordinatorServer(server, coord)
	healthpb.RegisterHealthServer(server, healthServer)
	return server
}

// runRenewals termine d'abord un renouvellement interrompu par un arrêt, puis renouvelle
// les parts toutes les renewalInterval (jamais si renewalInterval vaut 0).
func (c *coordinator) runRenewals(ctx context.Context) {
	if err := c.epochs.recover(ctx); err != nil {
		log.Printf("reprise du renouvellement : %v", err)
	}
	if c.renewalInterval <= 0 {
		return
	}
	ticker := time.NewTicker(c.renewalInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.renew(ctx)
		}
	}
}

// renew lance un renouvellement des parts et journalise le résultat.
func (c *coordinator) renew(ctx context.Context) {
	epoch, err := c.epochs.refresh(ctx)
	if err != nil {
		log.Printf("renouvellement : %v", err)
		return
	}
	log.Printf("renouvellement terminé : époque %d", epoch)
}
