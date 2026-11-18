// Commande node de SafeVault : un nœud de stockage, qui conserve les blocs chiffrés
// des fichiers et une part de la clé de chacun.
//
// Variables d'environnement :
//
//	NODE_X          abscisse du nœud dans le partage de Shamir (entier ≥ 1, obligatoire)
//	LISTEN_ADDR     adresse d'écoute gRPC (défaut :7444)
//	DATA_DIR        dossier des données du nœud (défaut /data)
//	TLS_CERT_PATH   certificat TLS du nœud, signé par la CA (défaut certs/node.crt)
//	TLS_KEY_PATH    clé privée TLS du nœud (défaut certs/node.key)
//	CA_PATH         certificat de la CA interne (défaut certs/ca.crt), qui sert à
//	                authentifier le coordinateur et les autres nœuds (mTLS)
package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"safevault/internal/storage"
	pb "safevault/proto"
)

// maxMessageSize est la taille maximale d'un message gRPC reçu ou envoyé, donc d'un bloc.
const maxMessageSize = 32 << 20

type Config struct {
	X           uint32
	ListenAddr  string
	DataDir     string
	TLSCertPath string
	TLSKeyPath  string
	CAPath      string
}

func loadConfig() (Config, error) {
	x, err := strconv.ParseUint(os.Getenv("NODE_X"), 10, 32)
	if err != nil || x == 0 {
		return Config{}, fmt.Errorf("NODE_X doit être un entier ≥ 1")
	}
	return Config{
		X:           uint32(x),
		ListenAddr:  getEnv("LISTEN_ADDR", ":7444"),
		DataDir:     getEnv("DATA_DIR", "/data"),
		TLSCertPath: getEnv("TLS_CERT_PATH", "certs/node.crt"),
		TLSKeyPath:  getEnv("TLS_KEY_PATH", "certs/node.key"),
		CAPath:      getEnv("CA_PATH", "certs/ca.crt"),
	}, nil
}

// getEnv renvoie la variable d'environnement name, ou defaultValue si elle est vide.
func getEnv(name, defaultValue string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return defaultValue
}

// loadCA lit le certificat de la CA interne.
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

// newGRPCServer crée le serveur gRPC du nœud, en TLS 1.3, avec ses services et le health
// check standard de gRPC. Le certificat client est facultatif (les utilisateurs n'en ont
// pas), mais s'il est présenté il doit être signé par la CA : les services Epoch et
// Renewal exigent ensuite le certificat du coordinateur ou d'un nœud (voir peer.go).
func newGRPCServer(cert tls.Certificate, ca *x509.CertPool, node *nodeServer) *grpc.Server {
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    ca,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		MinVersion:   tls.VersionTLS13,
	})
	server := grpc.NewServer(
		grpc.Creds(creds),
		grpc.MaxRecvMsgSize(maxMessageSize),
		grpc.MaxSendMsgSize(maxMessageSize),
	)
	pb.RegisterNodeServer(server, node)
	pb.RegisterRenewalServer(server, node)
	pb.RegisterEpochServer(server, node)
	healthpb.RegisterHealthServer(server, health.NewServer()) // SERVING par défaut
	return server
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	store, err := storage.Open(cfg.DataDir)
	if err != nil {
		log.Fatalf("ouverture du stockage : %v", err)
	}
	defer store.Close()

	cert, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath)
	if err != nil {
		log.Fatalf("certificat TLS : %v", err)
	}

	ca, err := loadCA(cfg.CAPath)
	if err != nil {
		log.Fatal(err)
	}

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatal(err)
	}
	server := newGRPCServer(cert, ca, newNodeServer(cfg.X, store, peerTLSConfig(cert, ca)))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Println("arrêt du nœud")
		server.GracefulStop()
	}()

	log.Printf("nœud x = %d à l'écoute sur %s, données dans %s", cfg.X, cfg.ListenAddr, cfg.DataDir)
	if err := server.Serve(listener); err != nil {
		log.Fatal(err)
	}
}
