package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// generateKey crée une paire de clés Ed25519 et enregistre la clé privée dans path.
func generateKey(path string) (ed25519.PrivateKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, privateKey, 0o600); err != nil {
		return nil, err
	}
	return privateKey, nil
}

// loadKey lit la clé privée enregistrée dans path.
func loadKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) != ed25519.PrivateKeySize {
		return nil, errors.New("clé privée invalide")
	}
	return ed25519.PrivateKey(data), nil
}

// sign signe un message précédé d'une étiquette qui indique son usage.
func sign(key ed25519.PrivateKey, label string, message []byte) []byte {
	data := append([]byte(label), 0)
	data = append(data, message...)
	return ed25519.Sign(key, data)
}

// connectCoordinator ouvre une connexion TLS au coordinateur et renvoie son client gRPC.
func connectCoordinator(cfg Config) (pb.CoordinatorClient, *grpc.ClientConn, error) {
	conn, err := connect(cfg, cfg.CoordinatorAddr)
	if err != nil {
		return nil, nil, err
	}
	return pb.NewCoordinatorClient(conn), conn, nil
}

// connectNode ouvre une connexion TLS au nœud d'adresse addr et renvoie son client gRPC.
func connectNode(cfg Config, addr string) (pb.NodeClient, *grpc.ClientConn, error) {
	conn, err := connect(cfg, addr)
	if err != nil {
		return nil, nil, err
	}
	return pb.NewNodeClient(conn), conn, nil
}

// connect ouvre une connexion gRPC en TLS, en vérifiant le certificat du serveur avec la CA.
func connect(cfg Config, addr string) (*grpc.ClientConn, error) {
	caPEM, err := os.ReadFile(cfg.CACertPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("certificat de la CA invalide")
	}
	creds := credentials.NewTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13})
	return grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
}

// proof construit la preuve d'identité d'une requête destinée au nœud x.
func proof(key ed25519.PrivateKey, label string, x uint32, fileID string, epoch uint64) *pb.Proof {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	timestamp := time.Now().Unix()
	message := fmt.Sprintf("%d|%s|%d|%d|%x", x, fileID, epoch, timestamp, nonce)
	return &pb.Proof{
		PublicKey: key.Public().(ed25519.PublicKey),
		Timestamp: timestamp,
		Nonce:     nonce,
		Signature: sign(key, label, []byte(message)),
	}
}
