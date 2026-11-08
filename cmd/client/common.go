package main

import (
	"crypto/ed25519"
	"errors"

	"google.golang.org/grpc"
)

// generateKey crée une paire de clés Ed25519 et enregistre la clé privée dans path.
func generateKey(path string) (ed25519.PrivateKey, error) {
	return nil, errors.New("generateKey : pas encore implémenté")
}

// loadKey lit la clé privée enregistrée dans path.
func loadKey(path string) (ed25519.PrivateKey, error) {
	return nil, errors.New("loadKey : pas encore implémenté")
}

// sign signe un message précédé d'une étiquette qui indique son usage.
func sign(key ed25519.PrivateKey, label string, message []byte) []byte {
	return nil
}

// connectCoordinator ouvre une connexion TLS au coordinateur.
func connectCoordinator(cfg Config) (*grpc.ClientConn, error) {
	return nil, errors.New("connectCoordinator : pas encore implémenté")
}

// connectNode ouvre une connexion TLS au nœud d'adresse addr.
func connectNode(cfg Config, addr string) (*grpc.ClientConn, error) {
	return nil, errors.New("connectNode : pas encore implémenté")
}

// runRegister crée la clé de l'utilisateur et l'inscrit auprès du coordinateur.
func runRegister(cfg Config, username string) error {
	return errors.New("register : pas encore implémenté")
}

// runList affiche les fichiers accessibles à l'utilisateur.
func runList(cfg Config) error {
	return errors.New("ls : pas encore implémenté")
}
