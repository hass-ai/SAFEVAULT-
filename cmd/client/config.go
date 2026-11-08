package main

import "os"

type Config struct {
	CoordinatorAddr string // adresse du coordinateur
	CACertPath      string // certificat de la CA
	KeyPath         string // clé privée Ed25519
}

func LoadConfig() Config {
	return Config{
		CoordinatorAddr: getEnv("COORD_ADDR", "localhost:7443"),
		CACertPath:      getEnv("CA_PATH", "certs/ca.crt"),
		KeyPath:         getEnv("KEY_PATH", "certs/client.key"),
	}
}

// getEnv renvoie la variable d'environnement name, ou defaultValue si elle est vide.
func getEnv(name, defaultValue string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return defaultValue
}
