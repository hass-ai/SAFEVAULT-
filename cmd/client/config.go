package main

import (
	"os"
	"path/filepath"
)

// Config est la configuration du client, lue dans l'environnement.
type Config struct {
	Home            string // dossier du client : clés et session
	Username        string // utilisateur pour les scripts (connexion automatique)
	CoordinatorAddr string // adresse du coordinateur
	CACertPath      string // certificat de la CA
	KeyPath         string // clé privée imposée (sinon <Home>/keys/<utilisateur>.key)
}

func LoadConfig() Config {
	home := os.Getenv("SAFEVAULT_HOME")
	if home == "" {
		if dir, err := os.UserHomeDir(); err == nil {
			home = filepath.Join(dir, ".safevault")
		} else {
			home = ".safevault"
		}
	}
	return Config{
		Home:            home,
		Username:        os.Getenv("CLIENT_USERNAME"),
		CoordinatorAddr: getEnv("COORD_ADDR", "localhost:7443"),
		CACertPath:      getEnv("CA_PATH", "certs/ca.crt"),
		KeyPath:         os.Getenv("KEY_PATH"),
	}
}

// keyPath renvoie le chemin de la clé privée de l'utilisateur.
func (c Config) keyPath(username string) string {
	if c.KeyPath != "" {
		return c.KeyPath
	}
	return filepath.Join(c.Home, "keys", username+".key")
}

// sessionPath renvoie le chemin du fichier de session. Avec KEY_PATH, la session est
// rangée à côté de la clé : plusieurs utilisateurs peuvent travailler sur la même machine.
func (c Config) sessionPath() string {
	if c.KeyPath != "" {
		return c.KeyPath + ".session"
	}
	return filepath.Join(c.Home, "session")
}

// getEnv renvoie la variable d'environnement name, ou defaultValue si elle est vide.
func getEnv(name, defaultValue string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return defaultValue
}
