// Commande coordinator de SafeVault : le service de coordination, qui garde les
// métadonnées (utilisateurs, fichiers, manifestes, nœuds, époques) sans jamais voir
// de clé ni de part.
//
// Variables d'environnement :
//
//	LISTEN_ADDR     adresse d'écoute gRPC (défaut :7443)
//	DATA_DIR        dossier de la base coordinator.db (défaut /data)
//	TLS_CERT_PATH   certificat TLS du coordinateur, signé par la CA (défaut certs/coordinator.crt)
//	TLS_KEY_PATH    clé privée TLS du coordinateur (défaut certs/coordinator.key)
//	SV_N            nombre de parts par fichier (défaut 5)
//	SV_T            seuil de reconstruction, 2 ≤ t ≤ n (défaut 3)
//	CA_PATH         certificat de la CA interne, pour vérifier les nœuds (défaut certs/ca.crt)
//	NODES           nœuds de stockage, "x=hôte:port,..." (défaut 1=node-1:7444,...,n=node-n:7444)
//	HEARTBEAT_MS    période des sondes des nœuds, en millisecondes (défaut 2000)
//	RENEWAL_INTERVAL  période du renouvellement des parts, durée Go comme "10m" ou "30s"
//	                  (défaut 10m ; "0" le désactive)
//
// Le signal SIGUSR1 lance un renouvellement immédiat (démo) :
//
//	docker compose kill -s SIGUSR1 coordinator
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

type Config struct {
	ListenAddr  string
	DataDir     string
	TLSCertPath string
	TLSKeyPath  string
	N           uint32
	T           uint32
	CAPath      string
	Nodes       map[uint32]string // x -> "hôte:port"

	HeartbeatInterval time.Duration
	RenewalInterval   time.Duration
}

func loadConfig() (Config, error) {
	n, err := getUint("SV_N", 5)
	if err != nil {
		return Config{}, err
	}
	t, err := getUint("SV_T", 3)
	if err != nil {
		return Config{}, err
	}
	if t < 2 || t > n {
		return Config{}, fmt.Errorf("il faut 2 ≤ SV_T ≤ SV_N (SV_T = %d, SV_N = %d)", t, n)
	}
	nodes, err := parseNodes(getEnv("NODES", defaultNodes(n)))
	if err != nil {
		return Config{}, err
	}
	heartbeat, err := getUint("HEARTBEAT_MS", 2000)
	if err != nil {
		return Config{}, err
	}
	if heartbeat < 100 {
		return Config{}, fmt.Errorf("HEARTBEAT_MS doit valoir au moins 100")
	}
	renewal, err := time.ParseDuration(getEnv("RENEWAL_INTERVAL", "10m"))
	if err != nil || renewal < 0 {
		return Config{}, fmt.Errorf("RENEWAL_INTERVAL doit être une durée positive, par exemple 10m")
	}
	return Config{
		ListenAddr:        getEnv("LISTEN_ADDR", ":7443"),
		DataDir:           getEnv("DATA_DIR", "/data"),
		TLSCertPath:       getEnv("TLS_CERT_PATH", "certs/coordinator.crt"),
		TLSKeyPath:        getEnv("TLS_KEY_PATH", "certs/coordinator.key"),
		N:                 n,
		T:                 t,
		CAPath:            getEnv("CA_PATH", "certs/ca.crt"),
		Nodes:             nodes,
		HeartbeatInterval: time.Duration(heartbeat) * time.Millisecond,
		RenewalInterval:   renewal,
	}, nil
}

// getEnv renvoie la variable d'environnement name, ou defaultValue si elle est vide.
func getEnv(name, defaultValue string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return defaultValue
}

// getUint lit la variable d'environnement name comme un entier positif, ou renvoie defaultValue.
func getUint(name string, defaultValue uint32) (uint32, error) {
	value := os.Getenv(name)
	if value == "" {
		return defaultValue, nil
	}
	v, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s doit être un entier positif", name)
	}
	return uint32(v), nil
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	c, err := setup(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer c.store.Close()

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatal(err)
	}

	background, cancelBackground := context.WithCancel(context.Background())
	defer cancelBackground()
	c.runBackground(background)

	renewNow := make(chan os.Signal, 1)
	signal.Notify(renewNow, syscall.SIGUSR1)
	go func() {
		for range renewNow {
			log.Println("renouvellement demandé (SIGUSR1)")
			c.renew(background)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Println("arrêt du coordinateur")
		cancelBackground()
		c.health.Shutdown() // le health check répond NOT_SERVING pendant l'arrêt
		c.grpc.GracefulStop()
	}()

	log.Printf("coordinateur à l'écoute sur %s, n = %d, t = %d, %d nœuds, renouvellement toutes les %v, données dans %s",
		cfg.ListenAddr, cfg.N, cfg.T, len(cfg.Nodes), cfg.RenewalInterval, cfg.DataDir)
	if err := c.grpc.Serve(listener); err != nil {
		log.Fatal(err)
	}
}
