package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"safevault/internal/metadata"
	pb "safevault/proto"
)

// testCoordinator est un coordinateur lancé en TLS sur un port local, via setup()
// comme en production, avec ses clients gRPC. Les heartbeats ne tournent pas : les
// tests règlent eux-mêmes l'état des nœuds.
type testCoordinator struct {
	addr    string
	caPool  *x509.CertPool
	dataDir string
	store   *metadata.Store
	coord   pb.CoordinatorClient
	health  healthpb.HealthClient
}

// testPKI est une CA de test et le dossier où ses certificats sont écrits en PEM.
type testPKI struct {
	dir    string
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPath string
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	dir := t.TempDir()
	ca, caKey := newCA(t)
	caPath := filepath.Join(dir, "ca.crt")
	writePEM(t, caPath, "CERTIFICATE", ca.Raw)
	return &testPKI{dir: dir, ca: ca, caKey: caKey, caPath: caPath}
}

func (p *testPKI) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.ca)
	return pool
}

// testConfig renvoie une configuration de test : n = 5, t = 3, nœuds 1..5.
func testConfig(t *testing.T, pki *testPKI) Config {
	t.Helper()
	certPath, keyPath := writeServerCert(t, pki, "coordinator")
	nodes, err := parseNodes(defaultNodes(5))
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		DataDir:           filepath.Join(pki.dir, "data"),
		TLSCertPath:       certPath,
		TLSKeyPath:        keyPath,
		N:                 5,
		T:                 3,
		CAPath:            pki.caPath,
		Nodes:             nodes,
		HeartbeatInterval: time.Second,
	}
}

func startCoordinator(t *testing.T) *testCoordinator {
	t.Helper()
	pki := newTestPKI(t)
	cfg := testConfig(t, pki)
	c, err := setup(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.store.Close() })

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go c.grpc.Serve(listener)
	t.Cleanup(c.grpc.Stop)

	// Le client vérifie le certificat du coordinateur avec la CA, comme le client SafeVault.
	creds := credentials.NewTLS(&tls.Config{RootCAs: pki.pool(), MinVersion: tls.VersionTLS13})
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	return &testCoordinator{
		addr:    listener.Addr().String(),
		caPool:  pki.pool(),
		dataDir: cfg.DataDir,
		store:   c.store,
		coord:   pb.NewCoordinatorClient(conn),
		health:  healthpb.NewHealthClient(conn),
	}
}

// setNodes règle l'état des nœuds 1..5 : up[i] pour le nœud i+1.
func (c *testCoordinator) setNodes(t *testing.T, up ...bool) {
	t.Helper()
	for i, isUp := range up {
		state := metadata.NodeDown
		if isUp {
			state = metadata.NodeUp
		}
		if err := c.store.SetNodeStatus(uint32(i+1), state, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
}

func (c *testCoordinator) allNodesUp(t *testing.T) {
	t.Helper()
	c.setNodes(t, true, true, true, true, true)
}

func newCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CA de test SafeVault"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

// writeServerCert crée un certificat signé par la CA, valable pour 127.0.0.1, et l'écrit
// en PEM comme scripts/gen_certs.sh.
func writeServerCert(t *testing.T, pki *testPKI, name string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, pki.ca, &key.PublicKey, pki.caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	certPath := filepath.Join(pki.dir, name+".crt")
	keyPath := filepath.Join(pki.dir, name+".key")
	writePEM(t, certPath, "CERTIFICATE", der)
	writePEM(t, keyPath, "EC PRIVATE KEY", keyDER)
	return certPath, keyPath
}

func writePEM(t *testing.T, path, kind string, der []byte) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// ---------- Démarrage et health check ----------

func TestHealthServing(t *testing.T) {
	c := startCoordinator(t)
	for _, service := range []string{"", pb.Coordinator_ServiceDesc.ServiceName} {
		resp, err := c.health.Check(testContext(t), &healthpb.HealthCheckRequest{Service: service})
		if err != nil {
			t.Fatalf("health check %q : %v", service, err)
		}
		if resp.Status != healthpb.HealthCheckResponse_SERVING {
			t.Fatalf("health check %q : %s, attendu SERVING", service, resp.Status)
		}
	}
}

func TestSetupCreatesSchemaAndNodes(t *testing.T) {
	c := startCoordinator(t)
	if _, err := os.Stat(filepath.Join(c.dataDir, metadata.DBFile)); err != nil {
		t.Fatalf("base absente après le démarrage : %v", err)
	}
	if epoch, err := c.store.CurrentEpoch(); err != nil || epoch != 1 {
		t.Fatalf("époque courante %d, %v ; attendue 1", epoch, err)
	}
	nodes, err := c.store.Nodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 5 || nodes[0].Address != "node-1:7444" || nodes[0].Status != metadata.NodeUnknown {
		t.Fatalf("nœuds enregistrés au démarrage : %+v", nodes)
	}
}

func TestSetupFailsWithoutCertificates(t *testing.T) {
	pki := newTestPKI(t)
	cfg := testConfig(t, pki)
	cfg.TLSCertPath = filepath.Join(pki.dir, "absent.crt")
	if _, err := setup(cfg); err == nil {
		t.Fatal("le démarrage sans certificat doit échouer")
	}

	cfg = testConfig(t, pki)
	cfg.DataDir = filepath.Join(pki.dir, "data2")
	cfg.CAPath = filepath.Join(pki.dir, "absente.crt")
	if _, err := setup(cfg); err == nil {
		t.Fatal("le démarrage sans CA doit échouer")
	}
}

// ---------- TLS ----------

func TestRefusesTLS12(t *testing.T) {
	c := startCoordinator(t)
	conn, err := tls.Dial("tcp", c.addr, &tls.Config{
		RootCAs:    c.caPool,
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
	})
	if err == nil {
		conn.Close()
		t.Fatal("une connexion TLS 1.2 doit être refusée")
	}
}

func TestRefusesUntrustedCA(t *testing.T) {
	c := startCoordinator(t)
	// Le client ne fait confiance qu'à une autre CA : la poignée de main doit échouer.
	otherCA, _ := newCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(otherCA)
	conn, err := tls.Dial("tcp", c.addr, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13})
	if err == nil {
		conn.Close()
		t.Fatal("un certificat d'une CA inconnue doit être refusé par le client")
	}
}

// ---------- Journalisation (G10) ----------

func TestLogsWhoWhatResultWithoutSecrets(t *testing.T) {
	c := startCoordinator(t)
	c.allNodesUp(t)
	var buf syncBuffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	key := registerUser(t, c, "alice-nom-prive")
	ctx, token := loginToken(t, c, "alice-nom-prive", key)
	file, err := c.coord.CreateFile(ctx, &pb.CreateFileRequest{Name: "nom-de-fichier-prive.pdf", Size: 10})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.health.Check(testContext(t), &healthpb.HealthCheckRequest{})

	out := buf.String()
	for _, want := range []string{
		"rpc=/safevault.Coordinator/Register user=1 file=- code=OK",
		"rpc=/safevault.Coordinator/Login user=1",
		"rpc=/safevault.Coordinator/CreateFile user=1 file=" + file.FileId + " code=OK",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ligne attendue absente : %q\njournal : %s", want, out)
		}
	}
	for _, secret := range []string{"alice-nom-prive", "nom-de-fichier-prive", token} {
		if strings.Contains(out, secret) {
			t.Errorf("le journal contient une donnée privée %q : %s", secret, out)
		}
	}
	if strings.Contains(out, "Health") {
		t.Errorf("le health check ne doit pas être journalisé : %s", out)
	}
}

// syncBuffer est un bytes.Buffer protégé, car le serveur écrit le journal depuis
// une autre goroutine que le test.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// ---------- Configuration ----------

func clearEnv(t *testing.T) {
	for _, name := range []string{"LISTEN_ADDR", "DATA_DIR", "TLS_CERT_PATH", "TLS_KEY_PATH",
		"SV_N", "SV_T", "CA_PATH", "NODES", "HEARTBEAT_MS"} {
		t.Setenv(name, "")
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	clearEnv(t)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != ":7443" || cfg.DataDir != "/data" ||
		cfg.TLSCertPath != "certs/coordinator.crt" || cfg.TLSKeyPath != "certs/coordinator.key" ||
		cfg.CAPath != "certs/ca.crt" || cfg.N != 5 || cfg.T != 3 || cfg.HeartbeatInterval != 2*time.Second {
		t.Fatalf("configuration par défaut : %+v", cfg)
	}
	if len(cfg.Nodes) != 5 || cfg.Nodes[3] != "node-3:7444" {
		t.Fatalf("nœuds par défaut : %v", cfg.Nodes)
	}
}

func TestLoadConfigRejects(t *testing.T) {
	cases := []struct{ name, value string }{
		{"SV_T", "1"},   // t < 2
		{"SV_T", "6"},   // t > n
		{"SV_T", "abc"}, // pas un entier
		{"SV_N", "-1"},  // négatif
		{"NODES", "x=node:1"},
		{"HEARTBEAT_MS", "10"},
	}
	for _, c := range cases {
		clearEnv(t)
		t.Setenv(c.name, c.value)
		if _, err := loadConfig(); err == nil {
			t.Errorf("%s=%s devrait être refusé", c.name, c.value)
		}
	}
}
