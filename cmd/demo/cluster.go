package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

func nodeName(x int) string { return fmt.Sprintf("node-%d", x) }

// cluster lance et pilote les vrais programmes de SafeVault (coordinateur, nœuds, client)
// dans un dossier temporaire, comme le ferait Docker Compose.
type cluster struct {
	dir   string // dossier de travail : binaires, certificats, données
	n, t  int
	nodes []*process
	coord *process

	mu sync.Mutex
}

// process est un composant lancé par la démo.
type process struct {
	name string
	bin  string
	env  []string
	addr string // adresse d'écoute, pour les nœuds et le coordinateur
	data string // dossier de données
	log  string // fichier de journal

	mu   sync.Mutex
	cmd  *exec.Cmd
	done chan struct{} // fermé quand le processus s'est terminé
}

// newCluster compile les programmes, génère les certificats et choisit les ports.
func newCluster(dir string, n, t int) (*cluster, error) {
	for _, d := range []string{"bin", "certs"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			return nil, err
		}
	}
	for _, program := range []string{"node", "coordinator", "client"} {
		out := filepath.Join(dir, "bin", program)
		build := exec.Command("go", "build", "-o", out, "./cmd/"+program)
		if output, err := build.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("compilation de cmd/%s (lancer la démo depuis la racine du dépôt) : %v\n%s", program, err, output)
		}
	}
	if err := generateCerts(filepath.Join(dir, "certs"), n); err != nil {
		return nil, err
	}

	c := &cluster{dir: dir, n: n, t: t}
	certs := filepath.Join(dir, "certs")
	var nodeList []string
	for x := 1; x <= n; x++ {
		addr, err := freeAddr()
		if err != nil {
			return nil, err
		}
		name := nodeName(x)
		p := &process{
			name: name,
			bin:  filepath.Join(dir, "bin", "node"),
			addr: addr,
			data: filepath.Join(dir, name),
			log:  filepath.Join(dir, name+".log"),
		}
		p.env = []string{
			fmt.Sprintf("NODE_X=%d", x),
			"LISTEN_ADDR=" + addr,
			"DATA_DIR=" + p.data,
			"TLS_CERT_PATH=" + filepath.Join(certs, name+".crt"),
			"TLS_KEY_PATH=" + filepath.Join(certs, name+".key"),
			"CA_PATH=" + filepath.Join(certs, "ca.crt"),
		}
		c.nodes = append(c.nodes, p)
		nodeList = append(nodeList, fmt.Sprintf("%d=%s", x, addr))
	}

	addr, err := freeAddr()
	if err != nil {
		return nil, err
	}
	c.coord = &process{
		name: "coordinator",
		bin:  filepath.Join(dir, "bin", "coordinator"),
		addr: addr,
		data: filepath.Join(dir, "coordinator"),
		log:  filepath.Join(dir, "coordinator.log"),
	}
	c.coord.env = []string{
		"LISTEN_ADDR=" + addr,
		"DATA_DIR=" + c.coord.data,
		"TLS_CERT_PATH=" + filepath.Join(certs, "coordinator.crt"),
		"TLS_KEY_PATH=" + filepath.Join(certs, "coordinator.key"),
		"CA_PATH=" + filepath.Join(certs, "ca.crt"),
		fmt.Sprintf("SV_N=%d", n),
		fmt.Sprintf("SV_T=%d", t),
		"NODES=" + strings.Join(nodeList, ","),
		"HEARTBEAT_MS=500",
		"RENEWAL_INTERVAL=0", // la démo déclenche les renouvellements à la main
	}
	return c, nil
}

// freeAddr réserve un port libre sur la machine locale.
func freeAddr() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return fmt.Sprintf("localhost:%d", l.Addr().(*net.TCPAddr).Port), nil
}

// start lance tous les composants et attend qu'ils répondent.
func (c *cluster) start() error {
	for _, p := range c.nodes {
		if err := p.start(); err != nil {
			return err
		}
	}
	if err := c.coord.start(); err != nil {
		return err
	}
	// Le coordinateur doit voir tous les nœuds avant le premier dépôt.
	time.Sleep(1500 * time.Millisecond)
	return nil
}

// stop arrête tous les composants.
func (c *cluster) stop() {
	c.coord.stop()
	for _, p := range c.nodes {
		p.stop()
	}
}

func (p *process) start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd != nil {
		return nil
	}
	logFile, err := os.OpenFile(p.log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	cmd := exec.Command(p.bin)
	cmd.Env = append(os.Environ(), p.env...)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return err
	}
	p.cmd = cmd
	done := make(chan struct{})
	p.done = done
	go func() {
		cmd.Wait()
		logFile.Close()
		p.mu.Lock()
		if p.cmd == cmd {
			p.cmd = nil
		}
		p.mu.Unlock()
		close(done)
	}()
	return waitListening(p.addr, 5*time.Second)
}

func (p *process) stop() {
	p.mu.Lock()
	cmd, done := p.cmd, p.done
	p.cmd = nil
	p.mu.Unlock()
	if cmd != nil {
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			cmd.Process.Kill()
			<-done
		}
	}
}

func (p *process) running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cmd != nil
}

func waitListening(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("%s ne répond pas", addr)
}

// client exécute, au nom d'alice, une commande du vrai client SafeVault et renvoie sa sortie.
func (c *cluster) client(args ...string) (string, error) {
	return c.clientAs("alice", args...)
}

// clientAs exécute une commande du vrai client SafeVault au nom de user, avec sa propre
// clé (dir/<user>.key), et renvoie sa sortie.
func (c *cluster) clientAs(user string, args ...string) (string, error) {
	certs := filepath.Join(c.dir, "certs")
	cmd := exec.Command(filepath.Join(c.dir, "bin", "client"), args...)
	cmd.Dir = c.dir
	cmd.Env = append(os.Environ(),
		"CLIENT_USERNAME="+user,
		"COORD_ADDR="+c.coord.addr,
		"CA_PATH="+filepath.Join(certs, "ca.crt"),
		"KEY_PATH="+c.userKeyPath(user),
	)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// renew demande un renouvellement au coordinateur (SIGUSR1) et attend son résultat
// dans le journal du coordinateur.
func (c *cluster) renew(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	before, _ := os.ReadFile(c.coord.log)
	c.coord.mu.Lock()
	cmd := c.coord.cmd
	c.coord.mu.Unlock()
	if cmd == nil {
		return "", errors.New("le coordinateur est arrêté")
	}
	if err := cmd.Process.Signal(syscall.SIGUSR1); err != nil {
		return "", err
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", errors.New("pas de réponse du coordinateur")
		case <-ticker.C:
		}
		all, _ := os.ReadFile(c.coord.log)
		if len(all) < len(before) {
			continue
		}
		for _, line := range strings.Split(string(all[len(before):]), "\n") {
			if i := strings.Index(line, "renouvellement terminé"); i >= 0 {
				return line[i:], nil
			}
			if i := strings.Index(line, "renouvellement : "); i >= 0 {
				return "", errors.New(shorten(line[i+len("renouvellement : "):]))
			}
		}
	}
}

// shorten garde le début utile d'un message d'erreur gRPC.
func shorten(msg string) string {
	if i := strings.Index(msg, "desc = "); i >= 0 {
		msg = msg[:i] + "…"
	}
	if len(msg) > 160 {
		msg = msg[:160] + "…"
	}
	return msg
}

// nodeShare est la part d'un fichier lue sur le disque d'un nœud, comme la verrait un
// attaquant qui a compromis ce nœud.
type nodeShare struct {
	FileID string
	X      uint32
	Epoch  uint64
	Value  []byte
}

// readShares lit les parts en service sur le disque du nœud x (base SQLite du nœud).
func (c *cluster) readShares(x int) ([]nodeShare, error) {
	path := filepath.Join(c.nodes[x-1].data, "node.db")
	if _, err := os.Stat(path); err != nil {
		return nil, nil
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(2000)")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT file_id, x, epoch, value FROM shares WHERE status = 'committed' ORDER BY file_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var shares []nodeShare
	for rows.Next() {
		var s nodeShare
		if err := rows.Scan(&s.FileID, &s.X, &s.Epoch, &s.Value); err != nil {
			return nil, err
		}
		shares = append(shares, s)
	}
	return shares, rows.Err()
}

// readBlock lit le bloc index du fichier sur le disque du nœud x.
func (c *cluster) readBlock(x int, fileID string, index int) ([]byte, error) {
	return os.ReadFile(filepath.Join(c.nodes[x-1].data, "blocks", fileID, fmt.Sprint(index)))
}

// fingerprint résume une part en quelques caractères pour l'affichage.
func fingerprint(value []byte) string {
	h := sha256.Sum256(value)
	return hex.EncodeToString(h[:4])
}

// userKeyPath renvoie le chemin de la clé privée de l'utilisateur de démo user.
func (c *cluster) userKeyPath(user string) string {
	return filepath.Join(c.dir, user+".key")
}
