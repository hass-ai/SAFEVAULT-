// Commande demo de SafeVault : lance le vrai système (coordinateur, 5 nœuds, client) en
// local et sert une page web qui montre son état en direct et permet de jouer le
// scénario du sujet et l'attaquant mobile.
//
// Utilisation, depuis la racine du dépôt :
//
//	go run ./cmd/demo            puis ouvrir http://localhost:8080
//
// Variables d'environnement : DEMO_ADDR (défaut localhost:8080).
package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed static
var static embed.FS

const (
	demoN = 5
	demoT = 3
)

// demoUsers sont les utilisateurs de la démo : alice dépose, bob reçoit un partage,
// charlie n'a aucun droit.
var demoUsers = []string{"alice", "bob", "charlie"}

// event est une ligne du journal affiché sur la page.
type event struct {
	Time string `json:"time"`
	Kind string `json:"kind"` // info, ok, err, attack, step
	Text string `json:"text"`
}

// app garde l'état de la démo et exécute les actions demandées par la page.
type app struct {
	c *cluster

	mu          sync.Mutex
	busy        string // action en cours, "" si aucune
	fileID      string
	original    []byte
	events      []event
	stolen      []stolenShare
	compromised map[int]uint64 // nœud → époque à laquelle il a été compromis
	outcome     *attackOutcome
}

func main() {
	addr := os.Getenv("DEMO_ADDR")
	if addr == "" {
		addr = "localhost:8080"
	}

	dir, err := os.MkdirTemp("", "safevault-demo-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	log.Println("compilation et démarrage du système (coordinateur + 5 nœuds)…")
	c, err := newCluster(dir, demoN, demoT)
	if err != nil {
		log.Fatal(err)
	}
	if err := c.start(); err != nil {
		c.stop()
		log.Fatal(err)
	}
	defer c.stop()

	a := &app{c: c, compromised: map[int]uint64{}}
	for _, user := range demoUsers {
		if out, err := c.clientAs(user, "register"); err != nil {
			c.stop()
			log.Fatalf("inscription de %s : %v\n%s", user, err, out)
		}
	}
	a.logf("info", "Système démarré : coordinateur et %d nœuds, seuil t = %d. Utilisateurs inscrits : alice, bob, charlie (chacun sa paire de clés).", demoN, demoT)

	staticFS, _ := fs.Sub(static, "static")
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(staticFS)))
	mux.HandleFunc("/api/state", a.handleState)
	mux.HandleFunc("/api/action", a.handleAction)
	server := &http.Server{Addr: addr, Handler: mux}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Println("arrêt de la démo")
		server.Close()
	}()

	log.Printf("démo prête : ouvrir http://%s", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Print(err)
	}
}

func (a *app) logf(kind, format string, args ...any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event{Time: time.Now().Format("15:04:05"), Kind: kind, Text: fmt.Sprintf(format, args...)})
	if len(a.events) > 200 {
		a.events = a.events[len(a.events)-200:]
	}
}

// ---------- État affiché ----------

type nodeView struct {
	X           int    `json:"x"`
	Name        string `json:"name"`
	Up          bool   `json:"up"`
	Epoch       uint64 `json:"epoch"`
	Print       string `json:"print"`
	Compromised bool   `json:"compromised"`
	StolenAt    uint64 `json:"stolenAt"`
}

type stateView struct {
	Coordinator coordinatorView `json:"coordinator"`
	Nodes       []nodeView      `json:"nodes"`
	Epoch       uint64          `json:"epoch"`
	T           int             `json:"t"`
	File        string          `json:"file"`
	Size        int             `json:"size"`
	Busy        string          `json:"busy"`
	Events      []event         `json:"events"`
	Stolen      []stolenShare   `json:"stolen"`
	Outcome     *attackOutcome  `json:"outcome"`
}

func (a *app) handleState(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	fileID := a.fileID
	view := stateView{
		T: demoT, File: fileID, Size: len(a.original), Busy: a.busy,
		Events: append([]event(nil), a.events...), Stolen: append([]stolenShare(nil), a.stolen...),
		Outcome: a.outcome,
	}
	compromised := make(map[int]uint64, len(a.compromised))
	for k, v := range a.compromised {
		compromised[k] = v
	}
	a.mu.Unlock()

	view.Coordinator, _ = a.c.readCoordinator()
	for x := 1; x <= demoN; x++ {
		nv := nodeView{X: x, Name: nodeName(x), Up: a.c.nodes[x-1].running()}
		if epoch, ok := compromised[x]; ok {
			nv.Compromised, nv.StolenAt = true, epoch
		}
		if fileID != "" {
			shares, _ := a.c.readShares(x)
			for _, s := range shares {
				if s.FileID == fileID {
					nv.Epoch, nv.Print = s.Epoch, fingerprint(s.Value)
				}
			}
		}
		if nv.Epoch > view.Epoch {
			view.Epoch = nv.Epoch
		}
		view.Nodes = append(view.Nodes, nv)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(view)
}

// ---------- Actions ----------

func (a *app) handleAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST attendu", http.StatusMethodNotAllowed)
		return
	}
	action := r.URL.Query().Get("do")
	x, _ := strconv.Atoi(r.URL.Query().Get("x"))

	var run func()
	switch action {
	case "upload":
		run = a.upload
	case "download":
		run = a.download
	case "renew":
		run = func() { a.renew() }
	case "stop", "start":
		if x < 1 || x > demoN {
			http.Error(w, "nœud invalide", http.StatusBadRequest)
			return
		}
		run = func() { a.toggleNode(x, action == "start") }
	case "share":
		run = a.share
	case "download-bob":
		run = func() { a.downloadAs("bob") }
	case "download-charlie":
		run = func() { a.downloadAs("charlie") }
	case "forge":
		run = a.forge
	case "revoke":
		run = a.revoke
	case "attack-norenew":
		run = func() { a.attack(false) }
	case "attack-renew":
		run = func() { a.attack(true) }
	default:
		http.Error(w, "action inconnue", http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	if a.busy != "" {
		a.mu.Unlock()
		http.Error(w, "une action est déjà en cours", http.StatusConflict)
		return
	}
	a.busy = action
	a.mu.Unlock()

	go func() {
		defer func() {
			a.mu.Lock()
			a.busy = ""
			a.mu.Unlock()
		}()
		run()
	}()
	w.WriteHeader(http.StatusAccepted)
}

// demoFile fabrique le fichier confidentiel déposé pendant la démo.
func demoFile() []byte {
	var b bytes.Buffer
	b.WriteString("RAPPORT CONFIDENTIEL — Projet SafeVault\n")
	b.WriteString("Code d'accès au coffre : 7391-ALPHA. Ne pas diffuser.\n\n")
	for i := 1; b.Len() < 200_000; i++ {
		fmt.Fprintf(&b, "Ligne %05d : données sensibles chiffrées côté client puis réparties sur les nœuds.\n", i)
	}
	return b.Bytes()
}

func (a *app) upload() {
	data := demoFile()
	path := filepath.Join(a.c.dir, "rapport-confidentiel.txt")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		a.logf("err", "Écriture du fichier : %v", err)
		return
	}
	a.logf("step", "Dépôt de « rapport-confidentiel.txt » (%d Ko) : chiffrement AES-256-GCM chez le client, clé découpée en %d parts (seuil %d).", len(data)/1000, demoN, demoT)
	out, err := a.c.client("upload", path)
	if err != nil {
		a.logf("err", "Dépôt refusé : %s", lastLine(out))
		return
	}
	fileID := ""
	for _, line := range strings.Split(out, "\n") {
		if id, ok := strings.CutPrefix(strings.TrimSpace(line), "identifiant :"); ok {
			fileID = strings.TrimSpace(id)
		}
	}
	if fileID == "" {
		a.logf("err", "Identifiant du fichier introuvable dans la sortie du client : %s", lastLine(out))
		return
	}
	a.mu.Lock()
	a.fileID, a.original = fileID, data
	a.stolen, a.outcome, a.compromised = nil, nil, map[int]uint64{}
	a.mu.Unlock()
	a.logf("ok", "Fichier déposé (identifiant %s) : chaque nœud a reçu les blocs chiffrés et UNE part de la clé.", fileID)
}

func (a *app) download() {
	a.mu.Lock()
	fileID, original := a.fileID, a.original
	a.mu.Unlock()
	if fileID == "" {
		a.logf("err", "Déposez d'abord un fichier.")
		return
	}
	up := 0
	for _, n := range a.c.nodes {
		if n.running() {
			up++
		}
	}
	a.logf("step", "Récupération : le client demande les parts aux nœuds (%d en ligne sur %d), en reconstruit la clé et déchiffre.", up, demoN)
	path := filepath.Join(a.c.dir, "recupere.txt")
	os.Remove(path)
	out, err := a.c.client("download", fileID, path)
	if err != nil {
		a.logf("err", "Récupération impossible : %s", lastLine(out))
		return
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		a.logf("err", "Le fichier récupéré ne correspond pas à l'original.")
		return
	}
	a.logf("ok", "Fichier récupéré et identique à l'original (%d Ko).", len(got)/1000)
}

// ---------- Partage ----------

// currentFile renvoie le fichier déposé et son contenu d'origine.
func (a *app) currentFile() (string, []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.fileID, a.original
}

func (a *app) share() {
	fileID, _ := a.currentFile()
	if fileID == "" {
		a.logf("err", "Déposez d'abord un fichier.")
		return
	}
	a.logf("step", "Alice partage le fichier avec bob : elle demande la clé publique de bob, en vérifie l'empreinte, signe une autorisation pour cette clé et rechiffre le nom du fichier pour bob.")
	out, err := a.c.clientAs("alice", "share", fileID, "bob")
	if err != nil {
		a.logf("err", "Partage refusé : %s", lastLine(out))
		return
	}
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.Contains(line, "empreinte de la clé"):
			a.logf("info", "%s", line)
		case strings.HasPrefix(line, "✓ "):
			a.logf("ok", "%s", strings.TrimPrefix(line, "✓ "))
		}
	}
}

func (a *app) downloadAs(user string) {
	fileID, original := a.currentFile()
	if fileID == "" {
		a.logf("err", "Déposez d'abord un fichier.")
		return
	}
	a.logf("step", "%s essaie de récupérer le fichier d'alice.", user)
	path := filepath.Join(a.c.dir, "recupere-"+user+".txt")
	os.Remove(path)
	out, err := a.c.clientAs(user, "download", fileID, path)
	if err != nil {
		a.logf("ok", "%s est refusé : %s", user, readableError(lastLine(out)))
		return
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		a.logf("err", "Le fichier récupéré par %s ne correspond pas à l'original.", user)
		return
	}
	a.logf("ok", "%s a récupéré le fichier, identique à l'original : les nœuds ont accepté l'autorisation signée par alice.", user)
}

func (a *app) forge() {
	fileID, _ := a.currentFile()
	if fileID == "" {
		a.logf("err", "Déposez d'abord un fichier.")
		return
	}
	var epoch uint64
	if shares, err := a.c.readShares(1); err == nil {
		for _, sh := range shares {
			if sh.FileID == fileID {
				epoch = sh.Epoch
			}
		}
	}
	a.logf("attack", "COORDINATEUR COMPROMIS : il fabrique une autorisation « au nom d'alice » pour charlie, mais ne peut la signer qu'avec sa propre clé. Charlie la présente aux nœuds.")
	answers, err := a.c.forgedGrantAttempt(fileID, epoch)
	if err != nil {
		a.logf("err", "Tentative impossible : %v", err)
		return
	}
	for _, line := range answers {
		a.logf("attack", "%s", line)
	}
	if allRefused(answers) {
		a.logf("ok", "Tous les nœuds refusent : sans la clé privée d'alice, personne ne peut fabriquer une autorisation, pas même le coordinateur.")
	} else {
		a.logf("err", "Un nœud a accepté l'autorisation fabriquée.")
	}
}

func (a *app) revoke() {
	fileID, _ := a.currentFile()
	if fileID == "" {
		a.logf("err", "Déposez d'abord un fichier.")
		return
	}
	a.logf("step", "Alice retire l'accès de bob : une révocation signée part vers chaque nœud, puis le partage est retiré chez le coordinateur.")
	out, err := a.c.clientAs("alice", "revoke", fileID, "bob")
	if err != nil {
		a.logf("err", "Révocation impossible : %s", lastLine(out))
		return
	}
	for _, line := range strings.Split(out, "\n") {
		if line != "" {
			a.logf("ok", "%s", strings.TrimPrefix(strings.TrimPrefix(line, "✓ "), "! "))
		}
	}
}

func (a *app) renew() bool {
	a.logf("step", "Renouvellement : chaque nœud tire δ avec δ(0) = 0 et envoie δ(j) aux autres ; la clé ne change pas, toutes les parts changent.")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	result, err := a.c.renew(ctx)
	if err != nil {
		a.logf("err", "Renouvellement abandonné, les anciennes parts restent en service : %s", err)
		return false
	}
	a.logf("ok", "Renouvellement réussi : %s. Les anciennes parts ont été effacées.", strings.TrimPrefix(result, "renouvellement terminé : "))
	return true
}

func (a *app) toggleNode(x int, start bool) {
	n := a.c.nodes[x-1]
	if start {
		if err := n.start(); err != nil {
			a.logf("err", "Redémarrage de %s : %v", n.name, err)
			return
		}
		a.logf("ok", "%s redémarré : il retrouve ses données sur son disque.", n.name)
		return
	}
	n.stop()
	a.logf("info", "%s arrêté (panne simulée).", n.name)
}

// attack joue l'attaquant mobile : 2 nœuds compromis par époque (c = t - 1).
func (a *app) attack(withRenewal bool) {
	a.mu.Lock()
	fileID := a.fileID
	a.stolen, a.outcome, a.compromised = nil, nil, map[int]uint64{}
	a.mu.Unlock()
	if fileID == "" {
		a.logf("err", "Déposez d'abord un fichier.")
		return
	}
	for _, n := range a.c.nodes {
		if !n.running() {
			a.logf("err", "Redémarrez tous les nœuds avant l'attaque (le renouvellement en a besoin).")
			return
		}
	}

	if withRenewal {
		a.logf("attack", "ATTAQUE AVEC RENOUVELLEMENT : l'attaquant compromet 2 nœuds par époque (il lui en faut 3 pour la clé).")
	} else {
		a.logf("attack", "ATTAQUE SANS RENOUVELLEMENT : l'attaquant compromet 2 nœuds par époque (il lui en faut 3 pour la clé).")
	}

	block, err := a.c.readBlock(1, fileID, 0)
	if err != nil {
		a.logf("err", "Lecture du bloc chiffré : %v", err)
		return
	}

	a.steal(fileID, 1, 2)
	time.Sleep(1200 * time.Millisecond)
	a.tryAndReport(fileID, block, false)
	time.Sleep(1200 * time.Millisecond)

	if withRenewal {
		if !a.renew() {
			return
		}
	} else {
		a.logf("info", "Aucun renouvellement : les parts restent les mêmes.")
	}
	time.Sleep(1200 * time.Millisecond)

	a.logf("attack", "Les nœuds 1 et 2 sont nettoyés. L'attaquant se déplace vers node-3 et node-4.")
	a.steal(fileID, 3, 4)
	time.Sleep(1200 * time.Millisecond)
	a.tryAndReport(fileID, block, true)
}

// steal copie les parts du fichier sur le disque des nœuds donnés.
func (a *app) steal(fileID string, xs ...int) {
	var names []string
	for _, x := range xs {
		shares, err := a.c.readShares(x)
		if err != nil {
			a.logf("err", "Lecture du disque de %s : %v", nodeName(x), err)
			continue
		}
		for _, s := range shares {
			if s.FileID != fileID {
				continue
			}
			a.mu.Lock()
			a.stolen = append(a.stolen, stolenShare{X: s.X, Epoch: s.Epoch, Print: fingerprint(s.Value), value: s.Value})
			a.compromised[x] = s.Epoch
			a.mu.Unlock()
			names = append(names, fmt.Sprintf("%s (part %s, époque %d)", nodeName(x), fingerprint(s.Value), s.Epoch))
		}
	}
	a.logf("attack", "L'attaquant lit le disque de %s.", strings.Join(names, " et "))
}

func (a *app) tryAndReport(fileID string, block []byte, final bool) {
	a.mu.Lock()
	stolen := append([]stolenShare(nil), a.stolen...)
	a.mu.Unlock()

	if len(stolen) < demoT {
		a.logf("attack", "%d parts volées sur les %d nécessaires : l'attaquant n'apprend rien sur la clé.", len(stolen), demoT)
		return
	}
	outcome := tryDecrypt(stolen, demoT, fileID, block)
	a.mu.Lock()
	a.outcome = &outcome
	a.mu.Unlock()
	if outcome.Success {
		a.logf("err", "CLÉ RETROUVÉE avec %s→ l'attaquant lit le fichier : « %s… »", outcome.Combined, firstLines(outcome.Leaked))
		return
	}
	a.logf("ok", "%d parts volées, %d combinaisons de %d essayées : AUCUNE ne déchiffre le fichier. Les parts d'époques différentes sont incompatibles.", len(stolen), outcome.Tried, demoT)
}

// readableError garde le message utile d'une erreur gRPC affichée par le client.
func readableError(line string) string {
	if i := strings.LastIndex(line, "desc = "); i >= 0 {
		return line[i+len("desc = "):]
	}
	return strings.TrimPrefix(line, "erreur : ")
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

func firstLines(s string) string {
	lines := strings.SplitN(s, "\n", 3)
	if len(lines) > 2 {
		lines = lines[:2]
	}
	return strings.Join(lines, " / ")
}
