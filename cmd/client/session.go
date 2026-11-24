package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcmd "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"safevault/internal/access"
	"safevault/internal/crypto"
	pb "safevault/proto"
)

// sessionTTL est la durée de validité d'une session, fixée par le coordinateur.
const sessionTTL = 12 * time.Hour

// session est la connexion ouverte par « login », gardée dans un fichier lisible par le
// seul utilisateur. Elle ne contient qu'un jeton du coordinateur, jamais la clé privée.
type session struct {
	Username    string `json:"username"`
	Token       string `json:"token"`
	ExpiresAt   int64  `json:"expires_at"`
	Coordinator string `json:"coordinator"`
}

var errNoSession = errors.New("aucune session ouverte : connectez-vous avec « client login <utilisateur> »")

func loadSession(cfg Config) (*session, error) {
	data, err := os.ReadFile(cfg.sessionPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, errNoSession
	}
	if err != nil {
		return nil, err
	}
	s := &session{}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("fichier de session illisible (%s) : reconnectez-vous", cfg.sessionPath())
	}
	if time.Now().Unix() >= s.ExpiresAt {
		return nil, errors.New("session expirée : reconnectez-vous avec « client login »")
	}
	return s, nil
}

func saveSession(cfg Config, s *session) error {
	if err := os.MkdirAll(filepath.Dir(cfg.sessionPath()), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cfg.sessionPath(), data, 0o600)
}

// app est une commande en cours : utilisateur connecté, sa clé et la connexion au coordinateur.
type app struct {
	cfg    Config
	user   string
	key    ed25519.PrivateKey
	coord  pb.CoordinatorClient
	conn   *grpc.ClientConn
	ctx    context.Context // porte le jeton de session
	cancel context.CancelFunc
}

// open prépare une commande qui demande d'être connecté. Sans session, et seulement si
// CLIENT_USERNAME est défini (scripts), une connexion est ouverte automatiquement.
func open(cfg Config, timeout time.Duration) (*app, error) {
	s, err := loadSession(cfg)
	if errors.Is(err, errNoSession) && cfg.Username != "" {
		s, err = login(cfg, cfg.Username)
	}
	if err != nil {
		return nil, err
	}
	key, err := loadKey(cfg.keyPath(s.Username))
	if err != nil {
		return nil, fmt.Errorf("clé de %s : %w", s.Username, err)
	}
	coord, conn, err := connectCoordinator(cfg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	ctx = grpcmd.AppendToOutgoingContext(ctx, "authorization", "Bearer "+s.Token)
	return &app{cfg: cfg, user: s.Username, key: key, coord: coord, conn: conn, ctx: ctx, cancel: cancel}, nil
}

func (a *app) close() {
	a.cancel()
	a.conn.Close()
}

func (a *app) publicKey() ed25519.PublicKey { return a.key.Public().(ed25519.PublicKey) }

// login ouvre une session : le coordinateur envoie un défi, la clé privée le signe.
func login(cfg Config, username string) (*session, error) {
	key, err := loadKey(cfg.keyPath(username))
	if err != nil {
		return nil, fmt.Errorf("clé de %s introuvable (%s) : inscrivez-vous d'abord avec « client register %s »",
			username, cfg.keyPath(username), username)
	}
	coord, conn, err := connectCoordinator(cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	challenge, err := coord.GetChallenge(ctx, &pb.GetChallengeRequest{Username: username})
	if err != nil {
		return nil, err
	}
	resp, err := coord.Login(ctx, &pb.LoginRequest{
		Username:  username,
		Challenge: challenge.Challenge,
		Signature: sign(key, "safevault/login/v1", challenge.Challenge),
	})
	if err != nil {
		return nil, fmt.Errorf("connexion refusée : %w", err)
	}
	s := &session{Username: username, Token: resp.Token, ExpiresAt: time.Now().Add(sessionTTL).Unix(),
		Coordinator: cfg.CoordinatorAddr}
	return s, saveSession(cfg, s)
}

// runRegister crée la clé de l'utilisateur, l'inscrit auprès du coordinateur et ouvre une session.
func runRegister(cfg Config, username string) error {
	if username == "" {
		username = cfg.Username
	}
	if username == "" {
		return errors.New("indiquez un nom d'utilisateur : client register <utilisateur>")
	}
	path := cfg.keyPath(username)
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("une clé existe déjà pour %s (%s)", username, path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	privateKey, err := generateKey(path)
	if err != nil {
		return err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)

	coord, conn, err := connectCoordinator(cfg)
	if err != nil {
		os.Remove(path)
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	message := append([]byte(username), publicKey...)
	_, err = coord.Register(ctx, &pb.RegisterRequest{
		Username:  username,
		PublicKey: publicKey,
		Signature: sign(privateKey, "safevault/register/v1", message),
	})
	if err != nil {
		os.Remove(path) // inscription refusée : on ne garde pas une clé inutile
		return fmt.Errorf("inscription refusée : %w", err)
	}
	success("Inscription réussie : %s", bold(username))
	info("  clé privée : %s (à garder, elle ne quitte jamais ce poste)", path)
	info("  empreinte  : %s", access.Fingerprint(publicKey))
	if _, err := login(cfg, username); err != nil {
		return err
	}
	success("Session ouverte.")
	return nil
}

func runLogin(cfg Config, username string) error {
	if username == "" {
		username = cfg.Username
	}
	if username == "" {
		return errors.New("indiquez un nom d'utilisateur : client login <utilisateur>")
	}
	s, err := login(cfg, username)
	if err != nil {
		return err
	}
	success("Connecté en tant que %s (session valable jusqu'au %s).", bold(s.Username), humanDate(s.ExpiresAt))
	return nil
}

func runLogout(cfg Config) error {
	err := os.Remove(cfg.sessionPath())
	if errors.Is(err, os.ErrNotExist) {
		info("Aucune session ouverte.")
		return nil
	}
	if err != nil {
		return err
	}
	success("Session fermée.")
	return nil
}

// runWhoami affiche l'utilisateur connecté et l'empreinte de sa clé publique, à comparer
// avec celle que voit la personne qui lui partage un fichier.
func runWhoami(cfg Config) error {
	s, err := loadSession(cfg)
	if errors.Is(err, errNoSession) && cfg.Username != "" {
		s = &session{Username: cfg.Username}
	} else if err != nil {
		return err
	}
	key, err := loadKey(cfg.keyPath(s.Username))
	if err != nil {
		return err
	}
	fmt.Printf("Utilisateur  %s\n", bold(s.Username))
	fmt.Printf("Empreinte    %s\n", access.Fingerprint(key.Public().(ed25519.PublicKey)))
	if s.ExpiresAt != 0 {
		fmt.Printf("Session      jusqu'au %s\n", humanDate(s.ExpiresAt))
	}
	return nil
}

// openName déchiffre le nom d'un fichier pour l'utilisateur. Les noms sont chiffrés pour
// sa clé publique ; les fichiers déposés avant les versions utilisaient une clé dérivée
// de la clé privée, encore acceptée.
func (a *app) openName(sealed []byte) string {
	if name, err := crypto.OpenNameFrom(a.key, sealed); err == nil {
		return name
	}
	if namesKey, err := crypto.NamesKey(a.key); err == nil {
		defer clear(namesKey)
		if name, err := crypto.OpenName(namesKey, sealed); err == nil {
			return name
		}
	}
	return "(nom illisible)"
}

// resolve trouve un fichier accessible à partir de son identifiant, du début de son
// identifiant (au moins 4 caractères) ou de son nom.
func (a *app) resolve(ref string) (*pb.FileInfo, string, error) {
	resp, err := a.coord.ListFiles(a.ctx, &pb.ListFilesRequest{})
	if err != nil {
		return nil, "", err
	}
	var matches []*pb.FileInfo
	for _, f := range resp.Files {
		if f.FileId == ref {
			return f, a.openName(f.EncryptedName), nil
		}
	}
	for _, f := range resp.Files {
		if (len(ref) >= 4 && strings.HasPrefix(f.FileId, ref)) || a.openName(f.EncryptedName) == ref {
			matches = append(matches, f)
		}
	}
	switch len(matches) {
	case 0:
		return nil, "", fmt.Errorf("aucun fichier « %s » parmi vos fichiers (voir « client ls »)", ref)
	case 1:
		return matches[0], a.openName(matches[0].EncryptedName), nil
	}
	var ids []string
	for _, f := range matches {
		ids = append(ids, f.FileId)
	}
	return nil, "", fmt.Errorf("« %s » désigne plusieurs fichiers, précisez l'identifiant : %s", ref, strings.Join(ids, ", "))
}

// describe rend une erreur gRPC lisible.
func describe(err error) string {
	st, ok := status.FromError(err)
	if !ok {
		// Erreur enveloppée : on garde le préfixe et on simplifie la partie gRPC.
		msg := err.Error()
		if i := strings.Index(msg, "rpc error: code = "); i >= 0 {
			if j := strings.Index(msg[i:], "desc = "); j >= 0 {
				return msg[:i] + msg[i+j+len("desc = "):]
			}
		}
		return msg
	}
	switch st.Code() {
	case codes.Unauthenticated:
		return st.Message() + " : reconnectez-vous avec « client login »"
	case codes.Unavailable:
		return "service injoignable : " + st.Message()
	}
	return st.Message()
}
