package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"safevault/internal/access"
	pb "safevault/proto"
)

// coordinatorRow est une ligne de la table des fichiers du coordinateur, telle qu'un
// attaquant qui aurait copié sa base la verrait.
type coordinatorRow struct {
	FileID string `json:"fileId"`
	Owner  string `json:"owner"`
	Name   string `json:"name"` // début du nom stocké, en hexadécimal
	Size   int64  `json:"size"`
}

type coordinatorView struct {
	Files  []coordinatorRow `json:"files"`
	Shares []string         `json:"shares"` // destinataires des partages en cours
}

// readCoordinator lit la base du coordinateur en lecture seule.
func (c *cluster) readCoordinator() (coordinatorView, error) {
	var view coordinatorView
	path := filepath.Join(c.coord.data, "coordinator.db")
	if _, err := os.Stat(path); err != nil {
		return view, nil
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(2000)")
	if err != nil {
		return view, err
	}
	defer db.Close()

	rows, err := db.Query(`SELECT f.file_id, u.username, f.name, f.size FROM files f
		JOIN users u ON u.id = f.owner_id ORDER BY f.created_at`)
	if err != nil {
		return view, err
	}
	for rows.Next() {
		var r coordinatorRow
		var name []byte
		if err := rows.Scan(&r.FileID, &r.Owner, &name, &r.Size); err != nil {
			rows.Close()
			return view, err
		}
		if len(name) > 12 {
			name = name[:12]
		}
		r.Name = hex.EncodeToString(name) + "…"
		view.Files = append(view.Files, r)
	}
	rows.Close()

	rows, err = db.Query(`SELECT u.username FROM grants g JOIN users u ON u.id = g.grantee_id ORDER BY u.username`)
	if err != nil {
		return view, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return view, err
		}
		view.Shares = append(view.Shares, name)
	}
	return view, rows.Err()
}

// userPublicKey lit la clé publique d'un utilisateur dans la base du coordinateur.
func (c *cluster) userPublicKey(user string) (ed25519.PublicKey, error) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(c.coord.data, "coordinator.db")+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var key []byte
	err = db.QueryRow(`SELECT public_key FROM users WHERE username = ?`, user).Scan(&key)
	return ed25519.PublicKey(key), err
}

// forgedGrantAttempt joue un coordinateur compromis qui veut donner à charlie l'accès au
// fichier d'alice : il fabrique une autorisation « au nom d'alice », mais il ne peut la
// signer qu'avec sa propre clé. Charlie la présente aux nœuds. Renvoie la réponse de
// chaque nœud.
func (c *cluster) forgedGrantAttempt(fileID string, epoch uint64) ([]string, error) {
	charlieKey, err := os.ReadFile(c.userKeyPath("charlie"))
	if err != nil || len(charlieKey) != ed25519.PrivateKeySize {
		return nil, errors.New("clé de charlie introuvable")
	}
	charlie := ed25519.PrivateKey(charlieKey)
	alicePub, err := c.userPublicKey("alice")
	if err != nil {
		return nil, err
	}
	_, coordinatorKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	forged := access.NewGrant(coordinatorKey, fileID, charlie.Public().(ed25519.PublicKey), access.Read, now, now.Add(time.Hour), nil)
	forged.IssuerPublicKey = alicePub // il prétend que l'autorisation vient d'alice

	caPEM, err := os.ReadFile(filepath.Join(c.dir, "certs", "ca.crt"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	creds := credentials.NewTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13})

	var answers []string
	for i, n := range c.nodes {
		x := uint32(i + 1)
		if !n.running() {
			answers = append(answers, fmt.Sprintf("%s : arrêté", n.name))
			continue
		}
		conn, err := grpc.NewClient(n.addr, grpc.WithTransportCredentials(creds))
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err = pb.NewNodeClient(conn).GetShare(ctx, &pb.GetShareRequest{
			FileId: fileID, Epoch: epoch, Proof: signedProof(charlie, "safevault/getshare/v1", x, fileID, epoch), Grant: forged,
		})
		cancel()
		conn.Close()
		if err == nil {
			answers = append(answers, n.name+" : PART DONNÉE")
		} else {
			answers = append(answers, n.name+" : refusé ("+status.Convert(err).Message()+")")
		}
	}
	return answers, nil
}

// signedProof construit la preuve d'identité d'une requête, comme le client SafeVault.
func signedProof(key ed25519.PrivateKey, label string, x uint32, fileID string, epoch uint64) *pb.Proof {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	timestamp := time.Now().Unix()
	message := fmt.Sprintf("%d|%s|%d|%d|%x", x, fileID, epoch, timestamp, nonce)
	data := append([]byte(label), 0)
	data = append(data, message...)
	return &pb.Proof{
		PublicKey: key.Public().(ed25519.PublicKey),
		Timestamp: timestamp,
		Nonce:     nonce,
		Signature: ed25519.Sign(key, data),
	}
}

// allRefused indique si tous les nœuds en ligne ont refusé.
func allRefused(answers []string) bool {
	for _, a := range answers {
		if strings.Contains(a, "PART DONNÉE") {
			return false
		}
	}
	return true
}
