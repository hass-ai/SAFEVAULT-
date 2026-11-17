// Package metadata conserve, dans une base SQLite, les métadonnées du coordinateur :
// utilisateurs, défis et sessions, nœuds, époques, fichiers et manifestes.
//
// Le coordinateur ne connaît ni les clés des fichiers ni les parts (garantie G3) :
// aucune table ne peut les contenir. Les défis et les jetons ne sont stockés que
// sous forme d'empreinte SHA-256.
//
// Ce paquet ne fait que du stockage : pas de gRPC, pas de vérification de signature.
package metadata

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound        = errors.New("introuvable")
	ErrAlreadyExists   = errors.New("existe déjà")
	ErrExpired         = errors.New("expiré")
	ErrNotOwner        = errors.New("fichier appartenant à un autre utilisateur")
	ErrConflict        = errors.New("état incompatible avec l'opération")
	ErrInvalidArgument = errors.New("argument invalide")
)

// DBFile est le nom du fichier de la base dans le dossier de données.
const DBFile = "coordinator.db"

// Store donne accès aux métadonnées du coordinateur.
type Store struct {
	db  *sql.DB
	now func() time.Time // horloge, remplaçable dans les tests
}

// Open ouvre (ou crée) la base dans le dossier dir et met le schéma à jour.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// foreign_keys : SQLite ne vérifie les clés étrangères que si on le demande.
	// journal_mode WAL : lectures possibles pendant une écriture, meilleure résistance aux crashs.
	// secure_delete : les empreintes de jetons supprimées sont écrasées dans le fichier.
	dsn := "file:" + filepath.Join(dir, DBFile) +
		"?_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)&_pragma=secure_delete(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// Une seule connexion : les transactions s'exécutent l'une après l'autre,
	// ce qui rend sûrs les « lire puis écrire » faits dans une transaction.
	db.SetMaxOpenConns(1)

	s := &Store{db: db, now: time.Now}
	if err := migrate(db, s.now()); err != nil {
		db.Close()
		return nil, fmt.Errorf("création du schéma : %w", err)
	}
	return s, nil
}

// Close ferme la base.
func (s *Store) Close() error {
	return s.db.Close()
}

// Ping vérifie que la base répond (utilisé par le health check).
func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// digest renvoie l'empreinte SHA-256 d'un défi ou d'un jeton : c'est elle qui est
// stockée, jamais la valeur elle-même.
func digest(secret []byte) []byte {
	sum := sha256.Sum256(secret)
	return sum[:]
}

// unixOrZero convertit une date Unix éventuellement NULL en time.Time.
func unixOrZero(v sql.NullInt64) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return time.Unix(v.Int64, 0)
}
