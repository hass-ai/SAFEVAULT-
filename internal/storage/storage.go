// Package storage conserve, sur le disque d'un nœud, les blocs chiffrés des fichiers
// et les parts de clé, avec leur époque.
//
// Organisation de DATA_DIR :
//
//	blocks/<file_id>/<index>   un fichier par bloc chiffré
//	node.db                    base SQLite : propriétaires, parts, sous-parts
package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound      = errors.New("introuvable")
	ErrOwnerMismatch = errors.New("fichier appartenant à une autre clé")
	ErrInvalidFileID = errors.New("identifiant de fichier invalide")
)

// Statut d'une part : une part "pending" a été calculée pendant un renouvellement
// mais n'est pas encore validée ; une part "committed" est la part en service.
const (
	StatusPending   = "pending"
	StatusCommitted = "committed"
)

// Share est la part de la clé d'un fichier détenue par ce nœud.
type Share struct {
	X     uint32
	Value []byte
	Epoch uint64
}

// SubShare est une sous-part reçue d'un autre nœud pendant un renouvellement.
type SubShare struct {
	FileID string
	FromX  uint32
	Value  []byte
}

// fileIDPattern limite les identifiants de fichier à des caractères sûrs dans un chemin.
var fileIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// Store donne accès aux blocs et aux parts stockés par le nœud.
type Store struct {
	dir string
	db  *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS files (
	file_id TEXT PRIMARY KEY,
	owner   BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS shares (
	file_id TEXT    NOT NULL,
	epoch   INTEGER NOT NULL,
	x       INTEGER NOT NULL,
	value   BLOB    NOT NULL,
	status  TEXT    NOT NULL CHECK (status IN ('pending', 'committed')),
	PRIMARY KEY (file_id, epoch)
);
CREATE TABLE IF NOT EXISTS sub_shares (
	target_epoch INTEGER NOT NULL,
	from_x       INTEGER NOT NULL,
	file_id      TEXT    NOT NULL,
	value        BLOB    NOT NULL,
	PRIMARY KEY (target_epoch, from_x, file_id)
);`

// Open ouvre (ou crée) le stockage dans le dossier dir.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "blocks"), 0o700); err != nil {
		return nil, err
	}
	// secure_delete écrase les données supprimées : une ancienne part ne doit pas
	// rester lisible dans le fichier de la base après un renouvellement.
	dsn := "file:" + filepath.Join(dir, "node.db") +
		"?_pragma=secure_delete(ON)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("création du schéma : %w", err)
	}
	return &Store{dir: dir, db: db}, nil
}

// Close ferme la base.
func (s *Store) Close() error {
	return s.db.Close()
}

// ValidFileID indique si fileID est un identifiant de fichier accepté.
func ValidFileID(fileID string) bool {
	return fileIDPattern.MatchString(fileID)
}

// ClaimOwner enregistre owner comme propriétaire du fichier s'il n'en a pas encore,
// et renvoie ErrOwnerMismatch si le fichier appartient déjà à une autre clé.
func (s *Store) ClaimOwner(fileID string, owner []byte) error {
	if !ValidFileID(fileID) {
		return ErrInvalidFileID
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var current []byte
	err = tx.QueryRow(`SELECT owner FROM files WHERE file_id = ?`, fileID).Scan(&current)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.Exec(`INSERT INTO files (file_id, owner) VALUES (?, ?)`, fileID, owner); err != nil {
			return err
		}
	case err != nil:
		return err
	case !slices.Equal(current, owner):
		return ErrOwnerMismatch
	}
	return tx.Commit()
}

// Owner renvoie la clé publique propriétaire du fichier.
func (s *Store) Owner(fileID string) ([]byte, error) {
	var owner []byte
	err := s.db.QueryRow(`SELECT owner FROM files WHERE file_id = ?`, fileID).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return owner, err
}

// PutShare enregistre la part déposée par le client comme part en service,
// et supprime les parts des autres époques de ce fichier.
func (s *Store) PutShare(fileID string, share Share) error {
	if !ValidFileID(fileID) {
		return ErrInvalidFileID
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM shares WHERE file_id = ?`, fileID); err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO shares (file_id, epoch, x, value, status) VALUES (?, ?, ?, ?, ?)`,
		fileID, share.Epoch, share.X, share.Value, StatusCommitted)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Share renvoie la part en service du fichier.
func (s *Store) Share(fileID string) (Share, error) {
	share := Share{}
	err := s.db.QueryRow(
		`SELECT x, value, epoch FROM shares WHERE file_id = ? AND status = ?`,
		fileID, StatusCommitted,
	).Scan(&share.X, &share.Value, &share.Epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return Share{}, ErrNotFound
	}
	return share, err
}

// PutPendingShare enregistre la nouvelle part calculée pendant un renouvellement,
// sans toucher à la part en service.
func (s *Store) PutPendingShare(fileID string, share Share) error {
	if !ValidFileID(fileID) {
		return ErrInvalidFileID
	}
	_, err := s.db.Exec(`INSERT OR REPLACE INTO shares (file_id, epoch, x, value, status) VALUES (?, ?, ?, ?, ?)`,
		fileID, share.Epoch, share.X, share.Value, StatusPending)
	return err
}

// CommitEpoch valide les parts en attente de l'époque epoch : elles deviennent les parts
// en service et les parts plus anciennes des mêmes fichiers sont effacées.
func (s *Store) CommitEpoch(epoch uint64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`DELETE FROM shares WHERE epoch < ? AND file_id IN
		(SELECT file_id FROM shares WHERE epoch = ? AND status = ?)`, epoch, epoch, StatusPending)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE shares SET status = ? WHERE epoch = ? AND status = ?`,
		StatusCommitted, epoch, StatusPending)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sub_shares WHERE target_epoch <= ?`, epoch); err != nil {
		return err
	}
	return tx.Commit()
}

// AbortEpoch abandonne le renouvellement vers l'époque epoch : les parts en attente
// et les sous-parts reçues sont effacées, les parts en service restent inchangées.
func (s *Store) AbortEpoch(epoch uint64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM shares WHERE epoch = ? AND status = ?`, epoch, StatusPending); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sub_shares WHERE target_epoch = ?`, epoch); err != nil {
		return err
	}
	return tx.Commit()
}

// PutSubShares enregistre les sous-parts envoyées par le nœud fromX pour l'époque targetEpoch.
func (s *Store) PutSubShares(targetEpoch uint64, fromX uint32, subShares []SubShare) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, sub := range subShares {
		if !ValidFileID(sub.FileID) {
			return ErrInvalidFileID
		}
		_, err := tx.Exec(`INSERT OR REPLACE INTO sub_shares (target_epoch, from_x, file_id, value) VALUES (?, ?, ?, ?)`,
			targetEpoch, fromX, sub.FileID, sub.Value)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SubShares renvoie les sous-parts reçues pour l'époque targetEpoch.
func (s *Store) SubShares(targetEpoch uint64) ([]SubShare, error) {
	rows, err := s.db.Query(`SELECT file_id, from_x, value FROM sub_shares WHERE target_epoch = ?
		ORDER BY file_id, from_x`, targetEpoch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subShares []SubShare
	for rows.Next() {
		var sub SubShare
		if err := rows.Scan(&sub.FileID, &sub.FromX, &sub.Value); err != nil {
			return nil, err
		}
		subShares = append(subShares, sub)
	}
	return subShares, rows.Err()
}

// PutBlock écrit le bloc index du fichier. L'écriture passe par un fichier temporaire
// renommé à la fin : un bloc à moitié écrit n'est jamais visible.
func (s *Store) PutBlock(fileID string, index uint32, data io.Reader) error {
	if !ValidFileID(fileID) {
		return ErrInvalidFileID
	}
	dir := filepath.Join(s.dir, "blocks", fileID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := io.Copy(tmp, data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, strconv.FormatUint(uint64(index), 10)))
}

// OpenBlock ouvre le bloc index du fichier en lecture.
func (s *Store) OpenBlock(fileID string, index uint32) (io.ReadCloser, error) {
	if !ValidFileID(fileID) {
		return nil, ErrInvalidFileID
	}
	f, err := os.Open(filepath.Join(s.dir, "blocks", fileID, strconv.FormatUint(uint64(index), 10)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return f, err
}

// BlockIndexes renvoie, dans l'ordre, les numéros des blocs stockés pour le fichier.
func (s *Store) BlockIndexes(fileID string) ([]uint32, error) {
	if !ValidFileID(fileID) {
		return nil, ErrInvalidFileID
	}
	entries, err := os.ReadDir(filepath.Join(s.dir, "blocks", fileID))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	var indexes []uint32
	for _, e := range entries {
		index, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue // fichier temporaire ou étranger
		}
		indexes = append(indexes, uint32(index))
	}
	slices.Sort(indexes)
	return indexes, nil
}
