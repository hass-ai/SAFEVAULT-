// Package storage conserve, sur le disque d'un nœud, les blocs chiffrés des fichiers
// et les parts de clé, avec leur époque.
//
// Organisation de DATA_DIR :
//
//	blocks/<clé>/<index>   un fichier par bloc chiffré
//	node.db                base SQLite : propriétaires, versions, parts, sous-parts
//
// Un fichier a plusieurs versions, chacune avec son propre secret : ses parts et ses blocs
// sont rangés sous la clé de stockage <file_id>_v<version> (voir VersionKey). Les
// propriétaires, les auteurs des versions et les retraits d'accès sont rangés sous
// l'identifiant du fichier.
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

// fileIDPattern limite les identifiants de fichier à des caractères sûrs dans un chemin ;
// keyPattern accepte en plus le suffixe de version des clés de stockage.
var (
	fileIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	keyPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,148}$`)
)

// VersionKey renvoie la clé de stockage de la version version du fichier fileID : les
// parts et les blocs de chaque version sont rangés à part. La version 0 désigne la
// version 1. Le suffixe est découpé à partir de la fin : deux couples (fichier, version)
// différents donnent toujours deux clés différentes.
func VersionKey(fileID string, version uint32) string {
	if version == 0 {
		version = 1
	}
	return fileID + "_v" + strconv.FormatUint(uint64(version), 10)
}

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
);
CREATE TABLE IF NOT EXISTS previous_owners (
	file_id TEXT    NOT NULL,
	owner   BLOB    NOT NULL,
	until   INTEGER NOT NULL,
	PRIMARY KEY (file_id, owner)
);
CREATE TABLE IF NOT EXISTS versions (
	file_id TEXT    NOT NULL,
	version INTEGER NOT NULL,
	author  BLOB    NOT NULL,
	PRIMARY KEY (file_id, version)
);
CREATE TABLE IF NOT EXISTS revocations (
	file_id    TEXT    NOT NULL,
	grantee    BLOB    NOT NULL,
	revoked_at INTEGER NOT NULL,
	PRIMARY KEY (file_id, grantee)
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

// validKey indique si key est une clé de stockage acceptée (identifiant ou version).
func validKey(key string) bool {
	return keyPattern.MatchString(key)
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

// Owners renvoie le propriétaire actuel du fichier (Until = 0), puis ses anciens
// propriétaires avec la date à laquelle ils ont cédé le fichier.
func (s *Store) Owners(fileID string) ([]Owner, error) {
	current, err := s.Owner(fileID)
	if err != nil {
		return nil, err
	}
	owners := []Owner{{Key: current}}
	rows, err := s.db.Query(`SELECT owner, until FROM previous_owners WHERE file_id = ? ORDER BY until`, fileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var o Owner
		if err := rows.Scan(&o.Key, &o.Until); err != nil {
			return nil, err
		}
		owners = append(owners, o)
	}
	return owners, rows.Err()
}

// Owner est une clé propriétaire du fichier. Until vaut 0 pour le propriétaire actuel.
type Owner struct {
	Key   []byte
	Until int64
}

// TransferOwner donne le fichier à newOwner à la date at : l'ancien propriétaire est
// gardé dans l'historique, ses autorisations émises avant at restent valables.
func (s *Store) TransferOwner(fileID string, newOwner []byte, at int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var current []byte
	err = tx.QueryRow(`SELECT owner FROM files WHERE file_id = ?`, fileID).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if slices.Equal(current, newOwner) {
		return nil
	}
	_, err = tx.Exec(`INSERT INTO previous_owners (file_id, owner, until) VALUES (?, ?, ?)
		ON CONFLICT (file_id, owner) DO UPDATE SET until = max(until, excluded.until)`, fileID, current, at)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM previous_owners WHERE file_id = ? AND owner = ?`, fileID, newOwner); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE files SET owner = ? WHERE file_id = ?`, newOwner, fileID); err != nil {
		return err
	}
	return tx.Commit()
}

// ClaimVersion enregistre author comme auteur de la version du fichier, et renvoie
// ErrOwnerMismatch si une autre clé l'a déjà déposée : une version déposée ne peut pas
// être écrasée par quelqu'un d'autre.
func (s *Store) ClaimVersion(fileID string, version uint32, author []byte) error {
	if !ValidFileID(fileID) || version == 0 {
		return ErrInvalidFileID
	}
	var current []byte
	err := s.db.QueryRow(`SELECT author FROM versions WHERE file_id = ? AND version = ?`, fileID, version).
		Scan(&current)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = s.db.Exec(`INSERT INTO versions (file_id, version, author) VALUES (?, ?, ?)`, fileID, version, author)
		return err
	case err != nil:
		return err
	case !slices.Equal(current, author):
		return ErrOwnerMismatch
	}
	return nil
}

// VersionAuthor renvoie la clé qui a déposé la version du fichier.
func (s *Store) VersionAuthor(fileID string, version uint32) ([]byte, error) {
	var author []byte
	err := s.db.QueryRow(`SELECT author FROM versions WHERE file_id = ? AND version = ?`, fileID, version).
		Scan(&author)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return author, err
}

// DeleteFile efface tout ce que le nœud garde d'un fichier : parts et blocs de toutes les
// versions, propriétaires, auteurs et retraits d'accès. Les parts sont effacées avec
// secure_delete, les blocs sont supprimés du disque.
func (s *Store) DeleteFile(fileID string) error {
	if !ValidFileID(fileID) {
		return ErrInvalidFileID
	}
	rows, err := s.db.Query(`SELECT version FROM versions WHERE file_id = ?`, fileID)
	if err != nil {
		return err
	}
	var keys []string
	for rows.Next() {
		var v uint32
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		keys = append(keys, VersionKey(fileID, v))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, key := range keys {
		if _, err := tx.Exec(`DELETE FROM shares WHERE file_id = ?`, key); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM sub_shares WHERE file_id = ?`, key); err != nil {
			return err
		}
	}
	for _, table := range []string{"versions", "previous_owners", "revocations", "files"} {
		if _, err := tx.Exec(`DELETE FROM `+table+` WHERE file_id = ?`, fileID); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	for _, key := range keys {
		if err := os.RemoveAll(filepath.Join(s.dir, "blocks", key)); err != nil {
			return err
		}
	}
	return nil
}

// PutRevocation enregistre le retrait de l'accès de grantee au fichier à la date
// revokedAt (secondes Unix). Seule la date la plus récente est gardée.
func (s *Store) PutRevocation(fileID string, grantee []byte, revokedAt int64) error {
	if !ValidFileID(fileID) {
		return ErrInvalidFileID
	}
	_, err := s.db.Exec(`INSERT INTO revocations (file_id, grantee, revoked_at) VALUES (?, ?, ?)
		ON CONFLICT (file_id, grantee) DO UPDATE SET revoked_at = max(revoked_at, excluded.revoked_at)`,
		fileID, grantee, revokedAt)
	return err
}

// RevokedAt renvoie la date du dernier retrait d'accès de grantee au fichier, si elle existe.
func (s *Store) RevokedAt(fileID string, grantee []byte) (int64, bool, error) {
	var revokedAt int64
	err := s.db.QueryRow(`SELECT revoked_at FROM revocations WHERE file_id = ? AND grantee = ?`,
		fileID, grantee).Scan(&revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return revokedAt, err == nil, err
}

// PutShare enregistre la part déposée par le client comme part en service,
// et supprime les parts des autres époques de ce fichier.
func (s *Store) PutShare(fileID string, share Share) error {
	if !validKey(fileID) {
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

// FileShare est la part en service d'un fichier.
type FileShare struct {
	FileID string
	Share  Share
}

// CommittedShares renvoie les parts en service de tous les fichiers, triées par fichier.
func (s *Store) CommittedShares() ([]FileShare, error) {
	rows, err := s.db.Query(`SELECT file_id, x, value, epoch FROM shares WHERE status = ? ORDER BY file_id`,
		StatusCommitted)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var shares []FileShare
	for rows.Next() {
		var fs FileShare
		if err := rows.Scan(&fs.FileID, &fs.Share.X, &fs.Share.Value, &fs.Share.Epoch); err != nil {
			return nil, err
		}
		shares = append(shares, fs)
	}
	return shares, rows.Err()
}

// HasPending indique si des parts en attente existent pour l'époque epoch.
func (s *Store) HasPending(epoch uint64) (bool, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM shares WHERE epoch = ? AND status = ?`,
		epoch, StatusPending).Scan(&count)
	return count > 0, err
}

// PutPendingShare enregistre la nouvelle part calculée pendant un renouvellement,
// sans toucher à la part en service.
func (s *Store) PutPendingShare(fileID string, share Share) error {
	if !validKey(fileID) {
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
		if !validKey(sub.FileID) {
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
	if !validKey(fileID) {
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
	if !validKey(fileID) {
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
	if !validKey(fileID) {
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
