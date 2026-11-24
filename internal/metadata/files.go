package metadata

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"
)

// Statut d'un fichier : "pending" entre CreateFile et ConfirmUpload, "ready" ensuite.
const (
	FilePending = "pending"
	FileReady   = "ready"
)

// File décrit un fichier. Name est opaque pour le coordinateur (voir le schéma).
type File struct {
	ID        string
	OwnerID   int64
	Name      []byte
	Size      uint64
	T, N      uint32
	Epoch     uint64 // époque des parts en service
	Status    string
	CreatedAt time.Time
	// CurrentVersion est la dernière version confirmée (1 pour un nouveau fichier).
	CurrentVersion uint32
}

// Version décrit une version confirmée d'un fichier.
type Version struct {
	Number    uint32
	AuthorID  int64
	Author    string // nom de l'auteur
	Size      uint64
	CreatedAt time.Time
}

// Manifest contient les informations publiques nécessaires pour relire un fichier.
type Manifest struct {
	BlockCount  uint32
	BlockHashes [][]byte // SHA-256 de chaque bloc chiffré, dans l'ordre
	NoncePrefix []byte
	Size        uint64
}

// CreateFile enregistre un nouveau fichier en attente de confirmation, avec les nœuds
// qui vont recevoir ses parts. Les champs Status et CreatedAt de f sont ignorés.
func (s *Store) CreateFile(f File, nodeXs []uint32) error {
	if f.ID == "" || f.T < 2 || f.T > f.N || len(nodeXs) != int(f.N) {
		return ErrInvalidArgument
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var exists bool
	if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM files WHERE file_id = ?)`, f.ID).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return ErrAlreadyExists
	}
	// Pas de nouveau dépôt pendant un renouvellement : ses parts seraient d'une époque
	// que les nœuds sont en train de remplacer.
	var renewing bool
	err = tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM epochs WHERE state IN (?, ?))`,
		EpochPreparing, EpochCommitting).Scan(&renewing)
	if err != nil {
		return err
	}
	if renewing {
		return ErrConflict
	}

	_, err = tx.Exec(`INSERT INTO files (file_id, owner_id, name, size, t, n, epoch, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.OwnerID, f.Name, f.Size, f.T, f.N, f.Epoch, FilePending, s.now().Unix())
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO versions (file_id, version, author_id, size, status, created_at)
		VALUES (?, 1, ?, ?, ?, ?)`, f.ID, f.OwnerID, f.Size, FilePending, s.now().Unix())
	if err != nil {
		return err
	}
	seen := make(map[uint32]bool)
	for _, x := range nodeXs {
		if seen[x] {
			return ErrInvalidArgument // deux parts sur le même nœud
		}
		seen[x] = true
		var known bool
		if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM nodes WHERE x = ?)`, x).Scan(&known); err != nil {
			return err
		}
		if !known {
			return ErrNotFound
		}
		if _, err := tx.Exec(`INSERT INTO file_nodes (file_id, node_x) VALUES (?, ?)`, f.ID, x); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// renewing indique si un renouvellement des parts est en cours.
func renewing(tx *sql.Tx) (bool, error) {
	var busy bool
	err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM epochs WHERE state IN (?, ?))`,
		EpochPreparing, EpochCommitting).Scan(&busy)
	return busy, err
}

// CreateVersion commence une nouvelle version d'un fichier confirmé, déposée par authorID
// (le contrôle des droits est fait par l'appelant), et renvoie son numéro. Refusé
// (ErrConflict) pendant un renouvellement, comme CreateFile.
func (s *Store) CreateVersion(fileID string, authorID int64, size uint64) (uint32, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var status string
	err = tx.QueryRow(`SELECT status FROM files WHERE file_id = ?`, fileID).Scan(&status)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0, ErrNotFound
	case err != nil:
		return 0, err
	case status != FileReady:
		return 0, ErrConflict
	}
	busy, err := renewing(tx)
	if err != nil {
		return 0, err
	}
	if busy {
		return 0, ErrConflict
	}

	var next uint32
	if err := tx.QueryRow(`SELECT MAX(version) + 1 FROM versions WHERE file_id = ?`, fileID).Scan(&next); err != nil {
		return 0, err
	}
	_, err = tx.Exec(`INSERT INTO versions (file_id, version, author_id, size, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, fileID, next, authorID, size, FilePending, s.now().Unix())
	if err != nil {
		return 0, err
	}
	return next, tx.Commit()
}

// ConfirmUpload enregistre le manifeste d'une version en attente et la marque comme prête ;
// elle devient la version actuelle du fichier. Seul l'auteur de la version peut la
// confirmer, une seule fois. La version 0 désigne la version 1.
func (s *Store) ConfirmUpload(fileID string, version uint32, authorID int64, m Manifest) error {
	if !validManifest(m) {
		return ErrInvalidArgument
	}
	version = max(version, 1)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var author int64
	var size uint64
	var status string
	err = tx.QueryRow(`SELECT author_id, size, status FROM versions WHERE file_id = ? AND version = ?`,
		fileID, version).Scan(&author, &size, &status)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return ErrNotFound
	case err != nil:
		return err
	case author != authorID:
		return ErrNotOwner
	case status != FilePending:
		return ErrConflict
	case m.Size != size:
		// La taille annoncée au début du dépôt doit être celle du manifeste.
		return ErrInvalidArgument
	}

	noncePrefix := m.NoncePrefix
	if noncePrefix == nil {
		noncePrefix = []byte{} // un BLOB vide, pas NULL
	}
	now := s.now().Unix()
	_, err = tx.Exec(`UPDATE versions SET status = ?, block_count = ?, nonce_prefix = ?, created_at = ?
		WHERE file_id = ? AND version = ?`, FileReady, m.BlockCount, noncePrefix, now, fileID, version)
	if err != nil {
		return err
	}
	for i, h := range m.BlockHashes {
		_, err := tx.Exec(`INSERT INTO version_blocks (file_id, version, idx, sha256) VALUES (?, ?, ?, ?)`,
			fileID, version, i, h)
		if err != nil {
			return err
		}
	}
	if version == 1 {
		_, err = tx.Exec(`UPDATE files SET status = ?, confirmed_at = ? WHERE file_id = ?`, FileReady, now, fileID)
		if err != nil {
			return err
		}
	}
	_, err = tx.Exec(`UPDATE files SET current_version = ?, size = ? WHERE file_id = ? AND current_version <= ?`,
		version, size, fileID, version)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteStalePending supprime les dépôts et les versions jamais confirmés commencés avant
// olderThan, et renvoie leur nombre. Sans cela, un dépôt abandonné bloquerait les
// renouvellements. Les parts et blocs déjà envoyés aux nœuds y restent.
func (s *Store) DeleteStalePending(olderThan time.Time) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`DELETE FROM files WHERE status = ? AND created_at < ?`, FilePending, olderThan.Unix())
	if err != nil {
		return 0, err
	}
	files, _ := res.RowsAffected()
	res, err = tx.Exec(`DELETE FROM versions WHERE status = ? AND created_at < ?`, FilePending, olderThan.Unix())
	if err != nil {
		return 0, err
	}
	versions, _ := res.RowsAffected()
	return files + versions, tx.Commit()
}

// SetFileName remplace le nom chiffré du fichier pour son propriétaire.
func (s *Store) SetFileName(fileID string, name []byte) error {
	if len(name) == 0 {
		return ErrInvalidArgument
	}
	return expectOne(s.db.Exec(`UPDATE files SET name = ? WHERE file_id = ?`, name, fileID))
}

// DeleteFile supprime un fichier et tout ce qui s'y rattache (versions, partages, retraits).
func (s *Store) DeleteFile(fileID string) error {
	return expectOne(s.db.Exec(`DELETE FROM files WHERE file_id = ?`, fileID))
}

// PreviousOwner est un ancien propriétaire d'un fichier.
type PreviousOwner struct {
	PublicKey []byte
	Until     int64
}

// TransferFile donne le fichier à newOwnerID, à la date at. La clé de l'ancien
// propriétaire est gardée avec cette date ; name est le nom chiffré pour le nouveau
// propriétaire. Un partage qu'il avait reçu disparaît : il a désormais tous les droits.
func (s *Store) TransferFile(fileID string, newOwnerID int64, at int64, name []byte) error {
	if len(name) == 0 {
		return ErrInvalidArgument
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var oldKey []byte
	err = tx.QueryRow(`SELECT u.public_key FROM files f JOIN users u ON u.id = f.owner_id WHERE f.file_id = ?`,
		fileID).Scan(&oldKey)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO previous_owners (file_id, public_key, until) VALUES (?, ?, ?)
		ON CONFLICT (file_id, public_key) DO UPDATE SET until = max(until, excluded.until)`, fileID, oldKey, at)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`DELETE FROM previous_owners WHERE file_id = ?
		AND public_key = (SELECT public_key FROM users WHERE id = ?)`, fileID, newOwnerID)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE files SET owner_id = ?, name = ? WHERE file_id = ?`, newOwnerID, name, fileID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM grants WHERE file_id = ? AND grantee_id = ?`, fileID, newOwnerID); err != nil {
		return err
	}
	return tx.Commit()
}

// PreviousOwners renvoie les anciens propriétaires du fichier.
func (s *Store) PreviousOwners(fileID string) ([]PreviousOwner, error) {
	rows, err := s.db.Query(`SELECT public_key, until FROM previous_owners WHERE file_id = ? ORDER BY until`, fileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var owners []PreviousOwner
	for rows.Next() {
		var o PreviousOwner
		if err := rows.Scan(&o.PublicKey, &o.Until); err != nil {
			return nil, err
		}
		owners = append(owners, o)
	}
	return owners, rows.Err()
}

// Versions renvoie les versions confirmées du fichier, de la plus ancienne à la plus récente.
func (s *Store) Versions(fileID string) ([]Version, error) {
	rows, err := s.db.Query(`SELECT v.version, v.author_id, u.username, v.size, v.created_at
		FROM versions v JOIN users u ON u.id = v.author_id
		WHERE v.file_id = ? AND v.status = ? ORDER BY v.version`, fileID, FileReady)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var versions []Version
	for rows.Next() {
		var v Version
		var createdAt int64
		if err := rows.Scan(&v.Number, &v.AuthorID, &v.Author, &v.Size, &createdAt); err != nil {
			return nil, err
		}
		v.CreatedAt = time.Unix(createdAt, 0)
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

// expectOne renvoie ErrNotFound si la requête n'a touché aucune ligne.
func expectOne(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// validManifest vérifie la cohérence interne d'un manifeste.
func validManifest(m Manifest) bool {
	// Le préfixe de nonce peut être vide : la version actuelle de internal/crypto dérive
	// les nonces de l'identifiant du fichier et n'en envoie plus.
	if int(m.BlockCount) != len(m.BlockHashes) {
		return false
	}
	for _, h := range m.BlockHashes {
		if len(h) != sha256.Size {
			return false
		}
	}
	return true
}

// File renvoie le fichier d'identifiant fileID.
func (s *Store) File(fileID string) (File, error) {
	f, err := scanFile(s.db.QueryRow(`SELECT file_id, owner_id, name, size, t, n, epoch, status, created_at,
		current_version FROM files WHERE file_id = ?`, fileID))
	if errors.Is(err, sql.ErrNoRows) {
		return File{}, ErrNotFound
	}
	return f, err
}

// FilesByOwner renvoie les fichiers prêts de l'utilisateur, du plus ancien au plus récent.
func (s *Store) FilesByOwner(ownerID int64) ([]File, error) {
	rows, err := s.db.Query(`SELECT file_id, owner_id, name, size, t, n, epoch, status, created_at,
		current_version FROM files WHERE owner_id = ? AND status = ? ORDER BY created_at, file_id`, ownerID, FileReady)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []File
	for rows.Next() {
		f, err := scanFile(rows)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	return files, rows.Err()
}

// scanner est commun à *sql.Row et *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanFile(row scanner) (File, error) {
	f := File{}
	var createdAt int64
	err := row.Scan(&f.ID, &f.OwnerID, &f.Name, &f.Size, &f.T, &f.N, &f.Epoch, &f.Status, &createdAt,
		&f.CurrentVersion)
	f.CreatedAt = time.Unix(createdAt, 0)
	return f, err
}

// FileNodes renvoie les nœuds qui détiennent une part du fichier, par x croissant.
func (s *Store) FileNodes(fileID string) ([]Node, error) {
	rows, err := s.db.Query(`SELECT n.x, n.address, n.status, n.last_seen
		FROM file_nodes fn JOIN nodes n ON n.x = fn.node_x
		WHERE fn.file_id = ? ORDER BY n.x`, fileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}

// Manifest renvoie le manifeste d'une version confirmée du fichier (0 = version actuelle)
// et sa description.
func (s *Store) Manifest(fileID string, version uint32) (Manifest, Version, error) {
	if version == 0 {
		if err := s.db.QueryRow(`SELECT current_version FROM files WHERE file_id = ?`, fileID).Scan(&version); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return Manifest{}, Version{}, ErrNotFound
			}
			return Manifest{}, Version{}, err
		}
	}
	m := Manifest{}
	v := Version{Number: version}
	var createdAt int64
	err := s.db.QueryRow(`SELECT v.block_count, v.nonce_prefix, v.size, v.author_id, u.username, v.created_at
		FROM versions v JOIN users u ON u.id = v.author_id
		WHERE v.file_id = ? AND v.version = ? AND v.status = ?`, fileID, version, FileReady).
		Scan(&m.BlockCount, &m.NoncePrefix, &m.Size, &v.AuthorID, &v.Author, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Manifest{}, Version{}, ErrNotFound
	}
	if err != nil {
		return Manifest{}, Version{}, err
	}
	v.Size, v.CreatedAt = m.Size, time.Unix(createdAt, 0)

	rows, err := s.db.Query(`SELECT sha256 FROM version_blocks WHERE file_id = ? AND version = ? ORDER BY idx`,
		fileID, version)
	if err != nil {
		return Manifest{}, Version{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var h []byte
		if err := rows.Scan(&h); err != nil {
			return Manifest{}, Version{}, err
		}
		m.BlockHashes = append(m.BlockHashes, h)
	}
	return m, v, rows.Err()
}
