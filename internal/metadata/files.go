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

// ConfirmUpload enregistre le manifeste d'un fichier en attente et le marque comme prêt.
// Seul le propriétaire peut confirmer, une seule fois.
func (s *Store) ConfirmUpload(fileID string, ownerID int64, m Manifest) error {
	if !validManifest(m) {
		return ErrInvalidArgument
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var owner int64
	var size uint64
	var status string
	err = tx.QueryRow(`SELECT owner_id, size, status FROM files WHERE file_id = ?`, fileID).
		Scan(&owner, &size, &status)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return ErrNotFound
	case err != nil:
		return err
	case owner != ownerID:
		return ErrNotOwner
	case status != FilePending:
		return ErrConflict
	case m.Size != size:
		// La taille annoncée à CreateFile doit être celle du manifeste.
		return ErrInvalidArgument
	}

	noncePrefix := m.NoncePrefix
	if noncePrefix == nil {
		noncePrefix = []byte{} // un BLOB vide, pas NULL
	}
	_, err = tx.Exec(`INSERT INTO manifests (file_id, block_count, nonce_prefix, size) VALUES (?, ?, ?, ?)`,
		fileID, m.BlockCount, noncePrefix, m.Size)
	if err != nil {
		return err
	}
	for i, h := range m.BlockHashes {
		if _, err := tx.Exec(`INSERT INTO blocks (file_id, idx, sha256) VALUES (?, ?, ?)`, fileID, i, h); err != nil {
			return err
		}
	}
	_, err = tx.Exec(`UPDATE files SET status = ?, confirmed_at = ? WHERE file_id = ?`,
		FileReady, s.now().Unix(), fileID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteStalePending supprime les dépôts jamais confirmés créés avant olderThan, et
// renvoie leur nombre. Sans cela, un dépôt abandonné bloquerait les renouvellements.
// Les blocs et les parts déjà envoyés aux nœuds y restent (pas encore de RPC de suppression).
func (s *Store) DeleteStalePending(olderThan time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM files WHERE status = ? AND created_at < ?`, FilePending, olderThan.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
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
	f, err := scanFile(s.db.QueryRow(`SELECT file_id, owner_id, name, size, t, n, epoch, status, created_at
		FROM files WHERE file_id = ?`, fileID))
	if errors.Is(err, sql.ErrNoRows) {
		return File{}, ErrNotFound
	}
	return f, err
}

// FilesByOwner renvoie les fichiers prêts de l'utilisateur, du plus ancien au plus récent.
func (s *Store) FilesByOwner(ownerID int64) ([]File, error) {
	rows, err := s.db.Query(`SELECT file_id, owner_id, name, size, t, n, epoch, status, created_at
		FROM files WHERE owner_id = ? AND status = ? ORDER BY created_at, file_id`, ownerID, FileReady)
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
	err := row.Scan(&f.ID, &f.OwnerID, &f.Name, &f.Size, &f.T, &f.N, &f.Epoch, &f.Status, &createdAt)
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

// Manifest renvoie le manifeste d'un fichier confirmé.
func (s *Store) Manifest(fileID string) (Manifest, error) {
	m := Manifest{}
	err := s.db.QueryRow(`SELECT block_count, nonce_prefix, size FROM manifests WHERE file_id = ?`, fileID).
		Scan(&m.BlockCount, &m.NoncePrefix, &m.Size)
	if errors.Is(err, sql.ErrNoRows) {
		return Manifest{}, ErrNotFound
	}
	if err != nil {
		return Manifest{}, err
	}

	rows, err := s.db.Query(`SELECT sha256 FROM blocks WHERE file_id = ? ORDER BY idx`, fileID)
	if err != nil {
		return Manifest{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var h []byte
		if err := rows.Scan(&h); err != nil {
			return Manifest{}, err
		}
		m.BlockHashes = append(m.BlockHashes, h)
	}
	return m, rows.Err()
}
