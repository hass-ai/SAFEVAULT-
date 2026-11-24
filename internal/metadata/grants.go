package metadata

import (
	"database/sql"
	"errors"
	"time"
)

// UserByID renvoie l'utilisateur d'identifiant id.
func (s *Store) UserByID(id int64) (User, error) {
	u := User{}
	err := s.db.QueryRow(`SELECT id, username, public_key FROM users WHERE id = ?`, id).
		Scan(&u.ID, &u.Username, &u.PublicKey)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// PutGrant enregistre (ou remplace) le partage du fichier avec granteeID. signedGrant est
// l'autorisation signée par le propriétaire, opaque pour le stockage ; encryptedName est
// le nom du fichier chiffré pour le destinataire. Le fichier doit être prêt et appartenir
// à ownerID.
func (s *Store) PutGrant(fileID string, ownerID, granteeID int64, signedGrant, encryptedName []byte) error {
	if len(signedGrant) == 0 || len(encryptedName) == 0 || ownerID == granteeID {
		return ErrInvalidArgument
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var owner int64
	var status string
	err = tx.QueryRow(`SELECT owner_id, status FROM files WHERE file_id = ?`, fileID).Scan(&owner, &status)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return ErrNotFound
	case err != nil:
		return err
	case owner != ownerID:
		return ErrNotOwner
	case status != FileReady:
		return ErrConflict
	}

	_, err = tx.Exec(`INSERT INTO grants (file_id, grantee_id, signed_grant, encrypted_name, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (file_id, grantee_id) DO UPDATE
		SET signed_grant = excluded.signed_grant, encrypted_name = excluded.encrypted_name,
		    created_at = excluded.created_at`,
		fileID, granteeID, signedGrant, encryptedName, s.now().Unix())
	if err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteGrant retire le partage du fichier avec granteeID. Seul le propriétaire peut le faire.
func (s *Store) DeleteGrant(fileID string, ownerID, granteeID int64) error {
	res, err := s.db.Exec(`DELETE FROM grants WHERE file_id = ? AND grantee_id = ?
		AND file_id IN (SELECT file_id FROM files WHERE owner_id = ?)`, fileID, granteeID, ownerID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Grant renvoie l'autorisation signée qui permet à granteeID de lire le fichier.
func (s *Store) Grant(fileID string, granteeID int64) ([]byte, error) {
	var signedGrant []byte
	err := s.db.QueryRow(`SELECT signed_grant FROM grants WHERE file_id = ? AND grantee_id = ?`,
		fileID, granteeID).Scan(&signedGrant)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return signedGrant, err
}

// SharedFile est un fichier partagé avec un utilisateur.
type SharedFile struct {
	File
	Owner         string // nom du propriétaire
	EncryptedName []byte // nom chiffré pour le destinataire
}

// FilesSharedWith renvoie les fichiers prêts partagés avec granteeID.
func (s *Store) FilesSharedWith(granteeID int64) ([]SharedFile, error) {
	rows, err := s.db.Query(`SELECT f.file_id, f.owner_id, f.name, f.size, f.t, f.n, f.epoch, f.status,
		f.created_at, u.username, g.encrypted_name
		FROM grants g JOIN files f ON f.file_id = g.file_id JOIN users u ON u.id = f.owner_id
		WHERE g.grantee_id = ? AND f.status = ? ORDER BY f.created_at, f.file_id`, granteeID, FileReady)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []SharedFile
	for rows.Next() {
		var sf SharedFile
		var createdAt int64
		err := rows.Scan(&sf.ID, &sf.OwnerID, &sf.Name, &sf.Size, &sf.T, &sf.N, &sf.Epoch, &sf.Status,
			&createdAt, &sf.Owner, &sf.EncryptedName)
		if err != nil {
			return nil, err
		}
		sf.CreatedAt = time.Unix(createdAt, 0)
		files = append(files, sf)
	}
	return files, rows.Err()
}
