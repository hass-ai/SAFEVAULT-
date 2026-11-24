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

// UserByKey renvoie l'utilisateur de clé publique publicKey.
func (s *Store) UserByKey(publicKey []byte) (User, error) {
	u := User{}
	err := s.db.QueryRow(`SELECT id, username, public_key FROM users WHERE public_key = ?`, publicKey).
		Scan(&u.ID, &u.Username, &u.PublicKey)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// PutGrant enregistre (ou remplace) le partage du fichier avec granteeID. signedGrant est
// l'autorisation signée, opaque pour le stockage (le coordinateur la vérifie avant) ;
// encryptedName est le nom du fichier chiffré pour le destinataire. Le fichier doit être
// prêt, et le destinataire ne peut pas en être le propriétaire.
func (s *Store) PutGrant(fileID string, granteeID int64, signedGrant, encryptedName []byte) error {
	if len(signedGrant) == 0 || len(encryptedName) == 0 {
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
	case owner == granteeID:
		return ErrInvalidArgument
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

// SetGrantName remplace le nom chiffré du fichier pour le destinataire granteeID.
func (s *Store) SetGrantName(fileID string, granteeID int64, name []byte) error {
	if len(name) == 0 {
		return ErrInvalidArgument
	}
	return expectOne(s.db.Exec(`UPDATE grants SET encrypted_name = ? WHERE file_id = ? AND grantee_id = ?`,
		name, fileID, granteeID))
}

// DeleteGrant retire le partage du fichier avec granteeID (le contrôle des droits est fait
// par l'appelant).
func (s *Store) DeleteGrant(fileID string, granteeID int64) error {
	return expectOne(s.db.Exec(`DELETE FROM grants WHERE file_id = ? AND grantee_id = ?`, fileID, granteeID))
}

// Grant renvoie l'autorisation signée de granteeID sur le fichier.
func (s *Store) Grant(fileID string, granteeID int64) ([]byte, error) {
	var signedGrant []byte
	err := s.db.QueryRow(`SELECT signed_grant FROM grants WHERE file_id = ? AND grantee_id = ?`,
		fileID, granteeID).Scan(&signedGrant)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return signedGrant, err
}

// GrantRow est un partage d'un fichier.
type GrantRow struct {
	Grantee     User
	SignedGrant []byte
	CreatedAt   time.Time
}

// GrantsOf renvoie les partages du fichier, par nom de destinataire.
func (s *Store) GrantsOf(fileID string) ([]GrantRow, error) {
	rows, err := s.db.Query(`SELECT u.id, u.username, u.public_key, g.signed_grant, g.created_at
		FROM grants g JOIN users u ON u.id = g.grantee_id
		WHERE g.file_id = ? ORDER BY u.username`, fileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var grants []GrantRow
	for rows.Next() {
		var g GrantRow
		var createdAt int64
		if err := rows.Scan(&g.Grantee.ID, &g.Grantee.Username, &g.Grantee.PublicKey, &g.SignedGrant, &createdAt); err != nil {
			return nil, err
		}
		g.CreatedAt = time.Unix(createdAt, 0)
		grants = append(grants, g)
	}
	return grants, rows.Err()
}

// SharedFile est un fichier partagé avec un utilisateur.
type SharedFile struct {
	File
	Owner         string // nom du propriétaire
	EncryptedName []byte // nom chiffré pour le destinataire
	SignedGrant   []byte // autorisation du destinataire
}

// FilesSharedWith renvoie les fichiers prêts partagés avec granteeID.
func (s *Store) FilesSharedWith(granteeID int64) ([]SharedFile, error) {
	rows, err := s.db.Query(`SELECT f.file_id, f.owner_id, f.name, f.size, f.t, f.n, f.epoch, f.status,
		f.created_at, f.current_version, u.username, g.encrypted_name, g.signed_grant
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
			&createdAt, &sf.CurrentVersion, &sf.Owner, &sf.EncryptedName, &sf.SignedGrant)
		if err != nil {
			return nil, err
		}
		sf.CreatedAt = time.Unix(createdAt, 0)
		files = append(files, sf)
	}
	return files, rows.Err()
}

// PutRevocation enregistre le retrait de l'accès de la clé granteeKey au fichier, à la
// date revokedAt. Seule la date la plus récente est gardée.
func (s *Store) PutRevocation(fileID string, granteeKey []byte, revokedAt int64) error {
	_, err := s.db.Exec(`INSERT INTO revocations (file_id, public_key, revoked_at) VALUES (?, ?, ?)
		ON CONFLICT (file_id, public_key) DO UPDATE SET revoked_at = max(revoked_at, excluded.revoked_at)`,
		fileID, granteeKey, revokedAt)
	return err
}

// RevokedAt renvoie la date du dernier retrait d'accès de granteeKey au fichier, s'il existe.
func (s *Store) RevokedAt(fileID string, granteeKey []byte) (int64, bool, error) {
	var at int64
	err := s.db.QueryRow(`SELECT revoked_at FROM revocations WHERE file_id = ? AND public_key = ?`,
		fileID, granteeKey).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return at, err == nil, err
}
