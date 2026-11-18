package metadata

import (
	"crypto/ed25519"
	"database/sql"
	"errors"
	"time"
)

// User est un utilisateur inscrit auprès du coordinateur.
type User struct {
	ID        int64
	Username  string
	PublicKey []byte // clé publique Ed25519
}

// CreateUser inscrit un utilisateur et renvoie son identifiant interne.
// Renvoie ErrAlreadyExists si le nom ou la clé publique est déjà utilisé.
func (s *Store) CreateUser(username string, publicKey []byte) (int64, error) {
	if username == "" || len(publicKey) != ed25519.PublicKeySize {
		return 0, ErrInvalidArgument
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// Vérification explicite plutôt que d'interpréter le code d'erreur du pilote ;
	// la contrainte UNIQUE reste en filet de sécurité.
	var exists bool
	err = tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM users WHERE username = ? OR public_key = ?)`,
		username, publicKey).Scan(&exists)
	if err != nil {
		return 0, err
	}
	if exists {
		return 0, ErrAlreadyExists
	}

	res, err := tx.Exec(`INSERT INTO users (username, public_key, created_at) VALUES (?, ?, ?)`,
		username, publicKey, s.now().Unix())
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// UserByName renvoie l'utilisateur de nom username.
func (s *Store) UserByName(username string) (User, error) {
	u := User{}
	err := s.db.QueryRow(`SELECT id, username, public_key FROM users WHERE username = ?`, username).
		Scan(&u.ID, &u.Username, &u.PublicKey)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// PutChallenge enregistre un défi de connexion pour l'utilisateur, valable jusqu'à expiresAt.
// Seule son empreinte est stockée.
func (s *Store) PutChallenge(userID int64, challenge []byte, expiresAt time.Time) error {
	if len(challenge) == 0 {
		return ErrInvalidArgument
	}
	_, err := s.db.Exec(`INSERT INTO challenges (hash, user_id, expires_at) VALUES (?, ?, ?)`,
		digest(challenge), userID, expiresAt.Unix())
	return err
}

// ConsumeChallenge supprime le défi de l'utilisateur et vérifie qu'il n'a pas expiré.
// Le défi est supprimé dans tous les cas : il ne peut servir qu'une fois.
// Renvoie ErrNotFound si le défi est inconnu (ou déjà utilisé), ErrExpired s'il a expiré.
func (s *Store) ConsumeChallenge(userID int64, challenge []byte) error {
	var expiresAt int64
	err := s.db.QueryRow(`DELETE FROM challenges WHERE hash = ? AND user_id = ? RETURNING expires_at`,
		digest(challenge), userID).Scan(&expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if s.now().Unix() >= expiresAt {
		return ErrExpired
	}
	return nil
}

// PutSession enregistre un jeton de session pour l'utilisateur, valable jusqu'à expiresAt.
// Seule son empreinte est stockée.
func (s *Store) PutSession(token []byte, userID int64, expiresAt time.Time) error {
	if len(token) == 0 {
		return ErrInvalidArgument
	}
	_, err := s.db.Exec(`INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		digest(token), userID, s.now().Unix(), expiresAt.Unix())
	return err
}

// SessionUser renvoie l'utilisateur du jeton de session.
// Renvoie ErrNotFound si le jeton est inconnu, ErrExpired s'il a expiré.
func (s *Store) SessionUser(token []byte) (int64, error) {
	var userID, expiresAt int64
	err := s.db.QueryRow(`SELECT user_id, expires_at FROM sessions WHERE token_hash = ?`, digest(token)).
		Scan(&userID, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	if s.now().Unix() >= expiresAt {
		return 0, ErrExpired
	}
	return userID, nil
}

// DeleteSession supprime le jeton de session (déconnexion ou révocation).
func (s *Store) DeleteSession(token []byte) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, digest(token))
	return err
}

// PurgeExpired supprime les défis et les sessions expirés et renvoie le nombre de lignes supprimées.
func (s *Store) PurgeExpired() (int64, error) {
	now := s.now().Unix()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var total int64
	for _, query := range []string{
		`DELETE FROM challenges WHERE expires_at <= ?`,
		`DELETE FROM sessions WHERE expires_at <= ?`,
	} {
		res, err := tx.Exec(query, now)
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, tx.Commit()
}
