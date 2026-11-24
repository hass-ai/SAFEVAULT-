package metadata

import (
	"database/sql"
	"errors"
	"strings"
)

// Group est un groupe d'utilisateurs, propre à son créateur.
type Group struct {
	Name    string
	Members []User
}

// CreateGroup crée le groupe name de l'utilisateur ownerID.
func (s *Store) CreateGroup(ownerID int64, name string) error {
	_, err := s.db.Exec(`INSERT INTO user_groups (owner_id, name, created_at) VALUES (?, ?, ?)`,
		ownerID, name, s.now().Unix())
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrAlreadyExists
	}
	return err
}

// DeleteGroup supprime le groupe name de l'utilisateur ownerID.
func (s *Store) DeleteGroup(ownerID int64, name string) error {
	return expectOne(s.db.Exec(`DELETE FROM user_groups WHERE owner_id = ? AND name = ?`, ownerID, name))
}

func (s *Store) groupID(ownerID int64, name string) (int64, error) {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM user_groups WHERE owner_id = ? AND name = ?`, ownerID, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}

// AddGroupMember ajoute userID au groupe name de ownerID.
func (s *Store) AddGroupMember(ownerID int64, name string, userID int64) error {
	id, err := s.groupID(ownerID, name)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)`, id, userID)
	return err
}

// RemoveGroupMember retire userID du groupe name de ownerID.
func (s *Store) RemoveGroupMember(ownerID int64, name string, userID int64) error {
	id, err := s.groupID(ownerID, name)
	if err != nil {
		return err
	}
	return expectOne(s.db.Exec(`DELETE FROM group_members WHERE group_id = ? AND user_id = ?`, id, userID))
}

// Groups renvoie les groupes de ownerID avec leurs membres, par nom.
func (s *Store) Groups(ownerID int64) ([]Group, error) {
	rows, err := s.db.Query(`SELECT g.name, u.id, u.username, u.public_key
		FROM user_groups g LEFT JOIN group_members m ON m.group_id = g.id LEFT JOIN users u ON u.id = m.user_id
		WHERE g.owner_id = ? ORDER BY g.name, u.username`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var groups []Group
	for rows.Next() {
		var name string
		var id sql.NullInt64
		var username sql.NullString
		var key []byte
		if err := rows.Scan(&name, &id, &username, &key); err != nil {
			return nil, err
		}
		if len(groups) == 0 || groups[len(groups)-1].Name != name {
			groups = append(groups, Group{Name: name})
		}
		if id.Valid {
			g := &groups[len(groups)-1]
			g.Members = append(g.Members, User{ID: id.Int64, Username: username.String, PublicKey: key})
		}
	}
	return groups, rows.Err()
}
