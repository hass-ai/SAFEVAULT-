package metadata

import (
	"database/sql"
	"time"
)

// État d'un nœud vu par le coordinateur.
const (
	NodeUnknown = "unknown"
	NodeUp      = "up"
	NodeDown    = "down"
)

// Node est un nœud de stockage connu du coordinateur.
type Node struct {
	X        uint32 // abscisse dans le partage de Shamir (NODE_X du nœud)
	Address  string // "hôte:port"
	Status   string
	LastSeen time.Time // zéro si le nœud n'a jamais répondu
}

// UpsertNode enregistre le nœud x à l'adresse address, ou met son adresse à jour.
func (s *Store) UpsertNode(x uint32, address string) error {
	if x == 0 || address == "" {
		return ErrInvalidArgument
	}
	_, err := s.db.Exec(`INSERT INTO nodes (x, address) VALUES (?, ?)
		ON CONFLICT (x) DO UPDATE SET address = excluded.address`, x, address)
	return err
}

// SetNodeStatus change l'état du nœud x et la date de sa dernière réponse.
func (s *Store) SetNodeStatus(x uint32, status string, lastSeen time.Time) error {
	if status != NodeUnknown && status != NodeUp && status != NodeDown {
		return ErrInvalidArgument
	}
	var seen sql.NullInt64
	if !lastSeen.IsZero() {
		seen = sql.NullInt64{Int64: lastSeen.Unix(), Valid: true}
	}
	res, err := s.db.Exec(`UPDATE nodes SET status = ?, last_seen = ? WHERE x = ?`, status, seen, x)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Nodes renvoie tous les nœuds connus, par x croissant.
func (s *Store) Nodes() ([]Node, error) {
	rows, err := s.db.Query(`SELECT x, address, status, last_seen FROM nodes ORDER BY x`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}

func scanNodes(rows *sql.Rows) ([]Node, error) {
	var nodes []Node
	for rows.Next() {
		var n Node
		var seen sql.NullInt64
		if err := rows.Scan(&n.X, &n.Address, &n.Status, &seen); err != nil {
			return nil, err
		}
		n.LastSeen = unixOrZero(seen)
		nodes = append(nodes, n)
	}
	return nodes, rows.Err()
}

// CurrentEpoch renvoie la dernière époque validée (committed).
func (s *Store) CurrentEpoch() (uint64, error) {
	var epoch uint64
	err := s.db.QueryRow(`SELECT MAX(number) FROM epochs WHERE state = 'committed'`).Scan(&epoch)
	return epoch, err
}
