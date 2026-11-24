package metadata

import (
	"database/sql"
	"errors"
)

// État d'une époque (voir le schéma).
const (
	EpochPreparing  = "preparing"
	EpochCommitting = "committing"
	EpochCommitted  = "committed"
	EpochAborted    = "aborted"
)

// Epoch est une époque de renouvellement.
type Epoch struct {
	Number uint64
	State  string
}

// ActiveEpoch renvoie le renouvellement en cours (preparing ou committing), s'il y en a un.
func (s *Store) ActiveEpoch() (Epoch, bool, error) {
	e := Epoch{}
	err := s.db.QueryRow(`SELECT number, state FROM epochs WHERE state IN (?, ?)`,
		EpochPreparing, EpochCommitting).Scan(&e.Number, &e.State)
	if errors.Is(err, sql.ErrNoRows) {
		return Epoch{}, false, nil
	}
	if err != nil {
		return Epoch{}, false, err
	}
	return e, true, nil
}

// BeginEpoch enregistre le début d'un renouvellement et renvoie le numéro de la nouvelle
// époque. Refusé (ErrConflict) si un renouvellement est déjà en cours, ou si un dépôt
// n'est pas encore confirmé : ses parts arrivent peut-être encore sur les nœuds, et il
// ne faut pas qu'un même fichier ait des parts de deux époques.
func (s *Store) BeginEpoch() (uint64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var busy bool
	err = tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM epochs WHERE state IN (?, ?))
		OR EXISTS (SELECT 1 FROM versions WHERE status = ?)`,
		EpochPreparing, EpochCommitting, FilePending).Scan(&busy)
	if err != nil {
		return 0, err
	}
	if busy {
		return 0, ErrConflict
	}

	// Un numéro neuf même après un abandon : une époque abandonnée n'est jamais réutilisée.
	var next uint64
	if err := tx.QueryRow(`SELECT MAX(number) + 1 FROM epochs`).Scan(&next); err != nil {
		return 0, err
	}
	_, err = tx.Exec(`INSERT INTO epochs (number, state, started_at) VALUES (?, ?, ?)`,
		next, EpochPreparing, s.now().Unix())
	if err != nil {
		return 0, err
	}
	return next, tx.Commit()
}

// DecideCommit enregistre la décision de valider l'époque : à partir de là, il n'y a
// plus de retour possible, même après un crash (le coordinateur renverra COMMIT).
func (s *Store) DecideCommit(epoch uint64) error {
	return s.transition(epoch, EpochPreparing, EpochCommitting, false)
}

// FinishCommit marque l'époque comme validée par tous les nœuds, et rattache à cette
// époque les parts de tous les fichiers confirmés.
func (s *Store) FinishCommit(epoch uint64) error {
	return s.transition(epoch, EpochCommitting, EpochCommitted, true)
}

// AbortEpoch abandonne un renouvellement qui n'a pas encore été décidé.
func (s *Store) AbortEpoch(epoch uint64) error {
	return s.transition(epoch, EpochPreparing, EpochAborted, false)
}

// transition fait passer l'époque de l'état from à l'état to, ou renvoie ErrConflict.
func (s *Store) transition(epoch uint64, from, to string, updateFiles bool) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	finished := sql.NullInt64{}
	if to == EpochCommitted || to == EpochAborted {
		finished = sql.NullInt64{Int64: s.now().Unix(), Valid: true}
	}
	res, err := tx.Exec(`UPDATE epochs SET state = ?, finished_at = ? WHERE number = ? AND state = ?`,
		to, finished, epoch, from)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrConflict
	}
	if updateFiles {
		if _, err := tx.Exec(`UPDATE files SET epoch = ? WHERE status = ?`, epoch, FileReady); err != nil {
			return err
		}
	}
	return tx.Commit()
}
