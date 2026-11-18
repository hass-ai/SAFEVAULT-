package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"safevault/internal/metadata"
)

// participant est un nœud vu par le gestionnaire d'époques. Le coordinateur ne fait que
// signaler les étapes : il n'envoie ni ne reçoit aucune part ni sous-part (G3).
// En production, c'est le service Epoch du nœud (voir participants.go).
type participant interface {
	X() uint32
	// Prepare demande au nœud de calculer et garder EN ATTENTE ses parts de l'époque,
	// en conservant les parts en service.
	Prepare(ctx context.Context, epoch uint64) error
	// Commit demande au nœud de basculer sur les parts de l'époque et d'effacer les anciennes.
	Commit(ctx context.Context, epoch uint64) error
	// Abort demande au nœud d'effacer les parts en attente de l'époque.
	Abort(ctx context.Context, epoch uint64) error
}

// epochManager conduit le renouvellement des parts en deux phases. Chaque étape est
// enregistrée dans la base AVANT d'être envoyée aux nœuds, pour qu'un redémarrage
// après un crash sache toujours quoi faire (G6) :
//
//	crash en preparing  -> rien n'a été décidé : ABORT partout (abandon présumé) ;
//	crash en committing -> la décision est prise : COMMIT partout, puis committed.
type epochManager struct {
	store        *metadata.Store
	participants []participant
	stepTimeout  time.Duration
}

func newEpochManager(store *metadata.Store, participants []participant) *epochManager {
	return &epochManager{store: store, participants: participants, stepTimeout: 30 * time.Second}
}

// errRenewalBusy signale qu'un renouvellement ne peut pas commencer maintenant.
var errRenewalBusy = errors.New("renouvellement impossible pour l'instant (déjà en cours ou dépôt non confirmé)")

// refresh fait passer le système à l'époque suivante et renvoie son numéro.
func (m *epochManager) refresh(ctx context.Context) (uint64, error) {
	epoch, err := m.store.BeginEpoch()
	if errors.Is(err, metadata.ErrConflict) {
		return 0, errRenewalBusy
	}
	if err != nil {
		return 0, err
	}
	log.Printf("époque %d : préparation", epoch)

	// Phase 1 : tous les nœuds doivent préparer, sinon on abandonne.
	if err := m.all(ctx, epoch, participant.Prepare); err != nil {
		log.Printf("époque %d : préparation refusée (%v), abandon", epoch, err)
		return 0, errors.Join(fmt.Errorf("préparation : %w", err), m.abort(ctx, epoch))
	}

	// Point de non-retour, enregistré avant le premier COMMIT.
	if err := m.store.DecideCommit(epoch); err != nil {
		return 0, err
	}
	return epoch, m.commit(ctx, epoch)
}

// recover termine un renouvellement interrompu par un arrêt du coordinateur.
func (m *epochManager) recover(ctx context.Context) error {
	active, ok, err := m.store.ActiveEpoch()
	if err != nil || !ok {
		return err
	}
	switch active.State {
	case metadata.EpochPreparing:
		log.Printf("époque %d : reprise après arrêt pendant la préparation, abandon", active.Number)
		return m.abort(ctx, active.Number)
	case metadata.EpochCommitting:
		log.Printf("époque %d : reprise après arrêt pendant la validation, validation", active.Number)
		return m.commit(ctx, active.Number)
	}
	return nil
}

// commit envoie COMMIT à tous les nœuds puis enregistre l'époque comme validée.
// Si un nœud ne répond pas, l'époque reste en committing : recover() réessaiera.
func (m *epochManager) commit(ctx context.Context, epoch uint64) error {
	if err := m.all(ctx, epoch, participant.Commit); err != nil {
		return fmt.Errorf("époque %d décidée mais pas encore validée partout : %w", epoch, err)
	}
	if err := m.store.FinishCommit(epoch); err != nil {
		return err
	}
	log.Printf("époque %d : validée", epoch)
	return nil
}

// abort envoie ABORT à tous les nœuds puis enregistre l'abandon. L'abandon est
// enregistré même si un nœud ne répond pas : ses parts en attente ne seront jamais
// validées, et AbortEpoch côté nœud les effacera à son retour.
func (m *epochManager) abort(ctx context.Context, epoch uint64) error {
	err := m.all(ctx, epoch, participant.Abort)
	if err != nil {
		log.Printf("époque %d : abandon non confirmé par tous les nœuds : %v", epoch, err)
	}
	return m.store.AbortEpoch(epoch)
}

// all appelle step sur tous les nœuds EN PARALLÈLE et renvoie leurs erreurs, avec le x
// de chaque nœud. Le parallélisme est nécessaire pour Prepare : chaque nœud attend les
// sous-parts de tous les autres avant de répondre.
func (m *epochManager) all(ctx context.Context, epoch uint64,
	step func(participant, context.Context, uint64) error) error {

	errs := make([]error, len(m.participants))
	var wg sync.WaitGroup
	for i, p := range m.participants {
		wg.Go(func() {
			stepCtx, cancel := context.WithTimeout(ctx, m.stepTimeout)
			defer cancel()
			if err := step(p, stepCtx, epoch); err != nil {
				errs[i] = fmt.Errorf("nœud x=%d : %w", p.X(), err)
			}
		})
	}
	wg.Wait()
	return errors.Join(errs...)
}
