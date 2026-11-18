package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"time"

	"filippo.io/edwards25519"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"safevault/internal/shamir"
	"safevault/internal/storage"
	pb "safevault/proto"
)

// subSharePollInterval est la période à laquelle Prepare regarde si toutes les sous-parts
// des autres participants sont arrivées.
const subSharePollInterval = 20 * time.Millisecond

// Prepare réalise la phase 1 du renouvellement vers l'époque req.Epoch :
//
//  1. pour chaque fichier, tirer δ de degré t-1 avec δ(0) = 0 (internal/shamir) ;
//  2. garder δ(x) pour soi et envoyer δ(j) au participant j (service Renewal, mTLS) ;
//  3. attendre les sous-parts de tous les participants ;
//  4. calculer s' = s + Σ δ_i(x) et l'enregistrer EN ATTENTE.
//
// La part en service n'est pas modifiée : seul Commit la remplace. Tous les nœuds
// additionnent les contributions du même ensemble de participants, fixé par le
// coordinateur dans la requête ; sinon les nouvelles parts ne seraient plus sur un
// même polynôme et la clé serait perdue.
func (s *nodeServer) Prepare(ctx context.Context, req *pb.PrepareRequest) (*pb.EpochResponse, error) {
	if err := requirePeer(ctx, coordinatorName); err != nil {
		return nil, err
	}
	indices, addresses, err := s.checkPrepare(req)
	if err != nil {
		return nil, err
	}

	s.prepareMu.Lock()
	defer s.prepareMu.Unlock()

	// Prepare déjà fait pour cette époque : rien à refaire (un second tirage de δ
	// serait incohérent avec les sous-parts déjà envoyées).
	if done, err := s.store.HasPending(req.Epoch); err != nil {
		return nil, storageError(err)
	} else if done {
		return &pb.EpochResponse{}, nil
	}

	all, err := s.store.CommittedShares()
	if err != nil {
		return nil, storageError(err)
	}
	var files []storage.FileShare
	for _, fs := range all {
		if fs.Share.Epoch < req.Epoch {
			files = append(files, fs)
		}
	}

	// 1 et 2 : une contribution par fichier, triée par destinataire.
	outbox := make(map[uint32][]storage.SubShare, len(indices))
	for _, fs := range files {
		contribution, err := shamir.NewRefreshContribution(int(req.T), indices, rand.Reader)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "contribution : %v", err)
		}
		for j, delta := range contribution {
			outbox[j] = append(outbox[j], storage.SubShare{FileID: fs.FileID, FromX: s.x, Value: delta.Bytes()})
		}
	}
	if err := s.store.PutSubShares(req.Epoch, s.x, outbox[s.x]); err != nil {
		return nil, storageError(err)
	}
	if err := s.sendSubShares(ctx, req.Epoch, addresses, outbox); err != nil {
		return nil, err
	}

	// 3 : attendre les sous-parts des autres participants.
	received, err := s.waitSubShares(ctx, req.Epoch, files, indices)
	if err != nil {
		return nil, err
	}

	// 4 : nouvelles parts en attente.
	for _, fs := range files {
		share, err := refreshShare(fs.Share, received[fs.FileID], req.Epoch)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "fichier %s : %v", fs.FileID, err)
		}
		if err := s.store.PutPendingShare(fs.FileID, share); err != nil {
			return nil, storageError(err)
		}
	}
	return &pb.EpochResponse{}, nil
}

// Commit réalise la phase 2 : les parts en attente de l'époque deviennent les parts en
// service et les anciennes parts sont effacées. Rappelable sans risque après un crash.
func (s *nodeServer) Commit(ctx context.Context, req *pb.EpochRequest) (*pb.EpochResponse, error) {
	if err := requirePeer(ctx, coordinatorName); err != nil {
		return nil, err
	}
	if req.Epoch == 0 {
		return nil, status.Error(codes.InvalidArgument, "époque invalide")
	}
	if err := s.store.CommitEpoch(req.Epoch); err != nil {
		return nil, storageError(err)
	}
	return &pb.EpochResponse{}, nil
}

// Abort abandonne le renouvellement : parts en attente et sous-parts sont effacées,
// les parts en service restent. Rappelable sans risque.
func (s *nodeServer) Abort(ctx context.Context, req *pb.EpochRequest) (*pb.EpochResponse, error) {
	if err := requirePeer(ctx, coordinatorName); err != nil {
		return nil, err
	}
	if req.Epoch == 0 {
		return nil, status.Error(codes.InvalidArgument, "époque invalide")
	}
	if err := s.store.AbortEpoch(req.Epoch); err != nil {
		return nil, storageError(err)
	}
	return &pb.EpochResponse{}, nil
}

// checkPrepare vérifie la requête et renvoie les abscisses des participants et leurs adresses.
func (s *nodeServer) checkPrepare(req *pb.PrepareRequest) ([]uint32, map[uint32]string, error) {
	if req.Epoch == 0 {
		return nil, nil, status.Error(codes.InvalidArgument, "époque invalide")
	}
	addresses := make(map[uint32]string, len(req.Participants))
	indices := make([]uint32, 0, len(req.Participants))
	for _, p := range req.Participants {
		if p.X == 0 {
			return nil, nil, status.Error(codes.InvalidArgument, "abscisse de participant nulle")
		}
		if _, dup := addresses[p.X]; dup {
			return nil, nil, status.Errorf(codes.InvalidArgument, "participant x = %d en double", p.X)
		}
		addresses[p.X] = p.Address
		indices = append(indices, p.X)
	}
	if _, ok := addresses[s.x]; !ok {
		return nil, nil, status.Errorf(codes.InvalidArgument, "ce nœud (x = %d) ne fait pas partie des participants", s.x)
	}
	if req.T < 1 || int(req.T) > len(indices) {
		return nil, nil, status.Errorf(codes.InvalidArgument, "seuil t = %d invalide pour %d participants", req.T, len(indices))
	}
	slices.Sort(indices)
	return indices, addresses, nil
}

// sendSubShares envoie à chaque autre participant, en parallèle, les sous-parts qui lui
// sont destinées. Chaque sous-part ne part que vers son destinataire.
func (s *nodeServer) sendSubShares(ctx context.Context, epoch uint64, addresses map[uint32]string,
	outbox map[uint32][]storage.SubShare) error {

	errs := make(chan error, len(addresses))
	for j, address := range addresses {
		if j == s.x {
			continue
		}
		go func() {
			errs <- s.deliver(ctx, j, address, epoch, outbox[j])
		}()
	}

	var all []error
	for j := range addresses {
		if j == s.x {
			continue
		}
		if err := <-errs; err != nil {
			all = append(all, err)
		}
	}
	if err := errors.Join(all...); err != nil {
		return status.Errorf(codes.Unavailable, "envoi des sous-parts : %v", err)
	}
	return nil
}

func (s *nodeServer) deliver(ctx context.Context, to uint32, address string, epoch uint64,
	subShares []storage.SubShare) error {

	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(s.peers.Clone())))
	if err != nil {
		return fmt.Errorf("nœud x=%d : %w", to, err)
	}
	defer conn.Close()

	req := &pb.DeliverSubSharesRequest{FromX: s.x, ToX: to, TargetEpoch: epoch}
	for _, sub := range subShares {
		req.SubShares = append(req.SubShares, &pb.SubShare{FileId: sub.FileID, Value: sub.Value})
	}
	if _, err := pb.NewRenewalClient(conn).DeliverSubShares(ctx, req); err != nil {
		return fmt.Errorf("nœud x=%d : %w", to, err)
	}
	return nil
}

// waitSubShares attend que, pour chaque fichier, une sous-part de chaque participant soit
// arrivée, et les renvoie par fichier. Elle échoue à l'expiration de ctx.
func (s *nodeServer) waitSubShares(ctx context.Context, epoch uint64, files []storage.FileShare,
	indices []uint32) (map[string][][]byte, error) {

	ticker := time.NewTicker(subSharePollInterval)
	defer ticker.Stop()
	for {
		subShares, err := s.store.SubShares(epoch)
		if err != nil {
			return nil, storageError(err)
		}
		received := make(map[string]map[uint32][]byte)
		for _, sub := range subShares {
			if received[sub.FileID] == nil {
				received[sub.FileID] = make(map[uint32][]byte)
			}
			received[sub.FileID][sub.FromX] = sub.Value
		}

		complete := true
		byFile := make(map[string][][]byte, len(files))
		for _, fs := range files {
			for _, x := range indices {
				value, ok := received[fs.FileID][x]
				if !ok {
					complete = false
					break
				}
				byFile[fs.FileID] = append(byFile[fs.FileID], value)
			}
		}
		if complete {
			return byFile, nil
		}

		select {
		case <-ctx.Done():
			return nil, status.Error(codes.DeadlineExceeded, "sous-parts manquantes : un participant n'a pas contribué")
		case <-ticker.C:
		}
	}
}

// refreshShare calcule la part de l'époque epoch : s' = s + Σ δ_i(x).
func refreshShare(old storage.Share, deltas [][]byte, epoch uint64) (storage.Share, error) {
	value, err := edwards25519.NewScalar().SetCanonicalBytes(old.Value)
	if err != nil {
		return storage.Share{}, fmt.Errorf("part en service mal formée : %w", err)
	}
	received := make([]*edwards25519.Scalar, len(deltas))
	for i, d := range deltas {
		if received[i], err = edwards25519.NewScalar().SetCanonicalBytes(d); err != nil {
			return storage.Share{}, fmt.Errorf("sous-part mal formée : %w", err)
		}
	}
	refreshed, err := shamir.ApplyRefresh(shamir.Share{Index: old.X, Epoch: old.Epoch, Value: value}, received)
	if err != nil {
		return storage.Share{}, err
	}
	return storage.Share{X: old.X, Value: refreshed.Value.Bytes(), Epoch: epoch}, nil
}
