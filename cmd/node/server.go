package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"slices"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"safevault/internal/access"
	"safevault/internal/storage"
	pb "safevault/proto"
)

// maxShareSize borne la taille d'une part ou d'une sous-part (un scalaire fait 32 octets).
const maxShareSize = 64

// nodeServer implémente les services Node (client → nœud), Renewal (nœud → nœud)
// et Epoch (coordinateur → nœud).
type nodeServer struct {
	pb.UnimplementedNodeServer
	pb.UnimplementedRenewalServer
	pb.UnimplementedEpochServer

	x      uint32 // abscisse du nœud dans le partage de Shamir
	store  *storage.Store
	proofs *proofVerifier
	peers  *tls.Config // configuration TLS pour appeler les autres nœuds (mTLS)
	now    func() time.Time

	prepareMu sync.Mutex // un seul Prepare à la fois
}

func newNodeServer(x uint32, store *storage.Store, peers *tls.Config) *nodeServer {
	return &nodeServer{x: x, store: store, proofs: newProofVerifier(), peers: peers, now: time.Now}
}

// PutShare enregistre la part du nœud pour un fichier. La clé qui dépose la première part
// devient propriétaire du fichier.
func (s *nodeServer) PutShare(ctx context.Context, req *pb.PutShareRequest) (*pb.PutShareResponse, error) {
	if !storage.ValidFileID(req.FileId) {
		return nil, status.Error(codes.InvalidArgument, "identifiant de fichier invalide")
	}
	share := req.Share
	if share == nil || len(share.Value) == 0 || len(share.Value) > maxShareSize {
		return nil, status.Error(codes.InvalidArgument, "part manquante ou de taille invalide")
	}
	if share.X != s.x {
		return nil, status.Errorf(codes.InvalidArgument, "part pour x = %d, ce nœud est x = %d", share.X, s.x)
	}
	if err := s.proofs.verify(labelPutShare, s.x, req.FileId, share.Epoch, req.Proof); err != nil {
		return nil, err
	}
	if err := s.store.ClaimOwner(req.FileId, req.Proof.PublicKey); err != nil {
		return nil, storageError(err)
	}

	err := s.store.PutShare(req.FileId, storage.Share{X: share.X, Value: share.Value, Epoch: share.Epoch})
	if err != nil {
		return nil, storageError(err)
	}
	return &pb.PutShareResponse{}, nil
}

// GetShare renvoie la part du nœud si elle est de l'époque demandée.
func (s *nodeServer) GetShare(ctx context.Context, req *pb.GetShareRequest) (*pb.GetShareResponse, error) {
	if !storage.ValidFileID(req.FileId) {
		return nil, status.Error(codes.InvalidArgument, "identifiant de fichier invalide")
	}
	if err := s.proofs.verify(labelGetShare, s.x, req.FileId, req.Epoch, req.Proof); err != nil {
		return nil, err
	}
	if err := s.checkReader(req.FileId, req.Proof.PublicKey, req.Grant); err != nil {
		return nil, err
	}

	share, err := s.store.Share(req.FileId)
	if err != nil {
		return nil, storageError(err)
	}
	if share.Epoch != req.Epoch {
		return nil, status.Errorf(codes.FailedPrecondition,
			"le nœud est à l'époque %d, la requête demande l'époque %d", share.Epoch, req.Epoch)
	}
	return &pb.GetShareResponse{Share: &pb.Share{X: share.X, Value: share.Value, Epoch: share.Epoch}}, nil
}

// PutBlocks reçoit les blocs d'un fichier un par un et écrit chacun sur le disque dès son
// arrivée : le fichier n'est jamais chargé entièrement en mémoire. La part du fichier doit
// avoir été déposée avant les blocs.
func (s *nodeServer) PutBlocks(stream pb.Node_PutBlocksServer) error {
	var fileID string
	var epoch uint64
	var stored uint32

	for {
		block, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.PutBlocksResponse{Stored: stored})
		}
		if err != nil {
			return err
		}

		if fileID == "" {
			if !storage.ValidFileID(block.FileId) {
				return status.Error(codes.InvalidArgument, "identifiant de fichier invalide")
			}
			share, err := s.store.Share(block.FileId)
			if errors.Is(err, storage.ErrNotFound) {
				return status.Error(codes.FailedPrecondition, "la part du fichier doit être déposée avant ses blocs")
			}
			if err != nil {
				return storageError(err)
			}
			fileID, epoch = block.FileId, share.Epoch
		} else if block.FileId != fileID {
			return status.Error(codes.InvalidArgument, "un flux ne peut contenir les blocs que d'un seul fichier")
		}

		if err := s.proofs.verify(labelPutBlocks, s.x, fileID, epoch, block.Proof); err != nil {
			return err
		}
		if err := s.checkOwner(fileID, block.Proof.PublicKey); err != nil {
			return err
		}
		if err := s.store.PutBlock(fileID, block.Index, bytes.NewReader(block.Data)); err != nil {
			return storageError(err)
		}
		stored++
	}
}

// GetBlocks renvoie les blocs d'un fichier dans l'ordre, en lisant un bloc à la fois.
func (s *nodeServer) GetBlocks(req *pb.GetBlocksRequest, stream pb.Node_GetBlocksServer) error {
	if !storage.ValidFileID(req.FileId) {
		return status.Error(codes.InvalidArgument, "identifiant de fichier invalide")
	}
	if err := s.proofs.verify(labelGetBlocks, s.x, req.FileId, 0, req.Proof); err != nil {
		return err
	}
	if err := s.checkReader(req.FileId, req.Proof.PublicKey, req.Grant); err != nil {
		return err
	}

	indexes, err := s.store.BlockIndexes(req.FileId)
	if err != nil {
		return storageError(err)
	}
	for _, index := range indexes {
		r, err := s.store.OpenBlock(req.FileId, index)
		if err != nil {
			return storageError(err)
		}
		data, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			return status.Errorf(codes.Internal, "lecture du bloc %d : %v", index, err)
		}
		if err := stream.Send(&pb.Block{FileId: req.FileId, Index: index, Data: data}); err != nil {
			return err
		}
	}
	return nil
}

// DeliverSubShares enregistre les sous-parts envoyées par un autre nœud pour un renouvellement.
// L'émetteur doit présenter le certificat "node-<from_x>" : un tiers ne peut pas injecter
// de sous-parts, et un nœud ne peut pas se faire passer pour un autre.
func (s *nodeServer) DeliverSubShares(ctx context.Context, req *pb.DeliverSubSharesRequest) (*pb.DeliverSubSharesResponse, error) {
	if err := requirePeer(ctx, nodeName(req.FromX)); err != nil {
		return nil, err
	}
	if req.ToX != s.x {
		return nil, status.Errorf(codes.InvalidArgument, "sous-parts pour x = %d, ce nœud est x = %d", req.ToX, s.x)
	}
	if req.FromX == 0 || req.FromX == s.x {
		return nil, status.Error(codes.InvalidArgument, "abscisse de l'émetteur invalide")
	}
	if req.TargetEpoch == 0 {
		return nil, status.Error(codes.InvalidArgument, "époque cible invalide")
	}

	subShares := make([]storage.SubShare, 0, len(req.SubShares))
	for _, sub := range req.SubShares {
		if len(sub.Value) == 0 || len(sub.Value) > maxShareSize {
			return nil, status.Errorf(codes.InvalidArgument, "sous-part du fichier %q de taille invalide", sub.FileId)
		}
		subShares = append(subShares, storage.SubShare{FileID: sub.FileId, FromX: req.FromX, Value: sub.Value})
	}
	if err := s.store.PutSubShares(req.TargetEpoch, req.FromX, subShares); err != nil {
		return nil, storageError(err)
	}
	return &pb.DeliverSubSharesResponse{}, nil
}

// checkReader vérifie que publicKey peut lire le fichier : c'est le propriétaire, ou
// le destinataire d'une autorisation signée par le propriétaire, valable et non révoquée.
// Le coordinateur ne peut pas fabriquer une telle autorisation : il n'a pas la clé
// privée du propriétaire.
func (s *nodeServer) checkReader(fileID string, publicKey []byte, grant *pb.Grant) error {
	owner, err := s.store.Owner(fileID)
	if err != nil {
		return storageError(err)
	}
	if slices.Equal(owner, publicKey) {
		return nil
	}
	if grant == nil {
		return status.Error(codes.PermissionDenied, "accès refusé à ce fichier")
	}
	if err := access.VerifyGrantFor(grant, fileID, owner, publicKey, s.now()); err != nil {
		return status.Errorf(codes.PermissionDenied, "autorisation refusée : %v", err)
	}
	revokedAt, revoked, err := s.store.RevokedAt(fileID, publicKey)
	if err != nil {
		return storageError(err)
	}
	if revoked && grant.IssuedAt <= revokedAt {
		return status.Error(codes.PermissionDenied, "accès retiré par le propriétaire")
	}
	return nil
}

// Revoke enregistre le retrait d'un accès. La révocation se suffit à elle-même : elle
// est signée par le propriétaire du fichier, et la rejouer ne change rien.
func (s *nodeServer) Revoke(ctx context.Context, req *pb.RevokeRequest) (*pb.RevokeResponse, error) {
	r := req.Revocation
	if r == nil || !storage.ValidFileID(r.FileId) {
		return nil, status.Error(codes.InvalidArgument, "révocation manquante ou fichier invalide")
	}
	owner, err := s.store.Owner(r.FileId)
	if err != nil {
		return nil, storageError(err)
	}
	if err := access.VerifyRevocation(r, owner); err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "révocation refusée : %v", err)
	}
	if err := s.store.PutRevocation(r.FileId, r.GranteePublicKey, r.RevokedAt); err != nil {
		return nil, storageError(err)
	}
	return &pb.RevokeResponse{}, nil
}

// checkOwner vérifie que publicKey est la clé propriétaire du fichier.
func (s *nodeServer) checkOwner(fileID string, publicKey []byte) error {
	owner, err := s.store.Owner(fileID)
	if err != nil {
		return storageError(err)
	}
	if !slices.Equal(owner, publicKey) {
		return status.Error(codes.PermissionDenied, "accès refusé à ce fichier")
	}
	return nil
}

// storageError traduit une erreur du stockage en erreur gRPC.
func storageError(err error) error {
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return status.Error(codes.NotFound, "fichier inconnu de ce nœud")
	case errors.Is(err, storage.ErrOwnerMismatch):
		return status.Error(codes.PermissionDenied, "accès refusé à ce fichier")
	case errors.Is(err, storage.ErrInvalidFileID):
		return status.Error(codes.InvalidArgument, "identifiant de fichier invalide")
	default:
		return status.Errorf(codes.Internal, "erreur de stockage : %v", err)
	}
}
