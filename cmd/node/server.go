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

// PutShare enregistre la part du nœud pour une version d'un fichier. La clé qui dépose
// la première part de la version 1 devient propriétaire du fichier ; une version suivante
// ne peut être déposée que par le propriétaire ou un utilisateur qui a le droit d'écrire
// (w), et une version déjà déposée ne peut pas être écrasée par une autre clé.
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
	version := max(req.Version, 1)
	author := req.Proof.PublicKey

	if version == 1 {
		if err := s.store.ClaimOwner(req.FileId, author); err != nil {
			return nil, storageError(err)
		}
	} else if _, err := s.authorize(req.FileId, author, req.Grant, access.Write); err != nil {
		return nil, err
	}
	if err := s.store.ClaimVersion(req.FileId, version, author); err != nil {
		if errors.Is(err, storage.ErrOwnerMismatch) {
			return nil, status.Error(codes.PermissionDenied, "version déjà déposée par une autre clé")
		}
		return nil, storageError(err)
	}

	err := s.store.PutShare(storage.VersionKey(req.FileId, version),
		storage.Share{X: share.X, Value: share.Value, Epoch: share.Epoch})
	if err != nil {
		return nil, storageError(err)
	}
	return &pb.PutShareResponse{}, nil
}

// GetShare renvoie la part du nœud pour une version d'un fichier, si elle est de l'époque
// demandée et si le demandeur a le droit de lire (r).
func (s *nodeServer) GetShare(ctx context.Context, req *pb.GetShareRequest) (*pb.GetShareResponse, error) {
	if !storage.ValidFileID(req.FileId) {
		return nil, status.Error(codes.InvalidArgument, "identifiant de fichier invalide")
	}
	if err := s.proofs.verify(labelGetShare, s.x, req.FileId, req.Epoch, req.Proof); err != nil {
		return nil, err
	}
	if _, err := s.authorize(req.FileId, req.Proof.PublicKey, req.Grant, access.Read); err != nil {
		return nil, err
	}

	share, err := s.store.Share(storage.VersionKey(req.FileId, req.Version))
	if err != nil {
		return nil, storageError(err)
	}
	if share.Epoch != req.Epoch {
		return nil, status.Errorf(codes.FailedPrecondition,
			"le nœud est à l'époque %d, la requête demande l'époque %d", share.Epoch, req.Epoch)
	}
	return &pb.GetShareResponse{Share: &pb.Share{X: share.X, Value: share.Value, Epoch: share.Epoch}}, nil
}

// PutBlocks reçoit les blocs d'une version un par un et écrit chacun sur le disque dès son
// arrivée : le fichier n'est jamais chargé entièrement en mémoire. La part de la version
// doit avoir été déposée avant les blocs, par la même clé.
func (s *nodeServer) PutBlocks(stream pb.Node_PutBlocksServer) error {
	var fileID, key string
	var version uint32
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
			version = max(block.Version, 1)
			key = storage.VersionKey(block.FileId, version)
			share, err := s.store.Share(key)
			if errors.Is(err, storage.ErrNotFound) {
				return status.Error(codes.FailedPrecondition, "la part du fichier doit être déposée avant ses blocs")
			}
			if err != nil {
				return storageError(err)
			}
			fileID, epoch = block.FileId, share.Epoch
		} else if block.FileId != fileID || max(block.Version, 1) != version {
			return status.Error(codes.InvalidArgument, "un flux ne peut contenir les blocs que d'une seule version")
		}

		if err := s.proofs.verify(labelPutBlocks, s.x, fileID, epoch, block.Proof); err != nil {
			return err
		}
		author, err := s.store.VersionAuthor(fileID, version)
		if err != nil {
			return storageError(err)
		}
		if !slices.Equal(author, block.Proof.PublicKey) {
			return status.Error(codes.PermissionDenied, "seul l'auteur de la version peut en déposer les blocs")
		}
		if err := s.store.PutBlock(key, block.Index, bytes.NewReader(block.Data)); err != nil {
			return storageError(err)
		}
		stored++
	}
}

// GetBlocks renvoie les blocs d'une version dans l'ordre, en lisant un bloc à la fois.
func (s *nodeServer) GetBlocks(req *pb.GetBlocksRequest, stream pb.Node_GetBlocksServer) error {
	if !storage.ValidFileID(req.FileId) {
		return status.Error(codes.InvalidArgument, "identifiant de fichier invalide")
	}
	if err := s.proofs.verify(labelGetBlocks, s.x, req.FileId, 0, req.Proof); err != nil {
		return err
	}
	if _, err := s.authorize(req.FileId, req.Proof.PublicKey, req.Grant, access.Read); err != nil {
		return err
	}

	key := storage.VersionKey(req.FileId, req.Version)
	indexes, err := s.store.BlockIndexes(key)
	if err != nil {
		return storageError(err)
	}
	for _, index := range indexes {
		r, err := s.store.OpenBlock(key, index)
		if err != nil {
			return storageError(err)
		}
		data, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			return status.Errorf(codes.Internal, "lecture du bloc %d : %v", index, err)
		}
		block := &pb.Block{FileId: req.FileId, Index: index, Data: data, Version: max(req.Version, 1)}
		if err := stream.Send(block); err != nil {
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

// accessContext rassemble ce que le nœud sait d'un fichier pour vérifier une autorisation :
// propriétaires successifs et retraits d'accès enregistrés.
func (s *nodeServer) accessContext(fileID string) (access.Context, error) {
	stored, err := s.store.Owners(fileID)
	if err != nil {
		return access.Context{}, storageError(err)
	}
	owners := make([]access.Owner, len(stored))
	for i, o := range stored {
		owners[i] = access.Owner{Key: o.Key, Until: o.Until}
	}
	return access.Context{
		FileID: fileID,
		Owners: owners,
		RevokedAt: func(grantee []byte) (int64, bool, error) {
			return s.store.RevokedAt(fileID, grantee)
		},
		Now: s.now(),
	}, nil
}

// authorize vérifie que publicKey a les droits want sur le fichier : c'est le propriétaire,
// ou le détenteur d'une autorisation dont toute la chaîne remonte au propriétaire, valable
// et non retirée. Le coordinateur ne peut pas fabriquer une telle autorisation : il n'a la
// clé privée de personne.
func (s *nodeServer) authorize(fileID string, publicKey []byte, grant *pb.Grant, want uint32) (uint32, error) {
	c, err := s.accessContext(fileID)
	if err != nil {
		return 0, err
	}
	rights, err := access.Authorize(publicKey, grant, want, c)
	if err != nil {
		if grant == nil {
			return 0, status.Error(codes.PermissionDenied, "accès refusé à ce fichier")
		}
		return 0, status.Errorf(codes.PermissionDenied, "autorisation refusée : %v", err)
	}
	return rights, nil
}

// Revoke enregistre le retrait d'un accès. La révocation se suffit à elle-même : elle est
// signée par le propriétaire ou par un utilisateur qui a le droit de gérer les accès (m),
// et la rejouer ne change rien.
func (s *nodeServer) Revoke(ctx context.Context, req *pb.RevokeRequest) (*pb.RevokeResponse, error) {
	r := req.Revocation
	if r == nil || !storage.ValidFileID(r.FileId) {
		return nil, status.Error(codes.InvalidArgument, "révocation manquante ou fichier invalide")
	}
	c, err := s.accessContext(r.FileId)
	if err != nil {
		return nil, err
	}
	if err := access.VerifyRevocation(r, c); err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "révocation refusée : %v", err)
	}
	if err := s.store.PutRevocation(r.FileId, r.GranteePublicKey, r.RevokedAt); err != nil {
		return nil, storageError(err)
	}
	return &pb.RevokeResponse{}, nil
}

// DeleteFile efface toutes les versions d'un fichier : parts et blocs. Il faut être
// propriétaire ou avoir le droit de supprimer (d).
func (s *nodeServer) DeleteFile(ctx context.Context, req *pb.DeleteFileRequest) (*pb.DeleteFileResponse, error) {
	if !storage.ValidFileID(req.FileId) {
		return nil, status.Error(codes.InvalidArgument, "identifiant de fichier invalide")
	}
	if err := s.proofs.verify(labelDelete, s.x, req.FileId, 0, req.Proof); err != nil {
		return nil, err
	}
	if _, err := s.authorize(req.FileId, req.Proof.PublicKey, req.Grant, access.Delete); err != nil {
		return nil, err
	}
	if err := s.store.DeleteFile(req.FileId); err != nil {
		return nil, storageError(err)
	}
	return &pb.DeleteFileResponse{}, nil
}

// TransferOwnership donne le fichier à un autre utilisateur. Le transfert est signé par le
// propriétaire actuel ; l'ancien propriétaire est gardé dans l'historique pour que les
// autorisations qu'il a signées avant restent valables.
func (s *nodeServer) TransferOwnership(ctx context.Context, req *pb.TransferRequest) (*pb.TransferResponse, error) {
	t := req.Transfer
	if t == nil || !storage.ValidFileID(t.FileId) {
		return nil, status.Error(codes.InvalidArgument, "transfert manquant ou fichier invalide")
	}
	c, err := s.accessContext(t.FileId)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(access.CurrentOwner(c.Owners), t.NewOwnerPublicKey) {
		return &pb.TransferResponse{}, nil // déjà fait : rejouer ne change rien
	}
	if err := access.VerifyTransfer(t, c); err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "transfert refusé : %v", err)
	}
	if err := s.store.TransferOwner(t.FileId, t.NewOwnerPublicKey, t.TransferredAt); err != nil {
		return nil, storageError(err)
	}
	return &pb.TransferResponse{}, nil
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
