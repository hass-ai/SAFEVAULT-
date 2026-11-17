package main

import (
	"context"
	"encoding/base64"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"safevault/internal/metadata"
	pb "safevault/proto"
)

const (
	fileIDSize  = 16      // octets aléatoires d'un identifiant de fichier (128 bits)
	maxNameSize = 1024    // taille maximale du nom (opaque) d'un fichier
	maxBlocks   = 1 << 20 // nombre maximal de blocs d'un manifeste
)

// errFileNotFound est renvoyée aussi quand le fichier appartient à quelqu'un d'autre :
// un utilisateur ne peut pas savoir si un identifiant existe chez un autre.
var errFileNotFound = status.Error(codes.NotFound, "fichier introuvable")

// newFileID tire un identifiant opaque : 16 octets aléatoires en base64url sans
// remplissage (22 caractères), accepté par les nœuds ([A-Za-z0-9_-]).
func newFileID() (string, error) {
	b, err := randomBytes(fileIDSize)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// CreateFile commence un dépôt : identifiant, époque courante, n nœuds disponibles, t et n.
func (s *coordinatorServer) CreateFile(ctx context.Context, req *pb.CreateFileRequest) (*pb.CreateFileResponse, error) {
	userID, _ := userFromContext(ctx)
	if len(req.Name) == 0 || len(req.Name) > maxNameSize {
		return nil, status.Error(codes.InvalidArgument, "nom de fichier vide ou trop long")
	}

	nodes, err := s.registry.uploadNodes(s.n)
	if err != nil {
		return nil, err
	}
	epoch, err := s.store.CurrentEpoch()
	if err != nil {
		return nil, internalError(err)
	}
	fileID, err := newFileID()
	if err != nil {
		return nil, internalError(err)
	}

	xs := make([]uint32, len(nodes))
	infos := make([]*pb.NodeInfo, len(nodes))
	for i, n := range nodes {
		xs[i] = n.X
		infos[i] = &pb.NodeInfo{Address: n.Address, X: n.X}
	}
	f := metadata.File{
		ID: fileID, OwnerID: userID, Name: []byte(req.Name), Size: req.Size,
		T: s.t, N: s.n, Epoch: epoch,
	}
	err = s.store.CreateFile(f, xs)
	if errors.Is(err, metadata.ErrConflict) {
		return nil, status.Error(codes.Unavailable, "renouvellement des parts en cours, réessayez dans un instant")
	}
	if err != nil {
		return nil, internalError(err)
	}
	setCallFile(ctx, fileID)
	return &pb.CreateFileResponse{FileId: fileID, Epoch: epoch, Nodes: infos, T: s.t, N: s.n}, nil
}

// ConfirmUpload enregistre le manifeste une fois les parts et les blocs envoyés aux nœuds.
func (s *coordinatorServer) ConfirmUpload(ctx context.Context, req *pb.ConfirmUploadRequest) (*pb.ConfirmUploadResponse, error) {
	userID, _ := userFromContext(ctx)
	setCallFile(ctx, req.FileId)
	m := req.Manifest
	if m == nil || m.BlockCount > maxBlocks {
		return nil, status.Error(codes.InvalidArgument, "manifeste manquant ou trop grand")
	}

	err := s.store.ConfirmUpload(req.FileId, userID, metadata.Manifest{
		BlockCount:  m.BlockCount,
		BlockHashes: m.BlockHashes,
		NoncePrefix: m.NoncePrefix,
		Size:        m.Size,
	})
	switch {
	case errors.Is(err, metadata.ErrNotFound), errors.Is(err, metadata.ErrNotOwner):
		return nil, errFileNotFound
	case errors.Is(err, metadata.ErrConflict):
		return nil, status.Error(codes.FailedPrecondition, "dépôt déjà confirmé")
	case errors.Is(err, metadata.ErrInvalidArgument):
		return nil, status.Error(codes.InvalidArgument, "manifeste incohérent")
	case err != nil:
		return nil, internalError(err)
	}
	return &pb.ConfirmUploadResponse{}, nil
}

// ListFiles liste les fichiers confirmés de l'utilisateur connecté.
func (s *coordinatorServer) ListFiles(ctx context.Context, req *pb.ListFilesRequest) (*pb.ListFilesResponse, error) {
	userID, _ := userFromContext(ctx)
	files, err := s.store.FilesByOwner(userID)
	if err != nil {
		return nil, internalError(err)
	}
	resp := &pb.ListFilesResponse{}
	for _, f := range files {
		resp.Files = append(resp.Files, &pb.FileInfo{FileId: f.ID, Name: string(f.Name), Size: f.Size})
	}
	return resp, nil
}

// GetFile renvoie ce qu'il faut pour relire un fichier : époque, seuil, manifeste et nœuds.
// Seul le propriétaire y a accès pour l'instant (le partage viendra avec SV-62).
func (s *coordinatorServer) GetFile(ctx context.Context, req *pb.GetFileRequest) (*pb.GetFileResponse, error) {
	userID, _ := userFromContext(ctx)
	setCallFile(ctx, req.FileId)

	f, err := s.store.File(req.FileId)
	if errors.Is(err, metadata.ErrNotFound) || (err == nil && f.OwnerID != userID) {
		return nil, errFileNotFound
	}
	if err != nil {
		return nil, internalError(err)
	}
	if f.Status != metadata.FileReady {
		return nil, status.Error(codes.FailedPrecondition, "dépôt pas encore confirmé")
	}

	m, err := s.store.Manifest(f.ID)
	if err != nil {
		return nil, internalError(err)
	}
	nodes, err := s.store.FileNodes(f.ID)
	if err != nil {
		return nil, internalError(err)
	}
	return &pb.GetFileResponse{
		Epoch: f.Epoch,
		T:     f.T,
		Manifest: &pb.Manifest{
			BlockCount:  m.BlockCount,
			BlockHashes: m.BlockHashes,
			NoncePrefix: m.NoncePrefix,
			Size:        m.Size,
		},
		Nodes: nodeInfosUpFirst(nodes),
	}, nil
}

// nodeInfosUpFirst met les nœuds en service en tête : le client s'arrête dès qu'il a
// t parts, il n'attend donc pas les nœuds en panne.
func nodeInfosUpFirst(nodes []metadata.Node) []*pb.NodeInfo {
	var up, others []*pb.NodeInfo
	for _, n := range nodes {
		info := &pb.NodeInfo{Address: n.Address, X: n.X}
		if n.Status == metadata.NodeUp {
			up = append(up, info)
		} else {
			others = append(others, info)
		}
	}
	return append(up, others...)
}
