package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"safevault/internal/access"
	"safevault/internal/metadata"
	pb "safevault/proto"
)

const (
	fileIDSize  = 16      // octets aléatoires d'un identifiant de fichier (128 bits)
	maxNameSize = 1024    // taille maximale du nom chiffré d'un fichier
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
	if len(req.EncryptedName) == 0 || len(req.EncryptedName) > maxNameSize {
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
		ID: fileID, OwnerID: userID, Name: req.EncryptedName, Size: req.Size,
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
	return &pb.CreateFileResponse{FileId: fileID, Epoch: epoch, Nodes: infos, T: s.t, N: s.n, Version: 1}, nil
}

// CreateVersion commence le dépôt d'une nouvelle version (propriétaire ou droit w). Les
// parts vont aux mêmes nœuds que les versions précédentes, qui connaissent les droits.
func (s *coordinatorServer) CreateVersion(ctx context.Context, req *pb.CreateVersionRequest) (*pb.CreateVersionResponse, error) {
	a, err := s.fileAccess(ctx, req.FileId, access.Write)
	if err != nil {
		return nil, err
	}
	if a.file.Status != metadata.FileReady {
		return nil, status.Error(codes.FailedPrecondition, "dépôt pas encore confirmé")
	}
	nodes, err := s.store.FileNodes(a.file.ID)
	if err != nil {
		return nil, internalError(err)
	}
	version, err := s.store.CreateVersion(a.file.ID, a.user.ID, req.Size)
	if errors.Is(err, metadata.ErrConflict) {
		return nil, status.Error(codes.Unavailable, "renouvellement des parts en cours, réessayez dans un instant")
	}
	if err != nil {
		return nil, internalError(err)
	}
	infos := make([]*pb.NodeInfo, len(nodes))
	for i, n := range nodes {
		infos[i] = &pb.NodeInfo{Address: n.Address, X: n.X}
	}
	return &pb.CreateVersionResponse{Version: version, Epoch: a.file.Epoch, Nodes: infos, T: a.file.T, N: a.file.N}, nil
}

// ConfirmUpload enregistre le manifeste d'une version une fois ses parts et ses blocs
// envoyés aux nœuds ; elle devient la version actuelle.
func (s *coordinatorServer) ConfirmUpload(ctx context.Context, req *pb.ConfirmUploadRequest) (*pb.ConfirmUploadResponse, error) {
	userID, _ := userFromContext(ctx)
	setCallFile(ctx, req.FileId)
	m := req.Manifest
	if m == nil || m.BlockCount > maxBlocks {
		return nil, status.Error(codes.InvalidArgument, "manifeste manquant ou trop grand")
	}

	err := s.store.ConfirmUpload(req.FileId, req.Version, userID, metadata.Manifest{
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

// ListFiles liste les fichiers confirmés de l'utilisateur, puis ceux qui lui sont
// partagés par une autorisation encore valable. Les noms sont chiffrés : le coordinateur
// ne fait que les transmettre.
func (s *coordinatorServer) ListFiles(ctx context.Context, req *pb.ListFilesRequest) (*pb.ListFilesResponse, error) {
	userID, _ := userFromContext(ctx)
	user, err := s.store.UserByID(userID)
	if err != nil {
		return nil, internalError(err)
	}
	owned, err := s.store.FilesByOwner(userID)
	if err != nil {
		return nil, internalError(err)
	}
	shared, err := s.store.FilesSharedWith(userID)
	if err != nil {
		return nil, internalError(err)
	}

	resp := &pb.ListFilesResponse{}
	for _, f := range owned {
		info := &pb.FileInfo{FileId: f.ID, EncryptedName: f.Name, Size: f.Size, Owner: user.Username,
			Rights: access.All, Version: f.CurrentVersion}
		s.setModified(info)
		resp.Files = append(resp.Files, info)
	}
	for _, f := range shared {
		rights, g, err := s.grantRights(f.File, f.SignedGrant, user.PublicKey)
		if err != nil {
			continue // autorisation expirée ou retirée : le fichier n'est plus visible
		}
		info := &pb.FileInfo{FileId: f.ID, EncryptedName: f.EncryptedName, Size: f.Size, Owner: f.Owner,
			Shared: true, Rights: rights, Version: f.CurrentVersion, ExpiresAt: access.Expiry(g)}
		s.setModified(info)
		resp.Files = append(resp.Files, info)
	}
	return resp, nil
}

// setModified complète info avec la date de la version actuelle.
func (s *coordinatorServer) setModified(info *pb.FileInfo) {
	if _, v, err := s.store.Manifest(info.FileId, 0); err == nil {
		info.ModifiedAt = v.CreatedAt.Unix()
	}
}

// GetFile renvoie ce qu'il faut pour relire une version d'un fichier : époque, seuil,
// manifeste et nœuds. Un destinataire reçoit aussi son autorisation, à présenter aux nœuds.
func (s *coordinatorServer) GetFile(ctx context.Context, req *pb.GetFileRequest) (*pb.GetFileResponse, error) {
	a, err := s.fileAccess(ctx, req.FileId, access.Read)
	if err != nil {
		return nil, err
	}
	if a.file.Status != metadata.FileReady {
		return nil, status.Error(codes.FailedPrecondition, "dépôt pas encore confirmé")
	}
	m, v, err := s.store.Manifest(a.file.ID, req.Version)
	if errors.Is(err, metadata.ErrNotFound) {
		return nil, status.Errorf(codes.NotFound, "version %d introuvable", req.Version)
	}
	if err != nil {
		return nil, internalError(err)
	}
	nodes, err := s.store.FileNodes(a.file.ID)
	if err != nil {
		return nil, internalError(err)
	}
	return &pb.GetFileResponse{
		Epoch: a.file.Epoch,
		T:     a.file.T,
		Manifest: &pb.Manifest{
			BlockCount:  m.BlockCount,
			BlockHashes: m.BlockHashes,
			NoncePrefix: m.NoncePrefix,
			Size:        m.Size,
		},
		Nodes:          nodeInfosUpFirst(nodes),
		Grant:          a.grant,
		Version:        v.Number,
		Rights:         a.rights,
		CurrentVersion: a.file.CurrentVersion,
	}, nil
}

// ListVersions liste les versions confirmées d'un fichier (droit r).
func (s *coordinatorServer) ListVersions(ctx context.Context, req *pb.ListVersionsRequest) (*pb.ListVersionsResponse, error) {
	a, err := s.fileAccess(ctx, req.FileId, access.Read)
	if err != nil {
		return nil, err
	}
	versions, err := s.store.Versions(a.file.ID)
	if err != nil {
		return nil, internalError(err)
	}
	resp := &pb.ListVersionsResponse{}
	for _, v := range versions {
		resp.Versions = append(resp.Versions, &pb.VersionInfo{
			Version: v.Number, Size: v.Size, Author: v.Author, CreatedAt: v.CreatedAt.Unix()})
	}
	return resp, nil
}

// RenameFile remplace le nom chiffré du fichier pour chaque utilisateur cité (propriétaire
// ou droit m). Le client a chiffré le nouveau nom pour chacun.
func (s *coordinatorServer) RenameFile(ctx context.Context, req *pb.RenameFileRequest) (*pb.RenameFileResponse, error) {
	a, err := s.fileAccess(ctx, req.FileId, access.Manage)
	if err != nil {
		return nil, err
	}
	for _, n := range req.Names {
		if len(n.EncryptedName) == 0 || len(n.EncryptedName) > maxNameSize {
			return nil, status.Error(codes.InvalidArgument, "nom chiffré vide ou trop long")
		}
		u, err := s.store.UserByName(n.Username)
		if errors.Is(err, metadata.ErrNotFound) {
			return nil, errUserNotFound
		}
		if err != nil {
			return nil, internalError(err)
		}
		if u.ID == a.file.OwnerID {
			err = s.store.SetFileName(a.file.ID, n.EncryptedName)
		} else {
			err = s.store.SetGrantName(a.file.ID, u.ID, n.EncryptedName)
		}
		if errors.Is(err, metadata.ErrNotFound) {
			return nil, status.Errorf(codes.InvalidArgument, "%s n'a pas accès à ce fichier", n.Username)
		}
		if err != nil {
			return nil, internalError(err)
		}
	}
	return &pb.RenameFileResponse{}, nil
}

// RemoveFile supprime un fichier chez le coordinateur (propriétaire ou droit d), une fois
// ses parts et ses blocs effacés des nœuds par le client.
func (s *coordinatorServer) RemoveFile(ctx context.Context, req *pb.RemoveFileRequest) (*pb.RemoveFileResponse, error) {
	a, err := s.fileAccess(ctx, req.FileId, access.Delete)
	if err != nil {
		return nil, err
	}
	if err := s.store.DeleteFile(a.file.ID); err != nil && !errors.Is(err, metadata.ErrNotFound) {
		return nil, internalError(err)
	}
	return &pb.RemoveFileResponse{}, nil
}

// TransferFile donne le fichier à un autre utilisateur. Le transfert est signé par le
// propriétaire actuel ; les nœuds l'ont déjà enregistré quand le client l'envoie ici.
func (s *coordinatorServer) TransferFile(ctx context.Context, req *pb.TransferFileRequest) (*pb.TransferFileResponse, error) {
	t := req.Transfer
	if t == nil || len(req.EncryptedName) == 0 || len(req.EncryptedName) > maxNameSize {
		return nil, status.Error(codes.InvalidArgument, "transfert ou nom chiffré manquant")
	}
	a, err := s.fileAccess(ctx, t.FileId, access.All)
	if err != nil {
		return nil, err
	}
	if a.grant != nil {
		return nil, status.Error(codes.PermissionDenied, "seul le propriétaire peut transférer le fichier")
	}
	newOwner, err := s.store.UserByName(req.NewOwner)
	if errors.Is(err, metadata.ErrNotFound) {
		return nil, errUserNotFound
	}
	if err != nil {
		return nil, internalError(err)
	}
	c, err := s.accessContext(a.file)
	if err != nil {
		return nil, internalError(err)
	}
	if !bytes.Equal(t.NewOwnerPublicKey, newOwner.PublicKey) || !bytes.Equal(t.OwnerPublicKey, a.user.PublicKey) {
		return nil, status.Error(codes.InvalidArgument, "transfert fait pour d'autres clés")
	}
	if err := access.VerifyTransfer(t, c); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "transfert refusé : %v", err)
	}
	if err := s.store.TransferFile(a.file.ID, newOwner.ID, t.TransferredAt, req.EncryptedName); err != nil {
		return nil, internalError(err)
	}
	return &pb.TransferFileResponse{}, nil
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
