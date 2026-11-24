package main

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"safevault/internal/access"
	"safevault/internal/metadata"
	pb "safevault/proto"
)

// errUserNotFound est renvoyée pour un destinataire inconnu.
var errUserNotFound = status.Error(codes.NotFound, "utilisateur inconnu")

// GetUserKey renvoie la clé publique d'un utilisateur, pour lui partager un fichier.
// Le client en affiche l'empreinte : le propriétaire peut la comparer avec le
// destinataire et détecter une clé substituée par un coordinateur malveillant.
func (s *coordinatorServer) GetUserKey(ctx context.Context, req *pb.GetUserKeyRequest) (*pb.GetUserKeyResponse, error) {
	if !usernamePattern.MatchString(req.Username) {
		return nil, status.Error(codes.InvalidArgument, "nom d'utilisateur invalide")
	}
	u, err := s.store.UserByName(req.Username)
	if errors.Is(err, metadata.ErrNotFound) {
		return nil, errUserNotFound
	}
	if err != nil {
		return nil, internalError(err)
	}
	return &pb.GetUserKeyResponse{PublicKey: u.PublicKey}, nil
}

// ShareFile enregistre un partage. L'autorisation est signée par le propriétaire : le
// coordinateur la vérifie (fichier, propriétaire, destinataire, validité) avant de la
// garder, mais c'est aux nœuds de l'accepter ou non au moment de la lecture.
func (s *coordinatorServer) ShareFile(ctx context.Context, req *pb.ShareFileRequest) (*pb.ShareFileResponse, error) {
	userID, _ := userFromContext(ctx)
	g := req.Grant
	if g == nil || len(req.EncryptedName) == 0 || len(req.EncryptedName) > maxNameSize {
		return nil, status.Error(codes.InvalidArgument, "autorisation ou nom chiffré manquant")
	}
	setCallFile(ctx, g.FileId)

	owner, err := s.store.UserByID(userID)
	if err != nil {
		return nil, internalError(err)
	}
	grantee, err := s.store.UserByName(req.Grantee)
	if errors.Is(err, metadata.ErrNotFound) {
		return nil, errUserNotFound
	}
	if err != nil {
		return nil, internalError(err)
	}
	if err := access.VerifyGrantFor(g, g.FileId, owner.PublicKey, grantee.PublicKey, s.now()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "autorisation refusée : %v", err)
	}

	signed, err := proto.Marshal(g)
	if err != nil {
		return nil, internalError(err)
	}
	err = s.store.PutGrant(g.FileId, userID, grantee.ID, signed, req.EncryptedName)
	switch {
	case errors.Is(err, metadata.ErrNotFound), errors.Is(err, metadata.ErrNotOwner):
		return nil, errFileNotFound
	case errors.Is(err, metadata.ErrConflict):
		return nil, status.Error(codes.FailedPrecondition, "dépôt pas encore confirmé")
	case errors.Is(err, metadata.ErrInvalidArgument):
		return nil, status.Error(codes.InvalidArgument, "partage avec soi-même")
	case err != nil:
		return nil, internalError(err)
	}
	return &pb.ShareFileResponse{}, nil
}

// RevokeShare retire un partage côté coordinateur : le destinataire ne voit plus le
// fichier et ne reçoit plus l'autorisation. Le client envoie aussi aux nœuds une
// révocation signée, pour qu'une autorisation gardée par le destinataire soit refusée.
func (s *coordinatorServer) RevokeShare(ctx context.Context, req *pb.RevokeShareRequest) (*pb.RevokeShareResponse, error) {
	userID, _ := userFromContext(ctx)
	setCallFile(ctx, req.FileId)
	grantee, err := s.store.UserByName(req.Grantee)
	if errors.Is(err, metadata.ErrNotFound) {
		return nil, errUserNotFound
	}
	if err != nil {
		return nil, internalError(err)
	}
	err = s.store.DeleteGrant(req.FileId, userID, grantee.ID)
	if errors.Is(err, metadata.ErrNotFound) {
		return nil, status.Error(codes.NotFound, "aucun partage de ce fichier avec cet utilisateur")
	}
	if err != nil {
		return nil, internalError(err)
	}
	return &pb.RevokeShareResponse{}, nil
}
