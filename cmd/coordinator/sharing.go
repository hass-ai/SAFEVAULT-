package main

import (
	"bytes"
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

// fileAccessInfo décrit ce que l'utilisateur connecté peut faire sur un fichier.
type fileAccessInfo struct {
	file   metadata.File
	user   metadata.User
	rights uint32
	grant  *pb.Grant // autorisation de l'utilisateur (nil pour le propriétaire)
}

// accessContext rassemble ce que le coordinateur sait d'un fichier pour vérifier une
// autorisation : propriétaire actuel, anciens propriétaires et retraits d'accès. Le
// coordinateur fait les mêmes vérifications que les nœuds, pour ne pas montrer un fichier
// qu'ils refuseraient ; mais ce sont les nœuds qui décident.
func (s *coordinatorServer) accessContext(f metadata.File) (access.Context, error) {
	owner, err := s.store.UserByID(f.OwnerID)
	if err != nil {
		return access.Context{}, err
	}
	previous, err := s.store.PreviousOwners(f.ID)
	if err != nil {
		return access.Context{}, err
	}
	owners := []access.Owner{{Key: owner.PublicKey}}
	for _, p := range previous {
		owners = append(owners, access.Owner{Key: p.PublicKey, Until: p.Until})
	}
	return access.Context{
		FileID: f.ID,
		Owners: owners,
		RevokedAt: func(grantee []byte) (int64, bool, error) {
			return s.store.RevokedAt(f.ID, grantee)
		},
		Now: s.now(),
	}, nil
}

// grantRights vérifie l'autorisation enregistrée signed pour la clé holder et renvoie ses droits.
func (s *coordinatorServer) grantRights(f metadata.File, signed, holder []byte) (uint32, *pb.Grant, error) {
	g := &pb.Grant{}
	if err := proto.Unmarshal(signed, g); err != nil {
		return 0, nil, err
	}
	c, err := s.accessContext(f)
	if err != nil {
		return 0, nil, err
	}
	rights, err := access.VerifyGrantFor(g, holder, access.Read, c)
	return rights, g, err
}

// fileAccess renvoie les droits de l'utilisateur connecté sur le fichier fileID, et une
// erreur s'il n'a pas les droits want. Un fichier auquel il n'a aucun accès est
// « introuvable » : un utilisateur ne peut pas savoir si un identifiant existe chez un autre.
func (s *coordinatorServer) fileAccess(ctx context.Context, fileID string, want uint32) (*fileAccessInfo, error) {
	userID, _ := userFromContext(ctx)
	setCallFile(ctx, fileID)
	f, err := s.store.File(fileID)
	if errors.Is(err, metadata.ErrNotFound) {
		return nil, errFileNotFound
	}
	if err != nil {
		return nil, internalError(err)
	}
	user, err := s.store.UserByID(userID)
	if err != nil {
		return nil, internalError(err)
	}
	a := &fileAccessInfo{file: f, user: user}
	if f.OwnerID == userID {
		a.rights = access.All
		return a, nil
	}
	signed, err := s.store.Grant(f.ID, userID)
	if errors.Is(err, metadata.ErrNotFound) {
		return nil, errFileNotFound
	}
	if err != nil {
		return nil, internalError(err)
	}
	a.rights, a.grant, err = s.grantRights(f, signed, user.PublicKey)
	if err != nil {
		return nil, errFileNotFound // autorisation expirée ou retirée
	}
	if a.rights&want != want {
		return nil, status.Errorf(codes.PermissionDenied, "droits insuffisants : vous avez %s, il faut %s",
			access.RightsString(a.rights), access.RightsString(want))
	}
	return a, nil
}

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

// ShareFile enregistre une autorisation signée par l'utilisateur connecté : le propriétaire,
// un utilisateur qui a le droit de repartager (s) ou de gérer les accès (m), ou un ancien
// propriétaire pour une autorisation signée avant le transfert. Le coordinateur vérifie
// toute la chaîne avant de la garder, mais ce sont les nœuds qui l'acceptent ou non.
func (s *coordinatorServer) ShareFile(ctx context.Context, req *pb.ShareFileRequest) (*pb.ShareFileResponse, error) {
	userID, _ := userFromContext(ctx)
	g := req.Grant
	if g == nil || len(req.EncryptedName) == 0 || len(req.EncryptedName) > maxNameSize {
		return nil, status.Error(codes.InvalidArgument, "autorisation ou nom chiffré manquant")
	}
	setCallFile(ctx, g.FileId)

	f, err := s.store.File(g.FileId)
	if errors.Is(err, metadata.ErrNotFound) {
		return nil, errFileNotFound
	}
	if err != nil {
		return nil, internalError(err)
	}
	issuer, err := s.store.UserByID(userID)
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
	if !bytes.Equal(g.IssuerPublicKey, issuer.PublicKey) {
		return nil, status.Error(codes.InvalidArgument, "autorisation signée par une autre clé")
	}
	c, err := s.accessContext(f)
	if err != nil {
		return nil, internalError(err)
	}
	if _, err := access.VerifyGrantFor(g, grantee.PublicKey, access.Read, c); err != nil {
		if errors.Is(err, access.ErrNotOwner) || errors.Is(err, access.ErrDelegation) {
			return nil, status.Errorf(codes.PermissionDenied, "partage refusé : %v", err)
		}
		return nil, status.Errorf(codes.InvalidArgument, "autorisation refusée : %v", err)
	}

	signed, err := proto.Marshal(g)
	if err != nil {
		return nil, internalError(err)
	}
	err = s.store.PutGrant(g.FileId, grantee.ID, signed, req.EncryptedName)
	switch {
	case errors.Is(err, metadata.ErrNotFound):
		return nil, errFileNotFound
	case errors.Is(err, metadata.ErrConflict):
		return nil, status.Error(codes.FailedPrecondition, "dépôt pas encore confirmé")
	case errors.Is(err, metadata.ErrInvalidArgument):
		return nil, status.Error(codes.InvalidArgument, "le destinataire est le propriétaire du fichier")
	case err != nil:
		return nil, internalError(err)
	}
	return &pb.ShareFileResponse{}, nil
}

// RevokeShare enregistre un retrait d'accès signé (propriétaire ou droit m) et retire le
// partage : le destinataire ne voit plus le fichier, et les accès qu'il avait lui-même
// donnés tombent avec le sien. Le client envoie la même révocation aux nœuds.
func (s *coordinatorServer) RevokeShare(ctx context.Context, req *pb.RevokeShareRequest) (*pb.RevokeShareResponse, error) {
	r := req.Revocation
	if r == nil || r.FileId != req.FileId {
		return nil, status.Error(codes.InvalidArgument, "révocation manquante")
	}
	a, err := s.fileAccess(ctx, req.FileId, access.Manage)
	if err != nil {
		return nil, err
	}
	grantee, err := s.store.UserByName(req.Grantee)
	if errors.Is(err, metadata.ErrNotFound) {
		return nil, errUserNotFound
	}
	if err != nil {
		return nil, internalError(err)
	}
	if !bytes.Equal(r.IssuerPublicKey, a.user.PublicKey) || !bytes.Equal(r.GranteePublicKey, grantee.PublicKey) {
		return nil, status.Error(codes.InvalidArgument, "révocation faite pour d'autres clés")
	}
	c, err := s.accessContext(a.file)
	if err != nil {
		return nil, internalError(err)
	}
	if err := access.VerifyRevocation(r, c); err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "révocation refusée : %v", err)
	}
	if err := s.store.PutRevocation(a.file.ID, r.GranteePublicKey, r.RevokedAt); err != nil {
		return nil, internalError(err)
	}
	if err := s.store.DeleteGrant(a.file.ID, grantee.ID); err != nil && !errors.Is(err, metadata.ErrNotFound) {
		return nil, internalError(err)
	}
	// Les autorisations qui dépendaient de celle-ci ne valent plus rien : on les retire.
	grants, err := s.store.GrantsOf(a.file.ID)
	if err != nil {
		return nil, internalError(err)
	}
	for _, g := range grants {
		if _, _, err := s.grantRights(a.file, g.SignedGrant, g.Grantee.PublicKey); errors.Is(err, access.ErrRevoked) {
			if err := s.store.DeleteGrant(a.file.ID, g.Grantee.ID); err != nil && !errors.Is(err, metadata.ErrNotFound) {
				return nil, internalError(err)
			}
		}
	}
	return &pb.RevokeShareResponse{}, nil
}

// ListAccess liste qui a accès au fichier, avec quels droits (propriétaire, ou droit s ou m).
func (s *coordinatorServer) ListAccess(ctx context.Context, req *pb.ListAccessRequest) (*pb.ListAccessResponse, error) {
	a, err := s.fileAccess(ctx, req.FileId, access.Read)
	if err != nil {
		return nil, err
	}
	if a.rights&(access.Share|access.Manage) == 0 {
		return nil, status.Error(codes.PermissionDenied, "il faut le droit de partager (s) ou de gérer (m) pour voir les accès")
	}
	owner, err := s.store.UserByID(a.file.OwnerID)
	if err != nil {
		return nil, internalError(err)
	}
	resp := &pb.ListAccessResponse{Entries: []*pb.AccessEntry{{
		Username: owner.Username, PublicKey: owner.PublicKey, Rights: access.All, Owner: true,
	}}}
	grants, err := s.store.GrantsOf(a.file.ID)
	if err != nil {
		return nil, internalError(err)
	}
	for _, row := range grants {
		rights, g, err := s.grantRights(a.file, row.SignedGrant, row.Grantee.PublicKey)
		if err != nil {
			continue // expirée ou retirée
		}
		entry := &pb.AccessEntry{
			Username: row.Grantee.Username, PublicKey: row.Grantee.PublicKey, Rights: rights,
			ExpiresAt: access.Expiry(g), GrantedAt: g.IssuedAt,
		}
		if issuer, err := s.store.UserByKey(g.IssuerPublicKey); err == nil {
			entry.GrantedBy = issuer.Username
		}
		resp.Entries = append(resp.Entries, entry)
	}
	return resp, nil
}
