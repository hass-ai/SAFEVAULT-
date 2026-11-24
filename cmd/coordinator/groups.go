package main

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"safevault/internal/metadata"
	pb "safevault/proto"
)

// Les groupes sont des listes d'utilisateurs propres à chacun, pour partager un fichier
// avec plusieurs personnes en une commande. Le partage reste individuel : le client signe
// une autorisation pour chaque membre, les nœuds ne connaissent pas les groupes.

var errGroupNotFound = status.Error(codes.NotFound, "groupe introuvable")

func validGroupName(name string) error {
	if !usernamePattern.MatchString(name) {
		return status.Error(codes.InvalidArgument, "nom de groupe invalide")
	}
	return nil
}

// CreateGroup crée un groupe de l'utilisateur connecté.
func (s *coordinatorServer) CreateGroup(ctx context.Context, req *pb.CreateGroupRequest) (*pb.CreateGroupResponse, error) {
	userID, _ := userFromContext(ctx)
	if err := validGroupName(req.Name); err != nil {
		return nil, err
	}
	err := s.store.CreateGroup(userID, req.Name)
	if errors.Is(err, metadata.ErrAlreadyExists) {
		return nil, status.Error(codes.AlreadyExists, "ce groupe existe déjà")
	}
	if err != nil {
		return nil, internalError(err)
	}
	return &pb.CreateGroupResponse{}, nil
}

// DeleteGroup supprime un groupe de l'utilisateur connecté (les partages déjà faits restent).
func (s *coordinatorServer) DeleteGroup(ctx context.Context, req *pb.DeleteGroupRequest) (*pb.DeleteGroupResponse, error) {
	userID, _ := userFromContext(ctx)
	err := s.store.DeleteGroup(userID, req.Name)
	if errors.Is(err, metadata.ErrNotFound) {
		return nil, errGroupNotFound
	}
	if err != nil {
		return nil, internalError(err)
	}
	return &pb.DeleteGroupResponse{}, nil
}

// AddGroupMember ajoute un utilisateur à un groupe de l'utilisateur connecté.
func (s *coordinatorServer) AddGroupMember(ctx context.Context, req *pb.GroupMemberRequest) (*pb.GroupMemberResponse, error) {
	return s.changeMember(ctx, req, s.store.AddGroupMember)
}

// RemoveGroupMember retire un utilisateur d'un groupe de l'utilisateur connecté.
func (s *coordinatorServer) RemoveGroupMember(ctx context.Context, req *pb.GroupMemberRequest) (*pb.GroupMemberResponse, error) {
	return s.changeMember(ctx, req, s.store.RemoveGroupMember)
}

func (s *coordinatorServer) changeMember(ctx context.Context, req *pb.GroupMemberRequest,
	change func(ownerID int64, group string, userID int64) error) (*pb.GroupMemberResponse, error) {

	userID, _ := userFromContext(ctx)
	member, err := s.store.UserByName(req.Username)
	if errors.Is(err, metadata.ErrNotFound) {
		return nil, errUserNotFound
	}
	if err != nil {
		return nil, internalError(err)
	}
	err = change(userID, req.Group, member.ID)
	if errors.Is(err, metadata.ErrNotFound) {
		return nil, status.Error(codes.NotFound, "groupe ou membre introuvable")
	}
	if err != nil {
		return nil, internalError(err)
	}
	return &pb.GroupMemberResponse{}, nil
}

// ListGroups renvoie les groupes de l'utilisateur connecté avec leurs membres et leurs clés.
func (s *coordinatorServer) ListGroups(ctx context.Context, req *pb.ListGroupsRequest) (*pb.ListGroupsResponse, error) {
	userID, _ := userFromContext(ctx)
	user, err := s.store.UserByID(userID)
	if err != nil {
		return nil, internalError(err)
	}
	groups, err := s.store.Groups(userID)
	if err != nil {
		return nil, internalError(err)
	}
	resp := &pb.ListGroupsResponse{}
	for _, g := range groups {
		info := &pb.GroupInfo{Name: g.Name, Owner: user.Username}
		for _, m := range g.Members {
			info.Members = append(info.Members, &pb.GroupMember{Username: m.Username, PublicKey: m.PublicKey})
		}
		resp.Groups = append(resp.Groups, info)
	}
	return resp, nil
}
