package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcmd "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"safevault/internal/metadata"
	pb "safevault/proto"
)

// Étiquettes des messages signés, identiques à celles du client (voir coordinator.proto).
const (
	labelRegister = "safevault/register/v1"
	labelLogin    = "safevault/login/v1"
)

const (
	challengeSize = 32             // octets aléatoires d'un défi
	challengeTTL  = time.Minute    // durée de validité d'un défi
	tokenSize     = 32             // octets aléatoires d'un jeton de session
	sessionTTL    = 12 * time.Hour // durée de validité d'un jeton de session
)

// usernamePattern limite les noms d'utilisateur à des caractères simples.
var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// errUnauthenticated est la seule erreur renvoyée en cas d'échec de connexion :
// le client ne sait pas si c'est le nom, le défi ou la signature qui est faux.
var errUnauthenticated = status.Error(codes.Unauthenticated, "authentification refusée")

// signedMessage reconstruit le message signé : étiquette || 0x00 || données.
func signedMessage(label string, parts ...[]byte) []byte {
	msg := append([]byte(label), 0)
	for _, p := range parts {
		msg = append(msg, p...)
	}
	return msg
}

// randomBytes renvoie n octets tirés avec crypto/rand.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Register inscrit un utilisateur après avoir vérifié qu'il possède la clé privée
// correspondant à la clé publique envoyée.
func (s *coordinatorServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if !usernamePattern.MatchString(req.Username) {
		return nil, status.Error(codes.InvalidArgument, "nom d'utilisateur invalide")
	}
	if len(req.PublicKey) != ed25519.PublicKeySize || len(req.Signature) != ed25519.SignatureSize {
		return nil, status.Error(codes.InvalidArgument, "clé publique ou signature de taille invalide")
	}
	msg := signedMessage(labelRegister, []byte(req.Username), req.PublicKey)
	if !ed25519.Verify(req.PublicKey, msg, req.Signature) {
		return nil, status.Error(codes.InvalidArgument, "signature invalide")
	}

	id, err := s.store.CreateUser(req.Username, req.PublicKey)
	if errors.Is(err, metadata.ErrAlreadyExists) {
		return nil, status.Error(codes.AlreadyExists, "nom d'utilisateur ou clé déjà inscrits")
	}
	if err != nil {
		return nil, internalError(err)
	}
	setCallUser(ctx, id)
	return &pb.RegisterResponse{}, nil
}

// GetChallenge renvoie un défi aléatoire à usage unique. Pour un nom inconnu, un défi
// est quand même renvoyé (mais pas enregistré) : la réponse ne révèle pas qui est inscrit.
func (s *coordinatorServer) GetChallenge(ctx context.Context, req *pb.GetChallengeRequest) (*pb.GetChallengeResponse, error) {
	challenge, err := randomBytes(challengeSize)
	if err != nil {
		return nil, internalError(err)
	}
	user, err := s.store.UserByName(req.Username)
	if errors.Is(err, metadata.ErrNotFound) {
		return &pb.GetChallengeResponse{Challenge: challenge}, nil
	}
	if err != nil {
		return nil, internalError(err)
	}
	if err := s.store.PutChallenge(user.ID, challenge, s.now().Add(challengeTTL)); err != nil {
		return nil, internalError(err)
	}
	setCallUser(ctx, user.ID)
	return &pb.GetChallengeResponse{Challenge: challenge}, nil
}

// Login vérifie la signature du défi et renvoie un jeton de session.
// Le défi est consommé AVANT la vérification : une signature fausse le brûle aussi.
func (s *coordinatorServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	user, err := s.store.UserByName(req.Username)
	if errors.Is(err, metadata.ErrNotFound) {
		return nil, errUnauthenticated
	}
	if err != nil {
		return nil, internalError(err)
	}
	setCallUser(ctx, user.ID)

	err = s.store.ConsumeChallenge(user.ID, req.Challenge)
	if errors.Is(err, metadata.ErrNotFound) || errors.Is(err, metadata.ErrExpired) {
		return nil, errUnauthenticated
	}
	if err != nil {
		return nil, internalError(err)
	}
	if len(req.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(user.PublicKey, signedMessage(labelLogin, req.Challenge), req.Signature) {
		return nil, errUnauthenticated
	}

	raw, err := randomBytes(tokenSize)
	if err != nil {
		return nil, internalError(err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	if err := s.store.PutSession([]byte(token), user.ID, s.now().Add(sessionTTL)); err != nil {
		return nil, internalError(err)
	}
	return &pb.LoginResponse{Token: token}, nil
}

// publicMethods sont les RPC accessibles sans jeton.
var publicMethods = map[string]bool{
	pb.Coordinator_Register_FullMethodName:     true,
	pb.Coordinator_GetChallenge_FullMethodName: true,
	pb.Coordinator_Login_FullMethodName:        true,
}

type userKey struct{}

// userFromContext renvoie l'utilisateur authentifié par l'intercepteur.
func userFromContext(ctx context.Context) (int64, bool) {
	id, ok := ctx.Value(userKey{}).(int64)
	return id, ok
}

// authUnary vérifie le jeton « authorization: Bearer <jeton> » de toute RPC du service
// Coordinator qui n'est pas publique, et place l'utilisateur dans le contexte.
func (s *coordinatorServer) authUnary(ctx context.Context, req any, info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler) (any, error) {

	if publicMethods[info.FullMethod] || strings.HasPrefix(info.FullMethod, healthPrefix) {
		return handler(ctx, req)
	}
	token, ok := bearerToken(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "jeton manquant")
	}
	userID, err := s.store.SessionUser([]byte(token))
	if errors.Is(err, metadata.ErrNotFound) || errors.Is(err, metadata.ErrExpired) {
		return nil, status.Error(codes.Unauthenticated, "jeton invalide ou expiré")
	}
	if err != nil {
		return nil, internalError(err)
	}
	setCallUser(ctx, userID)
	return handler(context.WithValue(ctx, userKey{}, userID), req)
}

// bearerToken lit le jeton de l'en-tête authorization.
func bearerToken(ctx context.Context) (string, bool) {
	md, ok := grpcmd.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}
	values := md.Get("authorization")
	if len(values) != 1 {
		return "", false
	}
	token, found := strings.CutPrefix(values[0], "Bearer ")
	if !found || token == "" {
		return "", false
	}
	return token, true
}
