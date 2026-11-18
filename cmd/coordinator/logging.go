package main

import (
	"context"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// healthPrefix désigne les appels du health check, trop fréquents pour être journalisés.
const healthPrefix = "/grpc.health.v1.Health/"

// callInfo collecte, pendant un appel, ce qui sera journalisé : qui (identifiant interne
// de l'utilisateur, jamais son nom) et sur quel fichier. Les intercepteurs et les RPC le
// remplissent ; logUnary l'écrit à la fin de l'appel.
type callInfo struct {
	mu     sync.Mutex
	userID int64
	fileID string
}

type callInfoKey struct{}

// setCallUser note l'utilisateur de l'appel en cours pour le journal.
func setCallUser(ctx context.Context, userID int64) {
	if info, ok := ctx.Value(callInfoKey{}).(*callInfo); ok {
		info.mu.Lock()
		info.userID = userID
		info.mu.Unlock()
	}
}

// setCallFile note le fichier de l'appel en cours pour le journal.
func setCallFile(ctx context.Context, fileID string) {
	if info, ok := ctx.Value(callInfoKey{}).(*callInfo); ok {
		info.mu.Lock()
		info.fileID = fileID
		info.mu.Unlock()
	}
}

// logUnary journalise chaque appel : méthode, utilisateur, fichier, code gRPC et durée (G10).
// Le contenu des requêtes n'est jamais journalisé : il peut contenir des noms de
// fichiers, des défis, des signatures ou des jetons.
func logUnary(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if strings.HasPrefix(info.FullMethod, healthPrefix) {
		return handler(ctx, req)
	}
	call := &callInfo{}
	start := time.Now()
	resp, err := handler(context.WithValue(ctx, callInfoKey{}, call), req)

	call.mu.Lock()
	user, file := "-", "-"
	if call.userID != 0 {
		user = strconv.FormatInt(call.userID, 10)
	}
	if call.fileID != "" {
		file = call.fileID
	}
	call.mu.Unlock()
	log.Printf("rpc=%s user=%s file=%s code=%s durée=%s",
		info.FullMethod, user, file, status.Code(err), time.Since(start).Round(time.Microsecond))
	return resp, err
}

// internalError journalise la cause d'une erreur interne et renvoie au client une
// erreur sans détail.
func internalError(err error) error {
	log.Printf("erreur interne : %v", err)
	return status.Error(codes.Internal, "erreur interne")
}
