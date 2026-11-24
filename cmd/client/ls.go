package main

import (
	"context"
	"fmt"
	"time"

	"safevault/internal/crypto"
	pb "safevault/proto"
)

// runList affiche les fichiers accessibles à l'utilisateur : les siens, puis ceux qui lui
// sont partagés. Les noms arrivent chiffrés du coordinateur et sont déchiffrés ici.
func runList(cfg Config) error {
	privateKey, err := loadKey(cfg.KeyPath)
	if err != nil {
		return err
	}
	coordinator, conn, err := connectCoordinator(cfg)
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ctx, err = login(ctx, cfg, coordinator)
	if err != nil {
		return err
	}

	resp, err := coordinator.ListFiles(ctx, &pb.ListFilesRequest{})
	if err != nil {
		return err
	}

	if len(resp.Files) == 0 {
		fmt.Println("Aucun fichier.")
		return nil
	}
	namesKey, err := crypto.NamesKey(privateKey)
	if err != nil {
		return err
	}
	defer clear(namesKey)

	for _, f := range resp.Files {
		var name string
		if f.Shared {
			name, err = crypto.OpenNameFrom(privateKey, f.EncryptedName)
		} else {
			name, err = crypto.OpenName(namesKey, f.EncryptedName)
		}
		if err != nil {
			name = "(nom illisible)"
		}
		origin := "à moi"
		if f.Shared {
			origin = "partagé par " + f.Owner
		}
		fmt.Printf("%s  %10d octets (arrondi)  %-20s  %s\n", f.FileId, f.Size, origin, name)
	}
	return nil
}

// findOwnFile renvoie, parmi les fichiers listés par le coordinateur, le fichier fileID
// s'il appartient à l'utilisateur.
func findOwnFile(ctx context.Context, coordinator pb.CoordinatorClient, fileID string) (*pb.FileInfo, error) {
	resp, err := coordinator.ListFiles(ctx, &pb.ListFilesRequest{})
	if err != nil {
		return nil, err
	}
	for _, f := range resp.Files {
		if f.FileId == fileID && !f.Shared {
			return f, nil
		}
	}
	return nil, fmt.Errorf("fichier %s introuvable parmi vos fichiers", fileID)
}
