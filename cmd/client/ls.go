package main

import (
	"context"
	"fmt"
	pb "safevault/proto"
	"time"
)

// runList affiche les fichiers accessibles à l'utilisateur.
func runList(cfg Config) error {
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
	for _, f := range resp.Files {
		fmt.Printf("%s  %10d octets  %s\n", f.FileId, f.Size, f.Name)
	}
	return nil
}
