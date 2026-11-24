package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"safevault/internal/access"
	"safevault/internal/crypto"
	pb "safevault/proto"
)

// shareValidity est la durée de validité d'une autorisation de partage.
const shareValidity = 30 * 24 * time.Hour

// runWhoami affiche le nom de l'utilisateur et l'empreinte de sa clé publique, à
// comparer avec celle que voit la personne qui lui partage un fichier.
func runWhoami(cfg Config) error {
	privateKey, err := loadKey(cfg.KeyPath)
	if err != nil {
		return err
	}
	fmt.Printf("Utilisateur : %s\nEmpreinte de votre clé : %s\n",
		cfg.Username, access.Fingerprint(privateKey.Public().(ed25519.PublicKey)))
	return nil
}

// runShare partage le fichier fileID avec l'utilisateur grantee, en lecture seule :
//  1. la clé publique du destinataire est demandée au coordinateur et son empreinte
//     affichée, pour que le propriétaire puisse la vérifier avec lui ;
//  2. le client signe une autorisation pour cette clé, que les nœuds vérifieront ;
//  3. le nom du fichier est rechiffré pour le destinataire.
func runShare(cfg Config, fileID, grantee string) error {
	privateKey, err := loadKey(cfg.KeyPath)
	if err != nil {
		return err
	}
	coordinator, conn, err := connectCoordinator(cfg)
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	authCtx, err := login(ctx, cfg, coordinator)
	if err != nil {
		return err
	}

	key, err := coordinator.GetUserKey(authCtx, &pb.GetUserKeyRequest{Username: grantee})
	if err != nil {
		return fmt.Errorf("clé de %s : %w", grantee, err)
	}
	if len(key.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("clé de %s invalide", grantee)
	}
	fmt.Printf("Empreinte de la clé de %s : %s\n", grantee, access.Fingerprint(key.PublicKey))
	fmt.Printf("(à comparer avec celle que %s obtient avec la commande whoami)\n", grantee)

	file, err := findOwnFile(authCtx, coordinator, fileID)
	if err != nil {
		return err
	}
	namesKey, err := crypto.NamesKey(privateKey)
	if err != nil {
		return err
	}
	name, err := crypto.OpenName(namesKey, file.EncryptedName)
	clear(namesKey)
	if err != nil {
		return err
	}
	nameForGrantee, err := crypto.SealNameFor(key.PublicKey, name)
	if err != nil {
		return err
	}

	grant := access.NewGrant(privateKey, fileID, key.PublicKey, time.Now(), shareValidity)
	_, err = coordinator.ShareFile(authCtx, &pb.ShareFileRequest{
		Grantee: grantee, Grant: grant, EncryptedName: nameForGrantee,
	})
	if err != nil {
		return fmt.Errorf("partage : %w", err)
	}
	fmt.Printf("Fichier « %s » partagé avec %s en lecture, jusqu'au %s.\n",
		name, grantee, time.Unix(grant.ExpiresAt, 0).Format("02/01/2006"))
	return nil
}

// runRevoke retire l'accès de grantee au fichier fileID : une révocation signée est
// envoyée à chaque nœud (qui refusera ensuite l'ancienne autorisation), puis le partage
// est retiré chez le coordinateur.
func runRevoke(cfg Config, fileID, grantee string) error {
	privateKey, err := loadKey(cfg.KeyPath)
	if err != nil {
		return err
	}
	coordinator, conn, err := connectCoordinator(cfg)
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	authCtx, err := login(ctx, cfg, coordinator)
	if err != nil {
		return err
	}

	key, err := coordinator.GetUserKey(authCtx, &pb.GetUserKeyRequest{Username: grantee})
	if err != nil {
		return fmt.Errorf("clé de %s : %w", grantee, err)
	}
	file, err := coordinator.GetFile(authCtx, &pb.GetFileRequest{FileId: fileID})
	if err != nil {
		return fmt.Errorf("GetFile : %w", err)
	}
	if file.Grant != nil {
		return fmt.Errorf("seul le propriétaire du fichier peut retirer un accès")
	}

	revocation := access.NewRevocation(privateKey, fileID, key.PublicKey, time.Now())
	revoked := 0
	for _, info := range file.Nodes {
		if err := sendRevocation(ctx, cfg, info, revocation); err != nil {
			fmt.Printf("nœud %s : révocation non enregistrée (%v)\n", info.Address, err)
			continue
		}
		revoked++
	}

	if _, err := coordinator.RevokeShare(authCtx, &pb.RevokeShareRequest{FileId: fileID, Grantee: grantee}); err != nil {
		fmt.Printf("coordinateur : %v\n", err)
	}

	// Le destinataire a besoin de t parts : il est bloqué dès que moins de t nœuds
	// acceptent encore son autorisation, soit au moins n - t + 1 révocations.
	needed := len(file.Nodes) - int(file.T) + 1
	fmt.Printf("Révocation enregistrée sur %d nœud(s) sur %d.\n", revoked, len(file.Nodes))
	if revoked < needed {
		fmt.Printf("Attention : il en faut au moins %d pour bloquer %s ; relancez la commande quand les nœuds seront revenus.\n",
			needed, grantee)
	} else {
		fmt.Printf("%s ne peut plus récupérer le fichier.\n", grantee)
	}
	return nil
}

func sendRevocation(ctx context.Context, cfg Config, info *pb.NodeInfo, r *pb.Revocation) error {
	node, conn, err := connectNode(cfg, info.Address)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err = node.Revoke(ctx, &pb.RevokeRequest{Revocation: r})
	return err
}
