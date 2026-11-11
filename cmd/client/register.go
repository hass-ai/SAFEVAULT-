package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"time"

	pb "safevault/proto"

	"google.golang.org/grpc/metadata"
)

// runRegister crée la clé de l'utilisateur et l'inscrit auprès du coordinateur.
func runRegister(cfg Config) error {
	if cfg.Username == "" {
		return errors.New("définissez CLIENT_USERNAME")
	}
	if _, err := os.Stat(cfg.KeyPath); err == nil {
		return fmt.Errorf("une clé existe déjà dans %s", cfg.KeyPath)
	}

	privateKey, err := generateKey(cfg.KeyPath)
	if err != nil {
		return err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)

	coordinator, conn, err := connectCoordinator(cfg)
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	message := append([]byte(cfg.Username), publicKey...)
	_, err = coordinator.Register(ctx, &pb.RegisterRequest{
		Username:  cfg.Username,
		PublicKey: publicKey,
		Signature: sign(privateKey, "safevault/register/v1", message),
	})
	if err != nil {
		os.Remove(cfg.KeyPath) // inscription refusée : on ne garde pas une clé inutile
		return fmt.Errorf("inscription refusée : %w", err)
	}

	fmt.Println("Inscription réussie :", cfg.Username)
	return nil
}

// login s'authentifie auprès du coordinateur et renvoie un contexte qui contient le jeton.
func login(ctx context.Context, cfg Config, coordinator pb.CoordinatorClient) (context.Context, error) {
	if cfg.Username == "" {
		return nil, errors.New("définissez SAFEVAULT_USERNAME")
	}
	privateKey, err := loadKey(cfg.KeyPath)
	if err != nil {
		return nil, err
	}

	challenge, err := coordinator.GetChallenge(ctx, &pb.GetChallengeRequest{Username: cfg.Username})
	if err != nil {
		return nil, err
	}

	resp, err := coordinator.Login(ctx, &pb.LoginRequest{
		Username:  cfg.Username,
		Challenge: challenge.Challenge,
		Signature: sign(privateKey, "safevault/login/v1", challenge.Challenge),
	})
	if err != nil {
		return nil, fmt.Errorf("connexion refusée : %w", err)
	}

	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+resp.Token), nil
}
