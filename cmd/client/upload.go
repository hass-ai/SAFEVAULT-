package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"safevault/internal/crypto"
	"safevault/internal/shamir"
	pb "safevault/proto"
)

// runUpload chiffre le fichier path et le dépose sur les nœuds.
func runUpload(cfg Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	privateKey, err := loadKey(cfg.KeyPath)
	if err != nil {
		return err
	}

	coordinator, conn, err := connectCoordinator(cfg)
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	authCtx, err := login(ctx, cfg, coordinator)
	if err != nil {
		return err
	}

	file, err := coordinator.CreateFile(authCtx, &pb.CreateFileRequest{
		Name: filepath.Base(path),
		Size: uint64(len(data)),
	})
	if err != nil {
		return fmt.Errorf("CreateFile : %w", err)
	}

	secret, err := shamir.RandomSecret()
	if err != nil {
		return err
	}
	defer clear(secret)

	key, err := crypto.DeriveFileKey(secret, file.FileId)
	if err != nil {
		return err
	}
	defer clear(key)

	blocks, noncePrefix, err := crypto.EncryptBlocks(key, data)
	if err != nil {
		return err
	}

	shares, err := shamir.Split(secret, int(file.T), int(file.N))
	if err != nil {
		return err
	}
	defer func() {
		for _, s := range shares {
			clear(s.Value)
		}
	}()
	sharesByX := make(map[uint32]shamir.Share)
	for _, s := range shares {
		sharesByX[s.X] = s
	}

	for _, node := range file.Nodes {
		share, ok := sharesByX[node.X]
		if !ok {
			return fmt.Errorf("aucune part pour le nœud x = %d", node.X)
		}
		if err := sendToNode(ctx, cfg, privateKey, file.FileId, file.Epoch, node, share, blocks); err != nil {
			return fmt.Errorf("nœud %s : %w", node.Address, err)
		}
	}

	hashes := make([][]byte, len(blocks))
	for i, b := range blocks {
		h := sha256.Sum256(b)
		hashes[i] = h[:]
	}
	_, err = coordinator.ConfirmUpload(authCtx, &pb.ConfirmUploadRequest{
		FileId: file.FileId,
		Manifest: &pb.Manifest{
			BlockCount:  uint32(len(blocks)),
			BlockHashes: hashes,
			NoncePrefix: noncePrefix,
			Size:        uint64(len(data)),
		},
	})
	if err != nil {
		return fmt.Errorf("ConfirmUpload : %w", err)
	}

	fmt.Println("Fichier déposé :", file.FileId)
	return nil
}

// sendToNode envoie à un nœud sa part de la clé, puis tous les blocs chiffrés.
func sendToNode(ctx context.Context, cfg Config, key ed25519.PrivateKey, fileID string, epoch uint64,
	info *pb.NodeInfo, share shamir.Share, blocks [][]byte) error {

	node, conn, err := connectNode(cfg, info.Address)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = node.PutShare(ctx, &pb.PutShareRequest{
		FileId: fileID,
		Share:  &pb.Share{X: share.X, Value: share.Value, Epoch: epoch},
		Proof:  proof(key, "safevault/putshare/v1", info.X, fileID, epoch),
	})
	if err != nil {
		return fmt.Errorf("PutShare : %w", err)
	}

	stream, err := node.PutBlocks(ctx)
	if err != nil {
		return fmt.Errorf("PutBlocks : %w", err)
	}
	for i, b := range blocks {
		err := stream.Send(&pb.Block{
			FileId: fileID,
			Index:  uint32(i),
			Data:   b,
			Proof:  proof(key, "safevault/putblocks/v1", info.X, fileID, epoch),
		})
		if err != nil {
			return fmt.Errorf("PutBlocks, bloc %d : %w", i, err)
		}
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		return fmt.Errorf("PutBlocks : %w", err)
	}
	if resp.Stored != uint32(len(blocks)) {
		return fmt.Errorf("PutBlocks : %d blocs stockés sur %d", resp.Stored, len(blocks))
	}
	return nil
}
