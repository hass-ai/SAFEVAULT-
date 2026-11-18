package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"filippo.io/edwards25519"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"safevault/internal/crypto"
	"safevault/internal/shamir"
	pb "safevault/proto"
)

// errEpochChanged signale qu'un renouvellement a eu lieu pendant la récupération.
var errEpochChanged = errors.New("l'époque a changé pendant la récupération")

// runDownload récupère le fichier fileID, le déchiffre et l'écrit dans output.
func runDownload(cfg Config, fileID, output string) error {
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

	var file *pb.GetFileResponse
	var secret *edwards25519.Scalar
	for attempt := 1; ; attempt++ {
		file, err = coordinator.GetFile(authCtx, &pb.GetFileRequest{FileId: fileID})
		if err != nil {
			return fmt.Errorf("GetFile : %w", err)
		}
		secret, err = collectSecret(ctx, cfg, privateKey, fileID, file)
		if err == nil {
			break
		}
		if !errors.Is(err, errEpochChanged) || attempt == 3 {
			return err
		}
		time.Sleep(time.Second)
	}
	defer secret.Set(edwards25519.NewScalar()) // remise à zéro du secret

	secretBytes := secret.Bytes()
	defer clear(secretBytes)

	key, err := crypto.DeriveFileKey(secretBytes, []byte(fileID))
	if err != nil {
		return err
	}
	defer clear(key)

	fileCipher, err := crypto.NewFileCipher(key, []byte(fileID))
	if err != nil {
		return err
	}

	blocks, err := fetchBlocks(ctx, cfg, privateKey, fileID, file)
	if err != nil {
		return err
	}

	if err := writeDecrypted(fileCipher, blocks, output); err != nil {
		return err
	}
	fmt.Println("Fichier récupéré :", output)
	return nil
}

// writeDecrypted déchiffre les blocs dans un fichier temporaire, puis le renomme en output :
// en cas d'erreur, aucun fichier à moitié déchiffré n'est laissé.
func writeDecrypted(fileCipher *crypto.FileCipher, blocks [][]byte, output string) error {
	tmp, err := os.CreateTemp(filepath.Dir(output), ".safevault-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // sans effet si le renommage a réussi

	if err := fileCipher.DecryptBlocks(blocks, tmp); err != nil {
		tmp.Close()
		return fmt.Errorf("déchiffrement impossible (part ou bloc incorrect) : %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), output)
}

// collectSecret demande leur part aux nœuds jusqu'à en avoir t de la même époque, puis reconstruit le secret.
func collectSecret(ctx context.Context, cfg Config, key ed25519.PrivateKey, fileID string,
	file *pb.GetFileResponse) (*edwards25519.Scalar, error) {

	var shares []shamir.Share
	defer func() {
		for _, s := range shares {
			s.Value.Set(edwards25519.NewScalar()) // remise à zéro des parts
		}
	}()

	for _, info := range file.Nodes {
		if len(shares) == int(file.T) {
			break
		}
		share, err := getShare(ctx, cfg, key, fileID, file.Epoch, info)
		if status.Code(err) == codes.FailedPrecondition {
			return nil, errEpochChanged
		}
		if err != nil {
			fmt.Printf("nœud %s ignoré : %v\n", info.Address, err)
			continue
		}
		if share.Epoch != file.Epoch {
			return nil, errEpochChanged
		}
		if share.X != info.X {
			fmt.Printf("nœud %s ignoré : part pour x = %d au lieu de %d\n", info.Address, share.X, info.X)
			continue
		}
		value, err := edwards25519.NewScalar().SetCanonicalBytes(share.Value)
		if err != nil {
			fmt.Printf("nœud %s ignoré : part mal formée\n", info.Address)
			continue
		}
		shares = append(shares, shamir.Share{Index: share.X, Epoch: share.Epoch, Value: value})
	}

	if len(shares) < int(file.T) {
		return nil, fmt.Errorf("seulement %d parts sur les %d nécessaires", len(shares), file.T)
	}
	return shamir.Combine(shares, int(file.T))
}

// getShare demande à un nœud sa part de la clé pour l'époque donnée.
func getShare(ctx context.Context, cfg Config, key ed25519.PrivateKey, fileID string, epoch uint64,
	info *pb.NodeInfo) (*pb.Share, error) {

	node, conn, err := connectNode(cfg, info.Address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := node.GetShare(ctx, &pb.GetShareRequest{
		FileId: fileID,
		Epoch:  epoch,
		Proof:  proof(key, "safevault/getshare/v1", info.X, fileID, epoch),
	})
	if err != nil {
		return nil, err
	}
	return resp.Share, nil
}

// fetchBlocks récupère tous les blocs chiffrés auprès du premier nœud qui répond correctement.
func fetchBlocks(ctx context.Context, cfg Config, key ed25519.PrivateKey, fileID string,
	file *pb.GetFileResponse) ([][]byte, error) {

	for _, info := range file.Nodes {
		blocks, err := getBlocks(ctx, cfg, key, fileID, info, file.Manifest)
		if err == nil {
			return blocks, nil
		}
		fmt.Printf("nœud %s ignoré : %v\n", info.Address, err)
	}
	return nil, errors.New("aucun nœud n'a renvoyé les blocs")
}

// getBlocks récupère tous les blocs d'un nœud et vérifie chacun avec son empreinte du manifeste.
func getBlocks(ctx context.Context, cfg Config, key ed25519.PrivateKey, fileID string,
	info *pb.NodeInfo, manifest *pb.Manifest) ([][]byte, error) {

	node, conn, err := connectNode(cfg, info.Address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	stream, err := node.GetBlocks(ctx, &pb.GetBlocksRequest{
		FileId: fileID,
		Proof:  proof(key, "safevault/getblocks/v1", info.X, fileID, 0),
	})
	if err != nil {
		return nil, err
	}

	blocks := make([][]byte, manifest.BlockCount)
	for {
		b, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if b.Index >= manifest.BlockCount {
			return nil, fmt.Errorf("bloc %d inattendu", b.Index)
		}
		if h := sha256.Sum256(b.Data); !bytes.Equal(h[:], manifest.BlockHashes[b.Index]) {
			return nil, fmt.Errorf("bloc %d modifié", b.Index)
		}
		blocks[b.Index] = b.Data
	}

	for i, b := range blocks {
		if b == nil {
			return nil, fmt.Errorf("bloc %d manquant", i)
		}
	}
	return blocks, nil
}
