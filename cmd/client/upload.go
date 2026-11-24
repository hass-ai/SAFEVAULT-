package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"filippo.io/edwards25519"

	"safevault/internal/access"
	"safevault/internal/crypto"
	"safevault/internal/shamir"
	pb "safevault/proto"
)

// uploadTarget décrit où déposer une version : fichier, numéro, époque et nœuds.
type uploadTarget struct {
	fileID  string
	version uint32
	epoch   uint64
	t, n    uint32
	nodes   []*pb.NodeInfo
}

// runUpload chiffre le fichier path et le dépose comme nouveau fichier.
func runUpload(cfg Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	a, err := open(cfg, 5*time.Minute)
	if err != nil {
		return err
	}
	defer a.close()

	// Métadonnées : le coordinateur ne reçoit qu'un nom chiffré et une taille arrondie.
	name := filepath.Base(path)
	encryptedName, err := crypto.SealNameFor(a.publicKey(), name)
	if err != nil {
		return err
	}
	padded := crypto.Pad(data)

	file, err := a.coord.CreateFile(a.ctx, &pb.CreateFileRequest{EncryptedName: encryptedName, Size: uint64(len(padded))})
	if err != nil {
		return fmt.Errorf("dépôt refusé : %w", err)
	}
	target := uploadTarget{fileID: file.FileId, version: 1, epoch: file.Epoch, t: file.T, n: file.N, nodes: file.Nodes}
	if err := a.pushVersion(target, padded, nil); err != nil {
		return err
	}
	success("%s déposé (%s, chiffré et réparti sur %d nœuds, seuil %d)", bold(name), humanSize(uint64(len(data))), file.N, file.T)
	fmt.Println("  identifiant : " + file.FileId)
	return nil
}

// runUpdate dépose le contenu de path comme nouvelle version du fichier ref (droit w).
// Chaque version a son propre secret ; les anciennes restent lisibles.
func runUpdate(cfg Config, ref, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	a, err := open(cfg, 5*time.Minute)
	if err != nil {
		return err
	}
	defer a.close()

	f, name, err := a.resolve(ref)
	if err != nil {
		return err
	}
	if f.Rights&access.Write == 0 {
		return fmt.Errorf("vous n'avez pas le droit de modifier « %s » (droits : %s)", name, access.RightsString(f.Rights))
	}
	current, err := a.coord.GetFile(a.ctx, &pb.GetFileRequest{FileId: f.FileId})
	if err != nil {
		return err
	}
	padded := crypto.Pad(data)
	v, err := a.coord.CreateVersion(a.ctx, &pb.CreateVersionRequest{FileId: f.FileId, Size: uint64(len(padded))})
	if err != nil {
		return fmt.Errorf("nouvelle version refusée : %w", err)
	}
	target := uploadTarget{fileID: f.FileId, version: v.Version, epoch: v.Epoch, t: v.T, n: v.N, nodes: v.Nodes}
	if err := a.pushVersion(target, padded, current.Grant); err != nil {
		return err
	}
	success("%s : version %d déposée (%s)", bold(name), v.Version, humanSize(uint64(len(data))))
	return nil
}

// pushVersion chiffre padded avec un nouveau secret, envoie une part et tous les blocs à
// chaque nœud, puis fait confirmer la version par le coordinateur.
func (a *app) pushVersion(target uploadTarget, padded []byte, grant *pb.Grant) error {
	secret, err := shamir.NewSecret(rand.Reader)
	if err != nil {
		return err
	}
	defer secret.Set(edwards25519.NewScalar()) // remise à zéro du secret

	secretBytes := secret.Bytes()
	defer clear(secretBytes)

	label := crypto.VersionContext(target.fileID, target.version)
	key, err := crypto.DeriveFileKey(secretBytes, label)
	if err != nil {
		return err
	}
	defer clear(key)

	fileCipher, err := crypto.NewFileCipher(key, label)
	if err != nil {
		return err
	}
	blocks, err := fileCipher.EncryptBlocks(bytes.NewReader(padded), crypto.DefaultBlockSize)
	if err != nil {
		return err
	}

	shares, err := shamir.Split(secret, int(target.t), int(target.n), rand.Reader)
	if err != nil {
		return err
	}
	defer func() {
		for _, s := range shares {
			s.Value.Set(edwards25519.NewScalar()) // remise à zéro des parts
		}
	}()
	sharesByX := make(map[uint32]shamir.Share)
	for _, s := range shares {
		sharesByX[s.Index] = s
	}

	for _, node := range target.nodes {
		share, ok := sharesByX[node.X]
		if !ok {
			return fmt.Errorf("aucune part pour le nœud x = %d", node.X)
		}
		if err := sendToNode(a.ctx, a.cfg, a.key, target, node, share, blocks, grant); err != nil {
			return fmt.Errorf("nœud %s : %w", node.Address, err)
		}
	}

	hashes := make([][]byte, len(blocks))
	for i, b := range blocks {
		h := sha256.Sum256(b)
		hashes[i] = h[:]
	}
	_, err = a.coord.ConfirmUpload(a.ctx, &pb.ConfirmUploadRequest{
		FileId:  target.fileID,
		Version: target.version,
		Manifest: &pb.Manifest{
			BlockCount:  uint32(len(blocks)),
			BlockHashes: hashes,
			Size:        uint64(len(padded)),
		},
	})
	if err != nil {
		return fmt.Errorf("confirmation refusée : %w", err)
	}
	return nil
}

// sendToNode envoie à un nœud sa part de la clé, puis tous les blocs chiffrés.
func sendToNode(ctx context.Context, cfg Config, key ed25519.PrivateKey, target uploadTarget,
	info *pb.NodeInfo, share shamir.Share, blocks [][]byte, grant *pb.Grant) error {

	node, conn, err := connectNode(cfg, info.Address)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = node.PutShare(ctx, &pb.PutShareRequest{
		FileId:  target.fileID,
		Share:   &pb.Share{X: share.Index, Value: share.Value.Bytes(), Epoch: target.epoch},
		Proof:   proof(key, "safevault/putshare/v1", info.X, target.fileID, target.epoch),
		Version: target.version,
		Grant:   grant,
	})
	if err != nil {
		return fmt.Errorf("dépôt de la part : %w", err)
	}

	stream, err := node.PutBlocks(ctx)
	if err != nil {
		return fmt.Errorf("envoi des blocs : %w", err)
	}
	for i, b := range blocks {
		err := stream.Send(&pb.Block{
			FileId:  target.fileID,
			Index:   uint32(i),
			Data:    b,
			Proof:   proof(key, "safevault/putblocks/v1", info.X, target.fileID, target.epoch),
			Version: target.version,
		})
		if err != nil {
			return fmt.Errorf("envoi du bloc %d : %w", i, err)
		}
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		return fmt.Errorf("envoi des blocs : %w", err)
	}
	if resp.Stored != uint32(len(blocks)) {
		return fmt.Errorf("%d blocs stockés sur %d", resp.Stored, len(blocks))
	}
	return nil
}
