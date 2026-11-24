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

// runDownload récupère une version du fichier ref (0 = la version actuelle), la déchiffre
// et l'écrit dans output (par défaut : son nom, dans le dossier courant).
func runDownload(cfg Config, ref, output string, version uint32, force bool) error {
	a, err := open(cfg, 5*time.Minute)
	if err != nil {
		return err
	}
	defer a.close()

	f, name, err := a.resolve(ref)
	if err != nil {
		return err
	}
	if output == "" {
		output = filepath.Base(name)
	}
	if _, err := os.Stat(output); err == nil && !force {
		return fmt.Errorf("%s existe déjà : choisissez une autre sortie (-o) ou ajoutez --force", output)
	}
	fileID := f.FileId

	var file *pb.GetFileResponse
	var secret *edwards25519.Scalar
	for attempt := 1; ; attempt++ {
		file, err = a.coord.GetFile(a.ctx, &pb.GetFileRequest{FileId: fileID, Version: version})
		if err != nil {
			return err
		}
		secret, err = collectSecret(a.ctx, cfg, a.key, fileID, file)
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

	label := crypto.VersionContext(fileID, file.Version)
	key, err := crypto.DeriveFileKey(secretBytes, label)
	if err != nil {
		return err
	}
	defer clear(key)

	fileCipher, err := crypto.NewFileCipher(key, label)
	if err != nil {
		return err
	}

	blocks, err := fetchBlocks(a.ctx, cfg, a.key, fileID, file)
	if err != nil {
		return err
	}
	size, err := writeDecrypted(fileCipher, blocks, output)
	if err != nil {
		return err
	}
	success("%s récupéré dans %s (version %d sur %d, %s)", bold(name), output, file.Version, file.CurrentVersion,
		humanSize(uint64(size)))
	return nil
}

// writeDecrypted déchiffre les blocs, retire le remplissage, et écrit le résultat dans un
// fichier temporaire renommé ensuite en output : en cas d'erreur, aucun fichier à moitié
// déchiffré n'est laissé.
func writeDecrypted(fileCipher *crypto.FileCipher, blocks [][]byte, output string) (int, error) {
	var padded bytes.Buffer
	if err := fileCipher.DecryptBlocks(blocks, &padded); err != nil {
		return 0, fmt.Errorf("déchiffrement impossible (part ou bloc incorrect) : %w", err)
	}
	data, err := crypto.Unpad(padded.Bytes())
	if err != nil {
		return 0, err
	}

	tmp, err := os.CreateTemp(filepath.Dir(output), ".safevault-*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp.Name()) // sans effet si le renommage a réussi

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		return 0, err
	}
	return len(data), os.Rename(tmp.Name(), output)
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
		share, err := getShare(ctx, cfg, key, fileID, file.Epoch, file.Version, info, file.Grant)
		if status.Code(err) == codes.FailedPrecondition {
			return nil, errEpochChanged
		}
		if err != nil {
			warn("nœud %s ignoré : %s", info.Address, describe(err))
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

// getShare demande à un nœud sa part de la clé pour l'époque donnée. grant est l'autorisation
// du propriétaire quand le fichier est partagé avec nous (nil pour le propriétaire).
func getShare(ctx context.Context, cfg Config, key ed25519.PrivateKey, fileID string, epoch uint64,
	version uint32, info *pb.NodeInfo, grant *pb.Grant) (*pb.Share, error) {

	node, conn, err := connectNode(cfg, info.Address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := node.GetShare(ctx, &pb.GetShareRequest{
		FileId:  fileID,
		Epoch:   epoch,
		Proof:   proof(key, "safevault/getshare/v1", info.X, fileID, epoch),
		Grant:   grant,
		Version: version,
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
		blocks, err := getBlocks(ctx, cfg, key, fileID, info, file)
		if err == nil {
			return blocks, nil
		}
		warn("nœud %s ignoré : %s", info.Address, describe(err))
	}
	return nil, errors.New("aucun nœud n'a renvoyé les blocs")
}

// getBlocks récupère tous les blocs d'un nœud et vérifie chacun avec son empreinte du manifeste.
func getBlocks(ctx context.Context, cfg Config, key ed25519.PrivateKey, fileID string,
	info *pb.NodeInfo, file *pb.GetFileResponse) ([][]byte, error) {

	manifest, grant := file.Manifest, file.Grant

	node, conn, err := connectNode(cfg, info.Address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	stream, err := node.GetBlocks(ctx, &pb.GetBlocksRequest{
		FileId:  fileID,
		Proof:   proof(key, "safevault/getblocks/v1", info.X, fileID, 0),
		Grant:   grant,
		Version: file.Version,
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
