package main

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"safevault/internal/access"
	"safevault/internal/crypto"
	pb "safevault/proto"
)

// runList affiche les fichiers accessibles : les siens, puis ceux partagés avec
// l'utilisateur. Les noms arrivent chiffrés du coordinateur et sont déchiffrés ici.
func runList(cfg Config) error {
	a, err := open(cfg, 30*time.Second)
	if err != nil {
		return err
	}
	defer a.close()

	resp, err := a.coord.ListFiles(a.ctx, &pb.ListFilesRequest{})
	if err != nil {
		return err
	}
	if len(resp.Files) == 0 {
		info("Aucun fichier. Déposez-en un avec « client upload <fichier> ».")
		return nil
	}
	t := newTable("ID", "NOM", "PROPRIÉTAIRE", "DROITS", "VERSION", "TAILLE*", "MODIFIÉ", "ACCÈS JUSQU'AU")
	for _, f := range resp.Files {
		owner := "moi"
		expiry := "-"
		if f.Shared {
			owner = f.Owner
			expiry = humanExpiry(f.ExpiresAt)
		}
		t.row(shortID(f.FileId), a.openName(f.EncryptedName), owner, access.RightsString(f.Rights),
			"v"+strconv.Itoa(int(f.Version)), humanSize(f.Size), humanDate(f.ModifiedAt), expiry)
	}
	t.flush()
	info("* taille arrondie, la seule que connaît le coordinateur. Droits : r lire, w modifier, s repartager, d supprimer, m gérer les accès.")
	return nil
}

// runVersions affiche l'historique des versions d'un fichier.
func runVersions(cfg Config, ref string) error {
	a, err := open(cfg, 30*time.Second)
	if err != nil {
		return err
	}
	defer a.close()

	f, name, err := a.resolve(ref)
	if err != nil {
		return err
	}
	resp, err := a.coord.ListVersions(a.ctx, &pb.ListVersionsRequest{FileId: f.FileId})
	if err != nil {
		return err
	}
	fmt.Printf("%s %s\n", bold(name), dim("("+f.FileId+")"))
	t := newTable("VERSION", "AUTEUR", "TAILLE*", "DATE", "")
	for _, v := range resp.Versions {
		current := ""
		if v.Version == f.Version {
			current = green("actuelle")
		}
		t.row("v"+strconv.Itoa(int(v.Version)), v.Author, humanSize(v.Size), humanDate(v.CreatedAt), current)
	}
	t.flush()
	info("Récupérer une ancienne version : client download %s --version <n>", shortID(f.FileId))
	return nil
}

// runRename renomme un fichier (propriétaire ou droit m). Le coordinateur ne connaît pas
// les noms : le client chiffre le nouveau nom pour chaque utilisateur qui a accès.
func runRename(cfg Config, ref, newName string) error {
	a, err := open(cfg, 30*time.Second)
	if err != nil {
		return err
	}
	defer a.close()

	f, name, err := a.resolve(ref)
	if err != nil {
		return err
	}
	if f.Rights&access.Manage == 0 {
		return fmt.Errorf("il faut le droit de gérer les accès (m) pour renommer « %s »", name)
	}
	entries, err := a.coord.ListAccess(a.ctx, &pb.ListAccessRequest{FileId: f.FileId})
	if err != nil {
		return err
	}
	req := &pb.RenameFileRequest{FileId: f.FileId}
	for _, e := range entries.Entries {
		sealed, err := crypto.SealNameFor(e.PublicKey, newName)
		if err != nil {
			return err
		}
		req.Names = append(req.Names, &pb.UserName{Username: e.Username, EncryptedName: sealed})
	}
	if _, err := a.coord.RenameFile(a.ctx, req); err != nil {
		return err
	}
	success("« %s » renommé en « %s » pour les %d personnes qui y ont accès.", name, bold(newName), len(req.Names))
	return nil
}

// runRemove supprime un fichier et toutes ses versions (propriétaire ou droit d) : les nœuds
// effacent parts et blocs, puis le coordinateur oublie le fichier.
func runRemove(cfg Config, ref string) error {
	a, err := open(cfg, time.Minute)
	if err != nil {
		return err
	}
	defer a.close()

	f, name, err := a.resolve(ref)
	if err != nil {
		return err
	}
	if f.Rights&access.Delete == 0 {
		return fmt.Errorf("il faut le droit de supprimer (d) pour supprimer « %s »", name)
	}
	file, err := a.coord.GetFile(a.ctx, &pb.GetFileRequest{FileId: f.FileId})
	if err != nil {
		return err
	}
	erased := 0
	for _, n := range file.Nodes {
		err := withNode(a.ctx, a.cfg, n, func(ctx context.Context, node pb.NodeClient) error {
			_, err := node.DeleteFile(ctx, &pb.DeleteFileRequest{
				FileId: f.FileId, Grant: file.Grant,
				Proof: proof(a.key, "safevault/delete/v1", n.X, f.FileId, 0),
			})
			return err
		})
		if err != nil && status.Code(err) != codes.NotFound { // déjà effacé : rien à faire
			warn("nœud %s : %s", n.Address, describe(err))
			continue
		}
		erased++
	}
	// Tant que t nœuds gardent leur part, le fichier reste reconstructible : on ne
	// l'oublie pas chez le coordinateur, pour pouvoir relancer la suppression.
	if remaining := len(file.Nodes) - erased; remaining >= int(file.T) {
		return fmt.Errorf("suppression incomplète : %d nœuds gardent encore leur part (il en faut moins de %d) ; relancez la commande quand ils seront revenus",
			remaining, file.T)
	}
	if _, err := a.coord.RemoveFile(a.ctx, &pb.RemoveFileRequest{FileId: f.FileId}); err != nil {
		return err
	}
	success("« %s » supprimé avec ses %d versions (effacé sur %d nœuds sur %d).", bold(name), f.Version, erased, len(file.Nodes))
	return nil
}

// withNode ouvre une connexion à un nœud le temps d'un appel.
func withNode(ctx context.Context, cfg Config, info *pb.NodeInfo, call func(context.Context, pb.NodeClient) error) error {
	node, conn, err := connectNode(cfg, info.Address)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return call(ctx, node)
}
