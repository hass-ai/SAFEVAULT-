package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"safevault/internal/access"
	"safevault/internal/crypto"
	pb "safevault/proto"
)

// recipient est un utilisateur visé par un partage.
type recipient struct {
	username string
	key      ed25519.PublicKey
}

// recipients renvoie les utilisateurs désignés par target : un nom d'utilisateur, ou
// « @groupe » pour tous les membres d'un de ses groupes.
func (a *app) recipients(target string) ([]recipient, error) {
	if group, ok := strings.CutPrefix(target, "@"); ok {
		resp, err := a.coord.ListGroups(a.ctx, &pb.ListGroupsRequest{})
		if err != nil {
			return nil, err
		}
		for _, g := range resp.Groups {
			if g.Name == group {
				var list []recipient
				for _, m := range g.Members {
					list = append(list, recipient{m.Username, m.PublicKey})
				}
				if len(list) == 0 {
					return nil, fmt.Errorf("le groupe %s est vide", group)
				}
				return list, nil
			}
		}
		return nil, fmt.Errorf("groupe %s introuvable (voir « client group ls »)", group)
	}
	resp, err := a.coord.GetUserKey(a.ctx, &pb.GetUserKeyRequest{Username: target})
	if err != nil {
		return nil, fmt.Errorf("%s : %w", target, err)
	}
	if len(resp.PublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("clé de %s invalide", target)
	}
	return []recipient{{target, resp.PublicKey}}, nil
}

// parseExpiry lit une fin d'accès : « never » ou « jamais » (sans limite), une durée
// (« 7d », « 12h », « 30m ») ou une date (« 2026-12-31 » ou « 31/12/2026 », jusqu'au soir).
func parseExpiry(s string, now time.Time) (time.Time, error) {
	switch strings.ToLower(s) {
	case "", "never", "jamais":
		return time.Time{}, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		if n, err := strconv.Atoi(days); err == nil && n > 0 {
			return now.AddDate(0, 0, n), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return now.Add(d), nil
	}
	for _, layout := range []string{"2006-01-02", "02/01/2006"} {
		if day, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			end := day.Add(24*time.Hour - time.Second)
			if !end.After(now) {
				return time.Time{}, errors.New("date d'expiration déjà passée")
			}
			return end, nil
		}
	}
	return time.Time{}, fmt.Errorf("expiration %q illisible (exemples : 7d, 12h, 2026-12-31, never)", s)
}

// runShare partage le fichier ref avec un utilisateur ou un groupe :
//  1. la clé publique de chaque destinataire est demandée au coordinateur et son
//     empreinte affichée, pour être vérifiée avec lui (commande whoami) ;
//  2. le client signe une autorisation pour cette clé, avec les droits et l'expiration
//     choisis ; un utilisateur qui n'est pas propriétaire y joint sa propre autorisation,
//     et les nœuds vérifient toute la chaîne ;
//  3. le nom du fichier est chiffré pour le destinataire.
//
// Si le destinataire avait déjà plus de droits, son ancien accès est d'abord retiré :
// une autorisation signée ne peut pas être modifiée, seulement révoquée.
func runShare(cfg Config, ref, target, rightsText, expireText string) error {
	rights, err := access.ParseRights(rightsText)
	if err != nil {
		return err
	}
	expires, err := parseExpiry(expireText, time.Now())
	if err != nil {
		return err
	}
	a, err := open(cfg, time.Minute)
	if err != nil {
		return err
	}
	defer a.close()

	f, name, err := a.resolve(ref)
	if err != nil {
		return err
	}
	file, err := a.coord.GetFile(a.ctx, &pb.GetFileRequest{FileId: f.FileId})
	if err != nil {
		return err
	}
	mine := file.Rights
	if mine&(access.Share|access.Manage) == 0 {
		return fmt.Errorf("vous n'avez pas le droit de partager « %s » (droits : %s)", name, access.RightsString(mine))
	}
	if mine&access.Manage == 0 {
		if extra := rights &^ mine; extra != 0 {
			return fmt.Errorf("vous ne pouvez pas donner plus que vos droits (%s)", access.RightsString(mine))
		}
		if end := access.Expiry(file.Grant); end != 0 && (expires.IsZero() || expires.Unix() > end) {
			expires = time.Unix(end, 0)
			info("Expiration ramenée au %s, la fin de votre propre accès.", humanExpiry(end))
		}
	}

	targets, err := a.recipients(target)
	if err != nil {
		return err
	}
	current := map[string]*pb.AccessEntry{}
	if entries, err := a.coord.ListAccess(a.ctx, &pb.ListAccessRequest{FileId: f.FileId}); err == nil {
		for _, e := range entries.Entries {
			current[e.Username] = e
		}
	}

	shared := 0
	for _, r := range targets {
		if r.username == a.user || r.username == f.Owner {
			continue // on ne partage pas avec soi-même ni avec le propriétaire
		}
		fmt.Printf("%s  empreinte de la clé : %s\n", bold(r.username), access.Fingerprint(r.key))
		issuedAt := time.Now()
		if old := current[r.username]; old != nil && reduces(old, rights, expires) {
			if mine&access.Manage == 0 {
				warn("%s a déjà un accès (%s, jusqu'à : %s) que ce partage réduirait : il faut le droit m pour le modifier.",
					r.username, access.RightsString(old.Rights), humanExpiry(old.ExpiresAt))
				continue
			}
			if err := a.revokeOne(f.FileId, file, r, issuedAt); err != nil {
				return err
			}
			issuedAt = issuedAt.Add(time.Second) // la nouvelle autorisation suit le retrait
		}

		nameFor, err := crypto.SealNameFor(r.key, name)
		if err != nil {
			return err
		}
		g := access.NewGrant(a.key, f.FileId, r.key, rights, issuedAt, expires, file.Grant)
		_, err = a.coord.ShareFile(a.ctx, &pb.ShareFileRequest{Grantee: r.username, Grant: g, EncryptedName: nameFor})
		if err != nil {
			return fmt.Errorf("partage avec %s : %w", r.username, err)
		}
		success("« %s » partagé avec %s : droits %s, jusqu'à : %s", name, bold(r.username),
			access.RightsString(rights), humanExpiry(g.ExpiresAt))
		shared++
	}
	if shared > 0 {
		info("Vérifiez les empreintes avec les destinataires (commande whoami) : c'est ce qui garantit que le coordinateur n'a pas substitué de clé.")
	}
	return nil
}

// reduces indique si le nouvel accès est plus restreint que l'accès actuel.
func reduces(old *pb.AccessEntry, rights uint32, expires time.Time) bool {
	if old.Rights&^rights != 0 {
		return true
	}
	if expires.IsZero() {
		return false
	}
	return old.ExpiresAt == 0 || expires.Unix() < old.ExpiresAt
}

// runRevoke retire l'accès d'un utilisateur ou d'un groupe (propriétaire ou droit m). Les
// accès que ces personnes avaient donnés tombent avec le leur.
func runRevoke(cfg Config, ref, target string) error {
	a, err := open(cfg, time.Minute)
	if err != nil {
		return err
	}
	defer a.close()

	f, name, err := a.resolve(ref)
	if err != nil {
		return err
	}
	file, err := a.coord.GetFile(a.ctx, &pb.GetFileRequest{FileId: f.FileId})
	if err != nil {
		return err
	}
	if file.Rights&access.Manage == 0 {
		return fmt.Errorf("il faut être propriétaire ou avoir le droit m pour retirer un accès à « %s »", name)
	}
	targets, err := a.recipients(target)
	if err != nil {
		return err
	}
	for _, r := range targets {
		if r.username == a.user || r.username == f.Owner {
			continue
		}
		if err := a.revokeOne(f.FileId, file, r, time.Now()); err != nil {
			return err
		}
	}
	return nil
}

// revokeOne signe le retrait de l'accès de r, l'envoie à chaque nœud puis au coordinateur.
func (a *app) revokeOne(fileID string, file *pb.GetFileResponse, r recipient, at time.Time) error {
	revocation := access.NewRevocation(a.key, fileID, r.key, at, file.Grant)
	revoked := 0
	for _, n := range file.Nodes {
		err := withNode(a.ctx, a.cfg, n, func(ctx context.Context, node pb.NodeClient) error {
			_, err := node.Revoke(ctx, &pb.RevokeRequest{Revocation: revocation})
			return err
		})
		if err != nil {
			warn("nœud %s : retrait non enregistré (%s)", n.Address, describe(err))
			continue
		}
		revoked++
	}
	if _, err := a.coord.RevokeShare(a.ctx, &pb.RevokeShareRequest{FileId: fileID, Grantee: r.username, Revocation: revocation}); err != nil {
		return fmt.Errorf("retrait chez le coordinateur : %w", err)
	}
	// Il faut t parts pour lire : l'accès est coupé dès que n - t + 1 nœuds ont enregistré
	// le retrait.
	needed := len(file.Nodes) - int(file.T) + 1
	if revoked < needed {
		warn("Retrait enregistré sur %d nœuds sur %d, il en faut %d pour bloquer %s : relancez la commande quand les nœuds seront revenus.",
			revoked, len(file.Nodes), needed, r.username)
		return nil
	}
	success("Accès de %s retiré (enregistré sur %d nœuds sur %d).", bold(r.username), revoked, len(file.Nodes))
	return nil
}

// runAccess affiche qui a accès au fichier et avec quels droits.
func runAccess(cfg Config, ref string) error {
	a, err := open(cfg, 30*time.Second)
	if err != nil {
		return err
	}
	defer a.close()

	f, name, err := a.resolve(ref)
	if err != nil {
		return err
	}
	resp, err := a.coord.ListAccess(a.ctx, &pb.ListAccessRequest{FileId: f.FileId})
	if err != nil {
		return err
	}
	fmt.Printf("%s %s\n", bold(name), dim("("+f.FileId+")"))
	t := newTable("UTILISATEUR", "DROITS", "DONNÉ PAR", "LE", "JUSQU'AU", "EMPREINTE")
	for _, e := range resp.Entries {
		if e.Owner {
			t.row(e.Username, rightsLabel(e.Rights), "propriétaire", "-", "-", access.Fingerprint(e.PublicKey))
			continue
		}
		t.row(e.Username, access.RightsString(e.Rights), e.GrantedBy, humanDate(e.GrantedAt), humanExpiry(e.ExpiresAt),
			access.Fingerprint(e.PublicKey))
	}
	t.flush()
	return nil
}

// runTransfer donne le fichier à un autre utilisateur (propriétaire seulement). keepText
// fixe les droits que l'ancien propriétaire garde (« none » pour aucun).
func runTransfer(cfg Config, ref, newOwner, keepText string) error {
	var keep uint32
	if strings.ToLower(keepText) != "none" && keepText != "aucun" {
		var err error
		if keep, err = access.ParseRights(keepText); err != nil {
			return err
		}
	}
	a, err := open(cfg, time.Minute)
	if err != nil {
		return err
	}
	defer a.close()

	f, name, err := a.resolve(ref)
	if err != nil {
		return err
	}
	if f.Shared {
		return fmt.Errorf("seul le propriétaire (%s) peut transférer « %s »", f.Owner, name)
	}
	targets, err := a.recipients(newOwner)
	if err != nil {
		return err
	}
	if len(targets) != 1 || targets[0].username == a.user {
		return errors.New("indiquez un autre utilisateur (pas un groupe)")
	}
	to := targets[0]
	fmt.Printf("%s  empreinte de la clé : %s\n", bold(to.username), access.Fingerprint(to.key))
	file, err := a.coord.GetFile(a.ctx, &pb.GetFileRequest{FileId: f.FileId})
	if err != nil {
		return err
	}

	now := time.Now()
	// L'autorisation de l'ancien propriétaire est signée AVANT le transfert, quand il est
	// encore propriétaire : elle reste donc valable ensuite.
	var selfGrant *pb.Grant
	if keep != 0 {
		selfGrant = access.NewGrant(a.key, f.FileId, a.publicKey(), keep, now, time.Time{}, nil)
	}
	transfer := access.NewTransfer(a.key, f.FileId, to.key, now)
	done := 0
	for _, n := range file.Nodes {
		err := withNode(a.ctx, a.cfg, n, func(ctx context.Context, node pb.NodeClient) error {
			_, err := node.TransferOwnership(ctx, &pb.TransferRequest{Transfer: transfer})
			return err
		})
		if err != nil {
			warn("nœud %s : transfert non enregistré (%s)", n.Address, describe(err))
			continue
		}
		done++
	}
	if done < int(file.T) {
		return fmt.Errorf("transfert enregistré sur %d nœuds seulement (il en faut au moins %d) : relancez la commande", done, file.T)
	}
	nameFor, err := crypto.SealNameFor(to.key, name)
	if err != nil {
		return err
	}
	_, err = a.coord.TransferFile(a.ctx, &pb.TransferFileRequest{NewOwner: to.username, Transfer: transfer, EncryptedName: nameFor})
	if err != nil {
		return fmt.Errorf("transfert chez le coordinateur : %w", err)
	}
	success("« %s » appartient désormais à %s (enregistré sur %d nœuds sur %d).", name, bold(to.username), done, len(file.Nodes))

	if selfGrant != nil {
		myName, err := crypto.SealNameFor(a.publicKey(), name)
		if err != nil {
			return err
		}
		_, err = a.coord.ShareFile(a.ctx, &pb.ShareFileRequest{Grantee: a.user, Grant: selfGrant, EncryptedName: myName})
		if err != nil {
			return fmt.Errorf("conservation de votre accès : %w", err)
		}
		info("Vous gardez les droits %s.", access.RightsString(keep))
	}
	return nil
}
