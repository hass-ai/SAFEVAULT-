package main

import (
	"fmt"
	"strings"
	"time"

	pb "safevault/proto"
)

// runGroup gère les groupes de l'utilisateur : create, delete, add, rm, ls.
func runGroup(cfg Config, args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	a, err := open(cfg, 30*time.Second)
	if err != nil {
		return err
	}
	defer a.close()

	switch sub, rest := args[0], args[1:]; {
	case sub == "ls" && len(rest) == 0:
		resp, err := a.coord.ListGroups(a.ctx, &pb.ListGroupsRequest{})
		if err != nil {
			return err
		}
		if len(resp.Groups) == 0 {
			info("Aucun groupe. Créez-en un avec « client group create <nom> ».")
			return nil
		}
		t := newTable("GROUPE", "MEMBRES")
		for _, g := range resp.Groups {
			var names []string
			for _, m := range g.Members {
				names = append(names, m.Username)
			}
			members := strings.Join(names, ", ")
			if members == "" {
				members = dim("(vide)")
			}
			t.row("@"+g.Name, members)
		}
		t.flush()
		return nil

	case sub == "create" && len(rest) == 1:
		if _, err := a.coord.CreateGroup(a.ctx, &pb.CreateGroupRequest{Name: rest[0]}); err != nil {
			return err
		}
		success("Groupe @%s créé.", rest[0])
		return nil

	case sub == "delete" && len(rest) == 1:
		if _, err := a.coord.DeleteGroup(a.ctx, &pb.DeleteGroupRequest{Name: rest[0]}); err != nil {
			return err
		}
		success("Groupe @%s supprimé (les partages déjà faits restent en place).", rest[0])
		return nil

	case (sub == "add" || sub == "rm") && len(rest) >= 2:
		group := rest[0]
		for _, user := range rest[1:] {
			req := &pb.GroupMemberRequest{Group: group, Username: user}
			if sub == "add" {
				_, err = a.coord.AddGroupMember(a.ctx, req)
			} else {
				_, err = a.coord.RemoveGroupMember(a.ctx, req)
			}
			if err != nil {
				return fmt.Errorf("%s : %w", user, err)
			}
		}
		if sub == "add" {
			success("Ajouté à @%s : %s", group, strings.Join(rest[1:], ", "))
			info("Les fichiers déjà partagés avec @%s ne leur sont pas ouverts : repartagez-les (client share <fichier> @%s).", group, group)
		} else {
			success("Retiré de @%s : %s", group, strings.Join(rest[1:], ", "))
			info("Leurs accès déjà donnés restent : retirez-les avec « client revoke <fichier> <utilisateur> ».")
		}
		return nil
	}
	return errUsage
}
