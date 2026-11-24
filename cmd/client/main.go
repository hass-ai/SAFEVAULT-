// Commande client de SafeVault : chiffre, dépose, récupère et partage des fichiers.
//
// Utilisation : client <commande> [arguments] (voir printUsage).
//
// Variables d'environnement :
//
//	SAFEVAULT_HOME   dossier du client (clés et session), ~/.safevault par défaut
//	COORD_ADDR       adresse du coordinateur
//	CA_PATH          certificat de la CA
//	KEY_PATH         clé privée imposée (la session est alors rangée à côté)
//	CLIENT_USERNAME  pour les scripts : connexion automatique sans « login »
//	NO_COLOR         désactive les couleurs
package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var errUsage = errors.New("arguments invalides")

const usage = `Utilisation : client <commande> [arguments]

Compte
  register <utilisateur>                 crée votre clé, vous inscrit et ouvre une session
  login <utilisateur>                    ouvre une session
  logout                                 ferme la session
  whoami                                 utilisateur connecté et empreinte de sa clé

Fichiers  (<fichier> : identifiant, début d'identifiant ou nom)
  ls                                     vos fichiers et ceux partagés avec vous
  upload <chemin>                        chiffre et dépose un fichier
  download <fichier> [sortie]            récupère et déchiffre
      [--version N] [--force]
  update <fichier> <chemin>              dépose une nouvelle version (droit w)
  versions <fichier>                     historique des versions
  rename <fichier> <nouveau nom>         renomme (droit m)
  rm <fichier>                           supprime toutes les versions (droit d)

Partage
  share <fichier> <utilisateur|@groupe>  donne un accès
      [--rights rwsdm] [--expire 7d|12h|2026-12-31|never]
  revoke <fichier> <utilisateur|@groupe> retire un accès (droit m)
  access <fichier>                       qui a accès, avec quels droits (droit s ou m)
  transfer <fichier> <utilisateur>       donne le fichier (propriétaire)
      [--keep rw|none]

Groupes
  group ls | create <nom> | delete <nom> | add <nom> <utilisateur>... | rm <nom> <utilisateur>...

Droits : r lire, w déposer une version, s repartager (avec au plus ses droits),
         d supprimer, m gérer les accès (donner, réduire, retirer, renommer).`

func main() {
	if len(os.Args) < 2 || os.Args[1] == "help" || os.Args[1] == "-h" || os.Args[1] == "--help" {
		fmt.Println(usage)
		if len(os.Args) < 2 {
			os.Exit(2)
		}
		return
	}
	err := run(LoadConfig(), os.Args[1], os.Args[2:])
	if errors.Is(err, errUsage) {
		fmt.Fprintln(os.Stderr, red("erreur :")+" arguments invalides pour « "+os.Args[1]+" »\n")
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, red("erreur :")+" "+describe(err))
		os.Exit(1)
	}
}

func run(cfg Config, command string, raw []string) error {
	args, flags, err := parseArgs(raw, "version", "rights", "expire", "keep", "o")
	if err != nil {
		return err
	}
	n := len(args)
	switch {
	case command == "register" && n <= 1:
		return runRegister(cfg, first(args))
	case command == "login" && n <= 1:
		return runLogin(cfg, first(args))
	case command == "logout" && n == 0:
		return runLogout(cfg)
	case command == "whoami" && n == 0:
		return runWhoami(cfg)

	case command == "ls" && n == 0:
		return runList(cfg)
	case command == "upload" && n == 1:
		return runUpload(cfg, args[0])
	case command == "download" && (n == 1 || n == 2):
		output := flags["o"]
		if n == 2 {
			output = args[1]
		}
		var version uint64
		if v := flags["version"]; v != "" {
			if version, err = strconv.ParseUint(strings.TrimPrefix(v, "v"), 10, 32); err != nil || version == 0 {
				return fmt.Errorf("version %q invalide", v)
			}
		}
		_, force := flags["force"]
		return runDownload(cfg, args[0], output, uint32(version), force)
	case command == "update" && n == 2:
		return runUpdate(cfg, args[0], args[1])
	case command == "versions" && n == 1:
		return runVersions(cfg, args[0])
	case command == "rename" && n == 2:
		return runRename(cfg, args[0], args[1])
	case command == "rm" && n == 1:
		return runRemove(cfg, args[0])

	case command == "share" && n == 2:
		rights := flags["rights"]
		if rights == "" {
			rights = "r"
		}
		return runShare(cfg, args[0], args[1], rights, flags["expire"])
	case command == "revoke" && n == 2:
		return runRevoke(cfg, args[0], args[1])
	case command == "access" && n == 1:
		return runAccess(cfg, args[0])
	case command == "transfer" && n == 2:
		keep := flags["keep"]
		if keep == "" {
			keep = "rw"
		}
		return runTransfer(cfg, args[0], args[1], keep)

	case command == "group":
		return runGroup(cfg, args)
	}
	switch command {
	case "register", "login", "logout", "whoami", "ls", "upload", "download", "update", "versions",
		"rename", "rm", "share", "revoke", "access", "transfer":
		return errUsage
	}
	return fmt.Errorf("commande inconnue « %s » (client help pour la liste)", command)
}

func first(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

// parseArgs sépare les arguments des options « --nom valeur », « --nom=valeur » ou
// « -o valeur ». withValue liste les options qui prennent une valeur ; les autres
// (--force) sont des interrupteurs.
func parseArgs(raw []string, withValue ...string) ([]string, map[string]string, error) {
	takes := map[string]bool{}
	for _, name := range withValue {
		takes[name] = true
	}
	var args []string
	flags := map[string]string{}
	for i := 0; i < len(raw); i++ {
		a := raw[i]
		if a == "--" {
			args = append(args, raw[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			args = append(args, a)
			continue
		}
		name := strings.TrimLeft(a, "-")
		name, value, hasValue := strings.Cut(name, "=")
		if takes[name] && !hasValue {
			if i+1 >= len(raw) {
				return nil, nil, fmt.Errorf("l'option --%s attend une valeur", name)
			}
			i++
			value = raw[i]
		}
		flags[name] = value
	}
	return args, flags, nil
}
