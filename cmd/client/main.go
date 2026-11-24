// Commande client de SafeVault : chiffre, dépose et récupère des fichiers.
//
// Utilisation :
//
//	client <commande> [arguments]
//
// Commandes :
//
//	register                           crée la clé de l'utilisateur et l'inscrit auprès du coordinateur
//	upload <fichier>                   chiffre et dépose un fichier
//	download <file_id> [-o sortie]     récupère et déchiffre un fichier
//	ls                                 liste les fichiers accessibles (les siens et ceux partagés)
//	share <file_id> <utilisateur>      partage un fichier en lecture
//	revoke <file_id> <utilisateur>     retire l'accès d'un utilisateur
//	whoami                             affiche l'empreinte de sa clé
//
// Variables d'environnement :
//
//	COORD_ADDR   adresse du coordinateur
//	CA_PATH      chemin du certificat de la CA
//	KEY_PATH	 chemin de la clé privé du client

package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cfg := LoadConfig()
	command := os.Args[1]
	args := os.Args[2:]

	var err error
	switch command {
	case "register":
		if len(args) != 0 {
			printUsage()
			os.Exit(1)
		}
		err = runRegister(cfg)

	case "upload":
		if len(args) != 1 {
			printUsage()
			os.Exit(1)
		}
		err = runUpload(cfg, args[0])

	case "download":
		if len(args) != 2 {
			printUsage()
			os.Exit(1)
		}
		err = runDownload(cfg, args[0], args[1])

	case "ls":
		err = runList(cfg)

	case "share", "revoke":
		if len(args) != 2 {
			printUsage()
			os.Exit(1)
		}
		if command == "share" {
			err = runShare(cfg, args[0], args[1])
		} else {
			err = runRevoke(cfg, args[0], args[1])
		}

	case "whoami":
		err = runWhoami(cfg)

	default:
		fmt.Println("commande inconnue :", command)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Println("erreur :", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Utilisation : client <commande> [arguments]

Commandes :
  register                        crée la clé de l'utilisateur et l'inscrit
  upload <fichier>                chiffre et dépose un fichier
  download <file_id> <sortie>     récupère et déchiffre un fichier
  ls                              liste les fichiers accessibles
  share <file_id> <utilisateur>   partage un fichier en lecture
  revoke <file_id> <utilisateur>  retire l'accès d'un utilisateur
  whoami                          affiche l'empreinte de sa clé`)
}
