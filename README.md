# SafeVault

Stockage distribué sécurisé avec partage de secret proactif.
Projet S9, ENSEIRB-MATMECA (Bordeaux INP). Encadrant : Joachim Bruneau-Queyreix (LaBRI).

## Organisation du dépôt

| Dossier | Contenu | Responsables |
|---|---|---|
| `cmd/client/` | Le client en ligne de commande : chiffre, dépose et récupère les fichiers | Karim Diop, Mehmed-Zaid Kara |
| `cmd/node/` | Le programme d'un nœud de stockage | Thomas Ferreira |
| `cmd/coordinator/` | Le programme du service de coordination | Mohamed Amine Boussenna |
| `internal/shamir/` | Partage de secret de Shamir et renouvellement proactif des parts | Karim Diop, Mehmed-Zaid Kara |
| `internal/crypto/` | Chiffrement des fichiers (AES-256-GCM) et dérivation de clé | Karim Diop, Mehmed-Zaid Kara |
| `internal/storage/` | Stockage des blocs chiffrés et des parts de clé sur un nœud | Thomas Ferreira |
| `internal/metadata/` | Métadonnées du coordinateur : fichiers, blocs, époques, droits d'accès | Mohamed Amine Boussenna |
| `proto/` | Contrats gRPC / Protobuf entre les composants | Toute l'équipe |
| `bench/` | Banc d'essai : simulation de pannes et d'attaques, mesures | Ayman Reggoug |
| `docs/adr/` | Une fiche par décision technique importante | Toute l'équipe |
| `.github/workflows/` | Intégration continue : tests lancés à chaque push | Ayman Reggoug |

`cmd/` contient les programmes qu'on lance, `internal/` le code qu'ils partagent.

Les fichiers `.gitkeep` servent seulement à garder les dossiers vides dans Git :
supprimez celui de votre dossier dès que vous y ajoutez vos fichiers.

## Règles de travail

- Une branche par fonctionnalité (par exemple `feat/shamir`), jamais de push direct sur `main`.
- Chaque pull request est relue par un autre membre avant d'être fusionnée.

## Nœud de stockage

Un nœud conserve les blocs chiffrés des fichiers et une part de la clé de chacun.
Il sert les services gRPC `Node` (client → nœud) et `Renewal` (nœud → nœud) décrits dans `proto/node.proto`, en TLS 1.3.

```sh
NODE_X=1 LISTEN_ADDR=:7444 DATA_DIR=./data/node1 \
TLS_CERT_PATH=certs/node1.crt TLS_KEY_PATH=certs/node1.key \
go run ./cmd/node
```

| Variable | Rôle | Défaut |
|---|---|---|
| `NODE_X` | Abscisse du nœud dans le partage de Shamir (entier ≥ 1) | obligatoire |
| `LISTEN_ADDR` | Adresse d'écoute gRPC | `:7444` |
| `DATA_DIR` | Dossier des données : `blocks/` et `node.db` | `/data` |
| `TLS_CERT_PATH` | Certificat du nœud, signé par la CA | `certs/node.crt` |
| `TLS_KEY_PATH` | Clé privée du certificat | `certs/node.key` |

Ce que fait le nœud aujourd'hui :

- chaque requête du client porte une preuve d'identité signée (Ed25519) : le nœud vérifie la signature, refuse une preuve de plus de 2 minutes ou déjà utilisée ;
- la clé qui dépose la première part d'un fichier en devient propriétaire : elle seule peut relire la part et les blocs (le partage viendra avec les autorisations signées) ;
- la part doit être déposée avant les blocs ;
- les blocs sont écrits sur le disque un par un, à leur arrivée, sans charger le fichier entier en mémoire ;
- les anciennes parts sont effacées de la base (`secure_delete`) quand une nouvelle époque est validée ;
- `DeliverSubShares` enregistre les sous-parts reçues ; le calcul de la nouvelle part arrivera avec le renouvellement.

Pas encore fait : mTLS entre composants, authentification des nœuds émetteurs de sous-parts.

Pour régénérer le code Go après une modification d'un `.proto` : `make proto`
(nécessite `protoc`, `protoc-gen-go` et `protoc-gen-go-grpc`).

Tests : `go test ./...` (ajouter `-short` pour sauter le transfert de 100 Mo).
