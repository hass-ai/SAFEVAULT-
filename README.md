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
