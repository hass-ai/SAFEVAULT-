# SafeVault

Stockage de fichiers distribué et chiffré, dont la clé n'existe jamais en un seul endroit
et se renouvelle d'elle-même. Plusieurs utilisateurs y déposent, partagent et gèrent des
fichiers avec des droits fins, sans avoir à faire confiance au serveur.

Projet S9, ENSEIRB-MATMECA (Bordeaux INP). Encadrant : Joachim Bruneau-Queyreix (LaBRI).

## L'idée

Un fichier est chiffré **sur le poste de l'utilisateur**, avant de partir. Sa clé n'est
envoyée nulle part : elle est découpée en `n` morceaux (des *parts*), un par serveur de
stockage, de sorte qu'il en faut `t` pour la reconstruire et qu'avec `t − 1` on n'apprend
rien. Pour lire le fichier, le client récupère `t` parts, reconstruit la clé chez lui et
déchiffre.

Un attaquant doit donc compromettre `t` serveurs **en même temps**. Et comme les parts
sont régulièrement renouvelées (la clé reste la même, toutes les parts changent), des parts
volées à des moments différents ne se combinent pas : l'attaquant n'a qu'une fenêtre de
temps limitée pour réunir ses `t` parts.

```
               poste de l'utilisateur
        ┌─────────────────────────────────────┐
        │ fichier ──AES-256-GCM──▶ blocs       │
        │ clé ──Shamir (t parmi n)──▶ n parts  │
        └──────┬───────────────┬──────────────┘
   nom chiffré │               │ 1 part + les blocs chiffrés
   taille      ▼               ▼ par serveur
   arrondie  coordinateur    serveur 1 · serveur 2 · … · serveur n
             (annuaire,        ▲      renouvellement des parts
              époques, droits) └───── entre serveurs, piloté
                                      par le coordinateur
```

## Comment ça marche

### Déposer et relire

1. Le client tire un secret aléatoire, en dérive une clé AES-256 et chiffre le fichier
   par blocs de 1 Mio. Le contenu est d'abord complété jusqu'à une taille arrondie
   (puissance de 2, au moins 64 Kio) pour ne pas révéler la taille exacte.
2. Le secret est découpé par le **partage de Shamir** : un polynôme aléatoire de degré
   `t − 1` dont le secret est la valeur en 0 ; la part du serveur `i` est sa valeur en `i`.
3. Chaque serveur reçoit sa part et les blocs chiffrés. Le coordinateur ne reçoit que des
   informations publiques : le nom du fichier **chiffré**, la taille arrondie, les
   empreintes des blocs.
4. Pour relire, le client demande sa part à chaque serveur jusqu'à en avoir `t`,
   reconstruit le secret (interpolation de Lagrange), vérifie chaque bloc et déchiffre.
   Jusqu'à `n − t` serveurs peuvent être en panne.

Chaque requête vers un serveur est **signée** avec la clé de l'utilisateur (Ed25519),
datée et à usage unique : un serveur sait toujours qui demande, et une requête interceptée
ne peut pas être rejouée.

### Renouveler les parts (attaquant mobile)

À intervalle régulier, le coordinateur ouvre une nouvelle **époque**. Chaque serveur tire
un polynôme δ avec δ(0) = 0 et envoie δ(j) à chaque autre serveur ; chacun ajoute ce
qu'il reçoit à sa part. La somme des δ vaut 0 en 0 : **la clé ne change pas, toutes les
parts changent**, et les anciennes sont effacées. Le passage se fait en deux phases
(préparer puis valider) : si un serveur manque, l'époque est abandonnée et les anciennes
parts restent en service.

### Partager, avec des droits

Chaque utilisateur a une paire de clés créée sur son poste ; le coordinateur ne connaît
que les clés publiques. Le propriétaire d'un fichier donne un accès en **signant une
autorisation** pour la clé d'un autre utilisateur : `{fichier, destinataire, droits,
date, expiration}`. Les serveurs vérifient cette signature avant de donner une part ou un
bloc. Le coordinateur transmet les autorisations mais ne peut pas en fabriquer : il n'a la
clé privée de personne.

| Droit | Permet de |
|---|---|
| `r` lire | récupérer le fichier et toutes ses versions |
| `w` écrire | déposer une nouvelle version |
| `s` repartager | donner un accès à son tour, avec au plus ses propres droits et sa propre durée |
| `d` supprimer | effacer le fichier et toutes ses versions |
| `m` gérer | donner n'importe quel droit, réduire ou retirer un accès, renommer (co-administrateur) |

- **Délégation** : un utilisateur qui repartage joint sa propre autorisation à celle qu'il
  signe ; les serveurs remontent toute la chaîne jusqu'au propriétaire.
- **Expiration** : un accès peut être limité dans le temps (7 jours, une date, ou sans
  limite).
- **Retrait** : un retrait signé (propriétaire ou droit `m`) est enregistré par chaque
  serveur ; l'accès est coupé, ainsi que tous ceux que la personne avait donnés.
- **Versions** : chaque version a son propre secret ; les anciennes restent lisibles.
- **Groupes** : on partage avec `@groupe` en une commande ; le client signe une
  autorisation par membre.
- **Transfert** : le propriétaire peut donner le fichier à un autre utilisateur ; les
  accès qu'il avait donnés restent valables.
- **Empreintes** : avant de partager, le client affiche l'empreinte de la clé du
  destinataire, à comparer avec la sienne (`client whoami`) : c'est ce qui empêche un
  coordinateur malveillant de substituer sa propre clé.

### Ce que voit le coordinateur

Ni le contenu, ni les clés, ni les parts, ni les noms de fichiers (chiffrés pour chaque
utilisateur qui y a accès), ni leur taille exacte. Il voit qui dépose, qui partage avec
qui, quand, et combien de fichiers chacun possède. Le détail est dans
[docs/partage.md](docs/partage.md) et [docs/metadata.md](docs/metadata.md).

## Garanties et limites

- Confidentialité tant que moins de `t` serveurs sont compromis **pendant une même
  époque**, même si le coordinateur l'est aussi.
- Disponibilité avec jusqu'à `n − t` serveurs en panne.
- Un serveur ou un coordinateur malveillant ne peut ni accorder un accès, ni lire un
  fichier, ni modifier un bloc sans que le client s'en aperçoive.
- Limites connues : un retrait d'accès n'efface pas ce que la personne a déjà téléchargé ;
  pendant qu'un serveur est en panne, les renouvellements sont abandonnés ; les
  empreintes ne protègent que si les utilisateurs les comparent.

## Lancer SafeVault

Prérequis : Docker, Go 1.27 et OpenSSL.

```sh
scripts/gen_certs.sh            # certificats de développement, une seule fois
docker compose up --build       # coordinateur (port 7443) et 5 serveurs (7451 à 7455)
```

`docker compose stop node-3` simule une panne ;
`docker compose kill -s SIGUSR1 coordinator` lance un renouvellement immédiat.

## Utiliser le client

```sh
go build -o safevault ./cmd/client
export COORD_ADDR=localhost:7443 CA_PATH=certs/ca.crt
```

Exemple de session :

```console
$ ./safevault register alice
✓ Inscription réussie : alice
  empreinte  : AB2A 7BC4 D349 2B98 71BE 2D78 6DCD 5C33
✓ Session ouverte.
$ ./safevault upload rapport.pdf
✓ rapport.pdf déposé (1,2 Mio, chiffré et réparti sur 5 nœuds, seuil 3)
  identifiant : wX3iYRrJLyiZYpQCp5Hf3w
$ ./safevault group create equipe && ./safevault group add equipe bob carol
$ ./safevault share rapport.pdf @equipe --rights rw --expire 7d
$ ./safevault access rapport.pdf
UTILISATEUR  DROITS        DONNÉ PAR     LE                JUSQU'AU          EMPREINTE
alice        rwsdm (tous)  propriétaire  -                 -                 AB2A 7BC4 …
bob          rw---         alice         24/11/2026 13:44  01/12/2026 13:44  A435 D20F …
carol        rw---         alice         24/11/2026 13:44  01/12/2026 13:44  B97A 8F91 …
```

| Commande | Rôle |
|---|---|
| `register <utilisateur>` · `login <utilisateur>` · `logout` · `whoami` | compte et session |
| `ls` | ses fichiers et ceux partagés avec soi, avec droits, version et expiration |
| `upload <chemin>` | chiffre et dépose un fichier |
| `download <fichier> [sortie] [--version N]` | récupère et déchiffre (une ancienne version au besoin) |
| `update <fichier> <chemin>` | dépose une nouvelle version |
| `versions <fichier>` · `rename <fichier> <nom>` · `rm <fichier>` | historique, renommage, suppression |
| `share <fichier> <utilisateur\|@groupe> [--rights rwsdm] [--expire 7d\|2026-12-31\|never]` | donne ou modifie un accès |
| `revoke <fichier> <utilisateur\|@groupe>` · `access <fichier>` | retire un accès, liste les accès |
| `transfer <fichier> <utilisateur> [--keep rw\|none]` | donne le fichier à un autre utilisateur |
| `group ls\|create\|delete\|add\|rm` | groupes d'utilisateurs |

Un `<fichier>` se désigne par son identifiant, le début de son identifiant ou son nom.
La clé privée et la session sont rangées dans `~/.safevault` (ou `SAFEVAULT_HOME`) ;
`NO_COLOR` désactive les couleurs. `client help` donne la liste complète.

## Démo web

```sh
go run ./cmd/demo        # depuis la racine du dépôt, puis ouvrir http://localhost:8080
```

La démo compile et lance les vrais programmes dans un dossier temporaire, et montre en
direct : dépôt et récupération, pannes de serveurs, renouvellement des parts, attaquant
mobile avec et sans renouvellement, partage entre alice, bob et charlie, coordinateur
tricheur, retrait d'accès, et ce que contient la base du coordinateur.

## Développer

| Dossier | Contenu |
|---|---|
| `cmd/` | les programmes : `client`, `node` (serveur de stockage), `coordinator`, `demo` |
| `internal/` | le code partagé : `shamir`, `crypto`, `access` (droits signés), `storage`, `metadata` |
| `proto/` | les contrats gRPC entre composants (`make proto` pour régénérer le code Go) |
| `docs/` | notes de conception : partage, métadonnées, décisions (`adr/`) |
| `scripts/`, `docker-compose.yml`, `.github/workflows/` | certificats, déploiement local, intégration continue |

Tests : `go test ./...` (`-short` saute le transfert de 100 Mo, `-race` comme en CI).

Règles de travail :

- une branche par fonctionnalité, jamais de push direct sur `main` ;
- chaque pull request est relue par un autre membre avant d'être fusionnée.
