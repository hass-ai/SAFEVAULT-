# Partage, droits et confidentialité des métadonnées

Plusieurs utilisateurs déposent, partagent et gèrent des fichiers. Les droits sont portés
par des objets **signés par les utilisateurs** et vérifiés par chaque nœud : le
coordinateur les transmet et les range, mais ne peut pas en fabriquer.

## Ce qui est garanti

| Garantie | Mécanisme | Preuve |
|---|---|---|
| Seules les personnes autorisées obtiennent les parts et les blocs | Les nœuds exigent une autorisation dont toute la chaîne remonte au propriétaire | `cmd/node/sharing_test.go`, démo « Charlie récupère » |
| Le coordinateur ne peut pas s'accorder ni accorder un accès | Il n'a la clé privée de personne : une autorisation qu'il fabrique a une signature invalide | `TestGrantRefused`, démo « Coordinateur tricheur » |
| On ne donne jamais plus que ce qu'on a | Un repartage (droit `s`) est limité aux droits et à la durée de l'émetteur | `TestDelegation`, `TestDelegationAndCoAdmin` |
| Un accès retiré ne sert plus, ni ceux qui en découlent | Retrait signé enregistré par chaque nœud ; toute autorisation de la chaîne émise avant est refusée | `TestRevocationCascades`, `TestDelegatedAccess` |
| Une version déposée ne peut pas être écrasée | Le nœud retient l'auteur de chaque version ; seul lui en dépose la part et les blocs | `TestVersions` (nœud) |
| Le coordinateur ne connaît ni le nom ni la taille exacte des fichiers | Nom chiffré pour chaque utilisateur, contenu complété jusqu'à une taille arrondie | `internal/crypto/metadata_test.go`, panneau « Ce que voit le coordinateur » |

## Droits

| Droit | Permet de |
|---|---|
| `r` | récupérer le fichier et toutes ses versions |
| `w` | déposer une nouvelle version |
| `s` | partager à son tour, avec au plus ses droits et jusqu'à sa propre expiration |
| `d` | supprimer le fichier (toutes les versions, sur tous les nœuds) |
| `m` | donner n'importe quels droits, réduire ou retirer un accès, renommer, voir les accès |

Le propriétaire a tous les droits. Tout droit inclut la lecture. Voir les accès
(`client access`) demande `s` ou `m`.

## Autorisations et chaînes

Une autorisation (`Grant`) contient `{fichier, émetteur, destinataire, émise le, expire le
(0 = sans limite), droits, signature}` et, si l'émetteur n'est pas propriétaire, son
**autorisation parente** : celle qui lui donne le droit de partager. Un nœud vérifie, du
destinataire jusqu'au propriétaire :

- chaque signature, le fichier, les dates (expiration, pas d'émission dans le futur) ;
- que le destinataire du parent est l'émetteur de l'enfant ;
- que le parent donne `m` (tous droits permis) ou `s` (droits inclus, expiration
  inférieure ou égale) ;
- qu'aucun maillon n'a été retiré après son émission ;
- que la racine est signée par le propriétaire (ou par un ancien propriétaire, avant la
  date du transfert) ;
- au plus 4 maillons.

## Déroulement

**Partager** (`client share <fichier> <utilisateur|@groupe> --rights rw --expire 7d`) :

1. le client demande la clé publique du destinataire et en affiche l'**empreinte**, que
   le destinataire compare avec `client whoami` : si elles diffèrent, le coordinateur a
   substitué une clé ;
2. il signe l'autorisation, avec la sienne en parent s'il n'est pas propriétaire ;
3. il chiffre le nom du fichier pour le destinataire ;
4. `ShareFile` : le coordinateur vérifie toute la chaîne et la range.

Pour `@groupe`, le client fait la même chose pour chaque membre : les nœuds ne
connaissent pas les groupes. Un membre ajouté plus tard n'a accès qu'après un nouveau
partage.

**Modifier un accès** : une autorisation signée ne se modifie pas. Pour réduire des
droits ou une durée, le client retire d'abord l'ancien accès (droit `m` nécessaire), puis
signe la nouvelle autorisation une seconde après. Élargir un accès ne demande pas de
retrait.

**Lire un fichier partagé** : `GetFile` remet au destinataire son autorisation ; il la
présente aux nœuds avec sa preuve signée. La suite est celle du propriétaire.

**Retirer un accès** (`client revoke`) : le client signe un retrait `{fichier, émetteur,
destinataire, date}` (avec son autorisation `m` s'il n'est pas propriétaire), l'envoie à
chaque nœud puis au coordinateur. Le destinataire a besoin de `t` parts : il est bloqué
dès que `n − t + 1` nœuds ont enregistré le retrait. Les accès qu'il avait donnés tombent
avec le sien (le coordinateur les efface aussi de sa base).

**Nouvelle version** (`client update`, droit `w`) : `CreateVersion` donne un numéro ; le
client tire un **nouveau secret**, dépose les parts et les blocs sous la clé de stockage
`<fichier>_v<n>`, puis `ConfirmUpload`. Les anciennes versions restent lisibles
(`client download --version N`). Les renouvellements renouvellent les parts de toutes les
versions.

**Renommer** (droit `m`) : le client chiffre le nouveau nom pour chaque personne qui a
accès (`ListAccess` donne leurs clés publiques) et l'envoie au coordinateur.

**Supprimer** (droit `d`) : le client demande à chaque nœud d'effacer parts et blocs de
toutes les versions, puis au coordinateur d'oublier le fichier. Si `t` nœuds ou plus
gardent encore leur part, le coordinateur garde le fichier pour qu'on puisse relancer.

**Transférer** (propriétaire) : le client signe `{fichier, ancien, nouveau propriétaire,
date}` et l'envoie aux nœuds, puis au coordinateur. Les nœuds gardent l'ancien
propriétaire avec la date : ses autorisations signées avant restent valables. Par défaut
l'ancien propriétaire garde lecture et écriture (`--keep rw`), grâce à une autorisation
qu'il se signe juste avant le transfert ; `--keep none` pour ne rien garder.

## Données signées

Dans `internal/access` (entiers en gros-boutiste, 8 octets) :

```
autorisation : "safevault/grant/v2"    || 0x00 || len(fichier) (4) || fichier || émetteur (32) || destinataire (32) || émise le || expire le || droits
retrait      : "safevault/revoke/v2"   || 0x00 || len(fichier) (4) || fichier || émetteur (32) || destinataire (32) || date
transfert    : "safevault/transfer/v1" || 0x00 || len(fichier) (4) || fichier || propriétaire (32) || nouveau (32) || date
```

L'autorisation parente n'est pas dans la signature : elle est vérifiée pour elle-même,
puis rattachée par la clé (destinataire du parent = émetteur de l'enfant).

## Métadonnées

- **Noms** : chiffrés pour la clé publique de chaque utilisateur qui a accès (le
  propriétaire compris) : clé X25519 éphémère, échange de clé avec la clé X25519
  équivalente à sa clé Ed25519, clé AES dérivée par HKDF. Chaque utilisateur garde une
  seule paire de clés.
- **Taille arrondie** : le contenu est précédé de sa taille réelle (8 octets) et complété
  jusqu'à la puissance de 2 supérieure (au moins 64 Kio), avant chiffrement.
- **Restent visibles du coordinateur** : qui dépose, qui partage avec qui et avec quels
  droits, quand, combien de fichiers et de versions chacun possède.

## Limites

- **Retrait non rétroactif** : une personne qui a déjà récupéré le fichier a pu en garder
  le contenu. Déposer une nouvelle version après un retrait protège les modifications
  suivantes.
- **Empreintes à comparer** : sans comparaison, un coordinateur malveillant pourrait
  donner sa propre clé à la place de celle d'un destinataire.
- **Groupes côté client** : modifier un groupe ne change pas les accès déjà donnés.
- **Remplissage** : jusqu'à 2 fois la taille d'un fichier en stockage, par version.
