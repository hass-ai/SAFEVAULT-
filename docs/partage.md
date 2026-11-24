# Partage de fichiers et confidentialité des métadonnées

Cette version ajoute plusieurs utilisateurs qui partagent des fichiers en lecture, et
réduit ce que le coordinateur apprend sur les fichiers.

## Ce qui est garanti

| Garantie | Mécanisme | Preuve |
|---|---|---|
| Seuls le propriétaire et les destinataires qu'il a choisis obtiennent les parts et les blocs | Les nœuds exigent une autorisation **signée par le propriétaire** | Tests `cmd/node/sharing_test.go`, démo « Charlie récupère » |
| Le coordinateur ne peut pas s'accorder ni accorder un accès | Il n'a pas la clé privée du propriétaire : une autorisation qu'il fabrique a une signature invalide | Test `TestGrantRefused`, démo « Coordinateur tricheur » |
| Un accès retiré ne sert plus, même si le destinataire a gardé l'autorisation | Révocation signée par le propriétaire, enregistrée par chaque nœud | Test `TestRevocation`, démo « Alice retire l'accès de bob » |
| Le coordinateur ne connaît ni le nom ni la taille exacte des fichiers | Nom chiffré côté client, contenu complété jusqu'à une taille arrondie | Tests `internal/crypto/metadata_test.go`, panneau « Ce que voit le coordinateur » |

## Partager : déroulement

1. Alice demande au coordinateur la clé publique de bob (`GetUserKey`). Le client en
   affiche l'**empreinte** ; bob affiche la sienne avec `client whoami`. S'ils coïncident,
   le coordinateur n'a pas substitué de clé.
2. Le client d'alice signe une **autorisation** (`Grant`) :
   `{fichier, clé d'alice, clé de bob, émise le, expire le}`, valable 30 jours.
3. Il déchiffre le nom du fichier et le rechiffre **pour bob**.
4. `ShareFile` : le coordinateur vérifie l'autorisation (fichier d'alice, destinataire
   bob, signature valide, non expirée) et la garde avec le nom chiffré pour bob.

## Lire un fichier partagé

1. `ListFiles` montre à bob le fichier « partagé par alice », avec le nom chiffré pour lui.
2. `GetFile` lui remet l'autorisation signée par alice.
3. Bob demande ses parts et les blocs aux nœuds, avec sa preuve signée **et**
   l'autorisation. Chaque nœud vérifie :
   - que la preuve est signée par la clé de bob (comme pour le propriétaire) ;
   - que l'autorisation porte sur ce fichier, est signée par **le propriétaire enregistré
     au dépôt**, est faite pour la clé de bob, et n'a pas expiré ;
   - qu'aucune révocation postérieure n'existe pour bob.
4. La suite est inchangée : t parts, la clé, les blocs.

Partager ne touche ni aux parts ni au chiffrement : pas de rechiffrement du fichier, et
le renouvellement des parts continue sans rien changer aux autorisations.

## Retirer un accès

`client revoke <fichier> <utilisateur>` :

1. signe une **révocation** `{fichier, clé d'alice, clé de bob, date}` et l'envoie à
   chaque nœud (`Revoke`) : les autorisations de bob émises avant cette date sont refusées ;
2. retire le partage chez le coordinateur (`RevokeShare`).

Bob a besoin de t parts : il est bloqué dès que **n − t + 1** nœuds ont enregistré la
révocation. Le client l'indique, et demande de relancer la commande sinon. Un nouveau
partage, émis après la révocation, rouvre l'accès.

## Données signées

Dans `internal/access` (entiers en gros-boutiste) :

```
autorisation : "safevault/grant/v1"  || 0x00 || len(fichier) (4) || fichier || clé propriétaire (32) || clé destinataire (32) || émise le (8) || expire le (8)
révocation   : "safevault/revoke/v1" || 0x00 || len(fichier) (4) || fichier || clé propriétaire (32) || clé destinataire (32) || date (8)
```

## Métadonnées

- **Nom chiffré pour soi** : AES-256-GCM avec une clé dérivée de la clé privée de
  l'utilisateur (HKDF). Nonce aléatoire : deux fichiers de même nom ne se ressemblent pas.
- **Nom chiffré pour un destinataire** : clé X25519 éphémère, échange de clé avec la clé
  X25519 équivalente à la clé Ed25519 du destinataire, clé AES dérivée par HKDF. Chaque
  utilisateur garde ainsi une seule paire de clés.
- **Taille arrondie** : le contenu est précédé de sa taille réelle (8 octets) et complété
  par des zéros jusqu'à la puissance de 2 supérieure (au moins 64 Kio), avant
  chiffrement. Le coordinateur et les nœuds ne voient que la taille arrondie et le nombre
  de blocs correspondant.

## Limites

- **Révocation non rétroactive** : un destinataire qui a déjà récupéré le fichier a pu
  garder son contenu. La vraie réponse est de rechiffrer le fichier avec un nouveau
  secret (à faire).
- **Lecture seule** : un destinataire ne peut pas modifier le fichier.
- **Empreinte à vérifier par les utilisateurs** : si personne ne compare les empreintes,
  un coordinateur malveillant pourrait donner sa propre clé à la place de celle de bob.
- **Restent visibles du coordinateur** : qui dépose, qui partage avec qui, quand, et
  combien de fichiers chacun possède.
- **Remplissage** : jusqu'à 2 fois la taille d'un fichier en stockage, en échange de la
  taille cachée.
