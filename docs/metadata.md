# Modèle de métadonnées du coordinateur (SV-39)

Base SQLite du coordinateur : `DATA_DIR/coordinator.db`, gérée par `internal/metadata`.
Version du schéma : **3** (`PRAGMA user_version`). La version 2 ajoute les partages, la
version 3 les versions de fichiers, les retraits d'accès, les anciens propriétaires et les
groupes ; une base plus ancienne est migrée automatiquement au démarrage (ses fichiers
deviennent leur version 1). Le code de référence est
`internal/metadata/schema.go` ; ce document l'explique.

## Ce que le coordinateur ne stocke jamais (G3, G10)

| Donnée | Où elle vit | Pourquoi le coordinateur ne l'a pas |
|---|---|---|
| Clé de fichier (AES-256-GCM) | Dérivée sur le poste client, jamais transmise | G3 : une fuite du coordinateur ne donne aucun contenu |
| Secret de Shamir, parts s_i, sous-parts d_i(j) | Client (le temps du dépôt) et nœuds | G3 : le coordinateur signale et valide les époques, sans voir de valeur |
| Clés privées Ed25519 des utilisateurs | `certs/` sur le poste client | Seules les clés **publiques** sont stockées |
| Jetons de session et défis en clair | Envoyés une fois au client | Seule l'empreinte SHA-256 est stockée : une copie de la base ne permet pas de se connecter |
| Contenu des fichiers, blocs chiffrés | Nœuds | Le coordinateur ne garde que les empreintes des blocs |

Un test (`TestNoSecretColumns`) refuse toute colonne dont le nom évoque une clé,
une part, un secret ou un jeton en clair. Les journaux ne contiennent ni nom de fichier,
ni jeton, ni défi, ni signature.

## Tables

```
users ─┬─< challenges          nodes ─< file_nodes >─ files ─┬─< versions ─< version_blocks
       ├─< sessions                                   │      ├─< grants
       ├─< files (owner_id)               epochs ─────┘      ├─< revocations
       └─< user_groups ─< group_members                      └─< previous_owners
```

| Table | Rôle | Colonnes principales |
|---|---|---|
| `users` | Utilisateurs inscrits | `id`, `username` (unique), `public_key` (32 octets, unique) |
| `challenges` | Défis de connexion en cours | `hash` = SHA-256(défi), `user_id`, `expires_at` ; supprimé au premier usage |
| `sessions` | Jetons de session | `token_hash` = SHA-256(jeton), `user_id`, `expires_at` |
| `nodes` | Nœuds de stockage connus | `x` (abscisse Shamir = `NODE_X`), `address`, `status` (`unknown`/`up`/`down`), `last_seen` |
| `epochs` | Historique des époques | `number` (commence à 1), `state` (`preparing`/`committing`/`committed`/`aborted`) ; au plus un renouvellement en cours |
| `files` | Fichiers | `file_id`, `owner_id`, `name` (nom chiffré pour le propriétaire), `size` (de la version actuelle), `t`, `n`, `epoch`, `status` (`pending`/`ready`), `current_version` |
| `file_nodes` | Nœuds qui détiennent une part du fichier (« share_index ») | `(file_id, node_x)` ; la **valeur** de la part n'y est jamais |
| `versions` | Versions d'un fichier et leur manifeste public | `(file_id, version)`, `author_id`, `size`, `status` (`pending`/`ready`), `block_count`, `nonce_prefix` |
| `version_blocks` | Empreinte de chaque bloc chiffré d'une version | `(file_id, version, idx)`, `sha256` |
| `grants` | Accès donnés | `(file_id, grantee_id)`, `signed_grant` (autorisation signée, avec sa chaîne), `encrypted_name` (nom chiffré pour le destinataire) |
| `revocations` | Retraits d'accès signés | `(file_id, public_key)`, `revoked_at` |
| `previous_owners` | Anciens propriétaires | `(file_id, public_key)`, `until` (date du transfert) |
| `user_groups`, `group_members` | Groupes d'utilisateurs, propres à chacun | `owner_id`, `name` ; `(group_id, user_id)` |

Les dates sont des secondes Unix. Les clés étrangères sont activées (`foreign_keys=ON`).

### Choix à expliquer

- **Époque 1 au départ** : en proto3, 0 se confond avec un champ absent.
- **`files.epoch` par fichier** : l'époque des parts en service de ce fichier. Le nœud
  ne valide (`CommitEpoch`) que les fichiers qui ont une part en attente ; une époque
  globale seule ne dirait pas à quelle époque demander la part d'un fichier déposé
  pendant un renouvellement. Le gestionnaire d'époques (SV-21, SV-56) mettra cette
  colonne à jour au commit.
- **`files.name` en BLOB** : le client envoie un nom chiffré, que le coordinateur stocke
  sans pouvoir le lire (SV-73, voir `docs/partage.md`).
- **Fichier et version `pending`** : créés par `CreateFile` ou `CreateVersion`, deviennent
  `ready` à `ConfirmUpload`, et la version devient la version actuelle. Un dépôt jamais
  confirmé est supprimé au bout d'une heure.
- **Droits vérifiés deux fois** : le coordinateur vérifie les autorisations comme les
  nœuds (mêmes règles, `internal/access`) pour ne pas montrer un fichier qu'ils
  refuseraient ; ce sont les nœuds qui décident.
- **Renouvellement en deux phases** : `preparing` (les nœuds préparent) puis `committing`
  (décision enregistrée AVANT le premier COMMIT) puis `committed`. Après un crash :
  `preparing` → abandon, `committing` → on renvoie COMMIT. Pas de renouvellement tant
  qu'une version est `pending`, pas de `CreateFile` ni de `CreateVersion` pendant un
  renouvellement : un fichier n'a jamais de parts de deux époques. Au commit, `files.epoch` passe à la nouvelle époque.
- **Empreintes de jetons** : SHA-256 suffit (pas de sel ni de fonction lente) car le
  jeton et le défi sont 32 octets aléatoires, impossibles à deviner.

## Qui lit et écrit quoi

| RPC | Tables |
|---|---|
| `Register` | écrit `users` |
| `GetChallenge` | lit `users`, écrit `challenges` |
| `Login` | supprime dans `challenges`, écrit `sessions` |
| Toute RPC authentifiée | lit `sessions` |
| `CreateFile` | lit `epochs`, `nodes` ; écrit `files` (`pending`), `versions` (1), `file_nodes` |
| `CreateVersion` | lit `files`, droits ; écrit `versions` (`pending`) |
| `ConfirmUpload` | lit `versions` (auteur, statut, taille) ; écrit `versions` (`ready`), `version_blocks`, `files` |
| `ListFiles`, `GetFile`, `ListVersions` | lit `files`, `grants`, `revocations`, `previous_owners`, `versions`, `version_blocks`, `file_nodes`, `nodes` |
| `ShareFile`, `RevokeShare`, `ListAccess` | lit et écrit `grants`, `revocations` |
| `RenameFile`, `RemoveFile`, `TransferFile` | écrit `files`, `grants`, `previous_owners` |
| Groupes | lit et écrit `user_groups`, `group_members` |
| Registre des nœuds (SV-51) | écrit `nodes` |
| Renouvellement (SV-21, SV-56) | écrit `epochs`, met à jour `files.epoch` (`cmd/coordinator/epochs.go`) |

## Prévu plus tard (pas encore dans le schéma)

- `placements (file_id, block_index, node_x)` : quels nœuds gardent quel bloc, quand la
  stratégie de réplication sera décidée (SV-50). Aujourd'hui chaque bloc va sur les n nœuds.

## Confidentialité des métadonnées (SV-73)

Le coordinateur reçoit un nom chiffré côté client et une taille arrondie (le contenu est
complété avant chiffrement) : il ne connaît ni le nom ni la taille exacte des fichiers.
Restent visibles : qui dépose, qui partage avec qui et avec quels droits, quand, et combien
de fichiers et de versions chacun possède. Détails dans `docs/partage.md`.
