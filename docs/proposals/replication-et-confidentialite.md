# Décisions d'équipe en attente : réplication (SV-50) et confidentialité des métadonnées (SV-73)

Rédigé par Mohamed Amine, à discuter. Rien n'a été changé dans le contrat.

## SV-50 : placement et réplication des blocs

**Aujourd'hui** : `CreateFile` renvoie les n nœuds x = 1..n, et le client envoie la part
du nœud x et **tous les blocs** à chacun. Chaque bloc a donc n copies (r = n = 5). Le
coordinateur refuse un dépôt si l'un des n nœuds est en panne, car le partage de Shamir
du client attribue la part d'indice x au nœud x.

**Garanties visées** (page Garanties) : r = n - t + 1 = 3 copies suffisent pour survivre
à n - t = 2 pannes, pour 3 × la taille au lieu de 5 ×.

Options :

| Option | Changement | Pour | Contre |
|---|---|---|---|
| A. Garder r = n | aucun | simple, déjà testé de bout en bout | stockage 5 × |
| B. r = n - t + 1, placement déterministe : bloc i sur les nœuds (i + k) mod n, k = 0..r-1 | client (choix des nœuds par bloc) ; le coordinateur peut recalculer sans table | 3 ×, pas de table `placements` | `GetBlocks` doit savoir quels blocs demander à quel nœud |
| C. r = n - t + 1, placement choisi par le coordinateur et stocké | `Manifest` ou `CreateFileResponse` gagne une liste de placements ; table `placements` | souple (nœuds chargés, ajout de nœuds) | contrat plus gros |

Proposition : **A pour la démo du sprint 2**, **B ensuite** (aucun état en plus côté
coordinateur, formule facile à expliquer).

## SV-73 : confidentialité des métadonnées

**Aujourd'hui** : le coordinateur reçoit le nom du fichier en clair et sa taille exacte.
Il ne les journalise jamais, et la colonne `files.name` est déjà un BLOB opaque.

Options, de la plus simple à la plus forte :

1. **Nom chiffré côté client** : `CreateFileRequest.name` devient `bytes encrypted_name`
   (AES-GCM avec une clé dérivée de la clé privée de l'utilisateur). Le coordinateur
   stocke et renvoie le blob sans le comprendre. Coût : un champ de proto, quelques lignes
   côté client, rien côté coordinateur.
2. **Taille arrondie** : le client annonce la taille arrondie à la puissance de 2 (ou au
   multiple de 64 Kio) et met la vraie taille dans le contenu chiffré. Cache la taille
   exacte, pas l'ordre de grandeur.
3. **Manifeste chiffré par utilisateur** : le coordinateur ne garde qu'un blob par
   utilisateur. Le plus fort, mais le coordinateur ne peut plus vérifier les manifestes.

Ce qui reste visible quoi qu'on fasse : qui dépose, quand, combien de fichiers, et sur
quels nœuds (hors garanties : « confidentialité des horaires d'accès »).

Proposition : **1 et 2** pour le sprint 3.
