package metadata

import (
	"database/sql"
	"fmt"
	"time"
)

// schemaVersion est la version du schéma, enregistrée dans PRAGMA user_version.
// Toute modification du schéma ajoute une étape de migration et incrémente ce numéro.
//
//	1 : schéma initial
//	2 : partages de fichiers (table grants)
//	3 : versions, droits étendus, retraits d'accès, transferts de propriété, groupes
const schemaVersion = 3

// schemaV1 crée les tables du coordinateur. Les dates sont des secondes Unix (INTEGER).
//
// Rien ici ne contient de clé de fichier, de part ou de sous-part (garantie G3) :
// seules des clés PUBLIQUES d'utilisateurs, des empreintes de jetons et de défis,
// et des informations publiques (manifestes, nœuds, époques).
const schemaV1 = `
CREATE TABLE users (
	id         INTEGER PRIMARY KEY,
	username   TEXT    NOT NULL UNIQUE,
	public_key BLOB    NOT NULL UNIQUE CHECK (length(public_key) = 32), -- clé publique Ed25519
	created_at INTEGER NOT NULL
);

-- Défis de connexion : seule l'empreinte SHA-256 est gardée, la ligne est supprimée
-- dès qu'elle est utilisée (usage unique).
CREATE TABLE challenges (
	hash       BLOB    PRIMARY KEY CHECK (length(hash) = 32),
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	expires_at INTEGER NOT NULL
);

-- Jetons de session : seule l'empreinte SHA-256 est gardée.
CREATE TABLE sessions (
	token_hash BLOB    PRIMARY KEY CHECK (length(token_hash) = 32),
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);

-- Nœuds de stockage connus ; x est leur abscisse dans le partage de Shamir.
CREATE TABLE nodes (
	x         INTEGER PRIMARY KEY CHECK (x >= 1),
	address   TEXT    NOT NULL UNIQUE,
	status    TEXT    NOT NULL DEFAULT 'unknown' CHECK (status IN ('unknown', 'up', 'down')),
	last_seen INTEGER
);

-- Époques de renouvellement (validation en deux phases) :
--   preparing  -> les nœuds calculent leurs nouvelles parts (en attente) ;
--   committing -> décision de valider ENREGISTRÉE, les nœuds basculent ;
--   committed  -> tous les nœuds ont basculé ; aborted -> abandon.
-- Au plus un renouvellement en cours (preparing ou committing) à la fois.
CREATE TABLE epochs (
	number      INTEGER PRIMARY KEY CHECK (number >= 1),
	state       TEXT    NOT NULL CHECK (state IN ('preparing', 'committing', 'committed', 'aborted')),
	started_at  INTEGER NOT NULL,
	finished_at INTEGER
);
CREATE UNIQUE INDEX one_active_epoch ON epochs((1)) WHERE state IN ('preparing', 'committing');

-- Fichiers. name est un BLOB opaque : le nom chiffré côté client (depuis la version 2 du
-- contrat), que le coordinateur ne sait pas lire. size est la taille arrondie.
-- epoch est l'époque des parts EN SERVICE de ce fichier (mise à jour au commit d'un
-- renouvellement qui l'inclut).
CREATE TABLE files (
	file_id      TEXT    PRIMARY KEY CHECK (length(file_id) BETWEEN 1 AND 128),
	owner_id     INTEGER NOT NULL REFERENCES users(id),
	name         BLOB    NOT NULL,
	size         INTEGER NOT NULL CHECK (size >= 0),
	t            INTEGER NOT NULL,
	n            INTEGER NOT NULL,
	epoch        INTEGER NOT NULL REFERENCES epochs(number),
	status       TEXT    NOT NULL CHECK (status IN ('pending', 'ready')),
	created_at   INTEGER NOT NULL,
	confirmed_at INTEGER,
	CHECK (2 <= t AND t <= n)
);
CREATE INDEX files_by_owner ON files(owner_id);

-- Nœuds qui détiennent une part du fichier (« share_index » de la spec) :
-- la part du nœud x est s_x = f(x). La valeur de la part n'est jamais ici.
CREATE TABLE file_nodes (
	file_id TEXT    NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
	node_x  INTEGER NOT NULL REFERENCES nodes(x),
	PRIMARY KEY (file_id, node_x)
);

-- Manifeste public d'un fichier confirmé (aucune clé dedans).
CREATE TABLE manifests (
	file_id      TEXT    PRIMARY KEY REFERENCES files(file_id) ON DELETE CASCADE,
	block_count  INTEGER NOT NULL CHECK (block_count >= 0),
	nonce_prefix BLOB    NOT NULL,
	size         INTEGER NOT NULL CHECK (size >= 0)
);

-- Empreinte SHA-256 de chaque bloc chiffré, dans l'ordre.
CREATE TABLE blocks (
	file_id TEXT    NOT NULL REFERENCES manifests(file_id) ON DELETE CASCADE,
	idx     INTEGER NOT NULL CHECK (idx >= 0),
	sha256  BLOB    NOT NULL CHECK (length(sha256) = 32),
	PRIMARY KEY (file_id, idx)
);
`

// schemaV2 ajoute les partages : une ligne par (fichier, destinataire), avec
// l'autorisation signée par le propriétaire (que le coordinateur ne peut pas fabriquer)
// et le nom du fichier chiffré pour le destinataire.
const schemaV2 = `
CREATE TABLE grants (
	file_id        TEXT    NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
	grantee_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	signed_grant   BLOB    NOT NULL,
	encrypted_name BLOB    NOT NULL,
	created_at     INTEGER NOT NULL,
	PRIMARY KEY (file_id, grantee_id)
);
CREATE INDEX grants_by_grantee ON grants(grantee_id);
`

// schemaV3 ajoute les versions d'un fichier (chacune avec son manifeste), les retraits
// d'accès, les anciens propriétaires et les groupes d'utilisateurs. Les manifestes et
// blocs existants deviennent la version 1 de leur fichier.
const schemaV3 = `
CREATE TABLE versions (
	file_id      TEXT    NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
	version      INTEGER NOT NULL CHECK (version >= 1),
	author_id    INTEGER NOT NULL REFERENCES users(id),
	size         INTEGER NOT NULL CHECK (size >= 0),
	status       TEXT    NOT NULL CHECK (status IN ('pending', 'ready')),
	created_at   INTEGER NOT NULL,
	block_count  INTEGER,
	nonce_prefix BLOB,
	PRIMARY KEY (file_id, version)
);
CREATE TABLE version_blocks (
	file_id TEXT    NOT NULL,
	version INTEGER NOT NULL,
	idx     INTEGER NOT NULL CHECK (idx >= 0),
	sha256  BLOB    NOT NULL CHECK (length(sha256) = 32),
	PRIMARY KEY (file_id, version, idx),
	FOREIGN KEY (file_id, version) REFERENCES versions(file_id, version) ON DELETE CASCADE
);
INSERT INTO versions (file_id, version, author_id, size, status, created_at, block_count, nonce_prefix)
	SELECT f.file_id, 1, f.owner_id, f.size, f.status, coalesce(f.confirmed_at, f.created_at),
	       m.block_count, m.nonce_prefix
	FROM files f LEFT JOIN manifests m ON m.file_id = f.file_id;
INSERT INTO version_blocks (file_id, version, idx, sha256) SELECT file_id, 1, idx, sha256 FROM blocks;
DROP TABLE blocks;
DROP TABLE manifests;
ALTER TABLE files ADD COLUMN current_version INTEGER NOT NULL DEFAULT 1;

-- Retraits d'accès signés : une autorisation de la clé public_key émise avant revoked_at
-- est refusée, ainsi que toutes celles qui en découlent.
CREATE TABLE revocations (
	file_id     TEXT    NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
	public_key  BLOB    NOT NULL CHECK (length(public_key) = 32),
	revoked_at  INTEGER NOT NULL,
	PRIMARY KEY (file_id, public_key)
);

-- Anciens propriétaires : leurs autorisations signées avant until restent valables.
CREATE TABLE previous_owners (
	file_id    TEXT    NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
	public_key BLOB    NOT NULL CHECK (length(public_key) = 32),
	until      INTEGER NOT NULL,
	PRIMARY KEY (file_id, public_key)
);

-- Groupes d'utilisateurs, propres à chaque utilisateur, pour partager en une commande.
CREATE TABLE user_groups (
	id         INTEGER PRIMARY KEY,
	owner_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	name       TEXT    NOT NULL,
	created_at INTEGER NOT NULL,
	UNIQUE (owner_id, name)
);
CREATE TABLE group_members (
	group_id INTEGER NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
	user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	PRIMARY KEY (group_id, user_id)
);
`

// migrate amène la base à la version schemaVersion, étape par étape, et refuse une base
// d'une version inconnue. Toutes les étapes sont faites dans une seule transaction :
// une base n'est jamais laissée à moitié migrée.
func migrate(db *sql.DB, now time.Time) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	switch {
	case version == schemaVersion:
		return nil
	case version > schemaVersion:
		return fmt.Errorf("base en version %d, ce coordinateur connaît la version %d", version, schemaVersion)
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if version < 1 {
		if _, err := tx.Exec(schemaV1); err != nil {
			return err
		}
		// L'époque 1 est la première : 0 se confondrait avec un champ absent en proto3.
		_, err = tx.Exec(`INSERT INTO epochs (number, state, started_at, finished_at) VALUES (1, 'committed', ?, ?)`,
			now.Unix(), now.Unix())
		if err != nil {
			return err
		}
	}
	if version < 2 {
		if _, err := tx.Exec(schemaV2); err != nil {
			return err
		}
	}
	if version < 3 {
		if _, err := tx.Exec(schemaV3); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion)); err != nil {
		return err
	}
	return tx.Commit()
}
