# Proposition : RPC du coordinateur vers les nœuds (heartbeat + renouvellement)

Pour : Thomas (nœud) et l'équipe (`proto/` est partagé). Rédigé par Mohamed Amine, à discuter.

## Constat

`proto/node.proto` n'a aucune RPC appelée par le coordinateur. Il en faut deux sortes :

1. **Heartbeat (SV-51)**. En attendant, le coordinateur sonde chaque nœud par une poignée
   de main TLS 1.3 vérifiée par la CA (`cmd/coordinator/registry.go`). Ça détecte un nœud
   arrêté en 2 à 3 intervalles (4 à 6 s par défaut), mais pas un nœud dont la base est cassée.
2. **Renouvellement en deux phases (SV-21, SV-56)**. Le gestionnaire d'époques du
   coordinateur est écrit et testé (`cmd/coordinator/epochs.go`, état enregistré dans
   SQLite, reprise après crash) mais n'a personne à qui parler.

## 1. Heartbeat : service de santé standard de gRPC (aucun changement de proto)

Dans `cmd/node/main.go`, `newGRPCServer` :

```diff
+	"google.golang.org/grpc/health"
+	healthpb "google.golang.org/grpc/health/grpc_health_v1"
 ...
 	pb.RegisterNodeServer(server, node)
 	pb.RegisterRenewalServer(server, node)
+	healthServer := health.NewServer()
+	healthpb.RegisterHealthServer(server, healthServer) // SERVING par défaut
```

Le paquet fait partie du module grpc déjà présent : aucune dépendance nouvelle. Le
coordinateur remplacera alors sa sonde TLS par un `Health.Check` (quelques lignes dans
`tlsProbe`).

## 2. Renouvellement : nouveau service `Epoch` dans `node.proto`

```proto
// Appelé par le coordinateur uniquement. Aucune part ni sous-part dans ces messages (G3).
message EpochRequest {
  uint64 epoch = 1; // époque cible
}
message EpochResponse {}

service Epoch {
  // Phase 1 : échanger les sous-parts (service Renewal), calculer les parts de l'époque
  // et les garder EN ATTENTE (storage.PutPendingShare). Les parts en service restent.
  rpc Prepare(EpochRequest) returns (EpochResponse);
  // Phase 2 : storage.CommitEpoch(epoch). Doit être idempotent : rappelé après un crash.
  rpc Commit(EpochRequest) returns (EpochResponse);
  // Abandon : storage.AbortEpoch(epoch). Idempotent aussi.
  rpc Abort(EpochRequest) returns (EpochResponse);
}
```

Les trois fonctions de stockage existent déjà dans `internal/storage` ; seul le serveur
gRPC est à écrire côté nœud.

Points à trancher ensemble :

- **Authentification du coordinateur** : sans mTLS (SV-25), n'importe qui pourrait
  appeler `Commit`/`Abort`. Proposition : une signature Ed25519 du coordinateur sur
  `"safevault/epoch/v1" || 0x00 || étape || époque`, avec sa clé publique dans la config
  des nœuds, en attendant mTLS.
- **Qui lance l'échange des sous-parts** : proposition, le nœud lui-même pendant `Prepare`
  (il connaît les autres nœuds par une liste envoyée dans `EpochRequest`, ou par sa config).

## Règles côté coordinateur (déjà codées)

- Pas de renouvellement tant qu'un dépôt n'est pas confirmé ; pas de nouveau dépôt
  pendant un renouvellement (`CreateFile` répond `Unavailable`).
- Crash en `preparing` : ABORT partout. Crash en `committing` : COMMIT partout.
- Une époque abandonnée n'est jamais réutilisée (numéro neuf au renouvellement suivant).
