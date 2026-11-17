# Proposition : ajouter le coordinateur à Docker Compose et à la CI

Pour : Ayman (branche `feat/docker`). Rédigé par Mohamed Amine, à discuter.

## Constat

- `cmd/coordinator` démarre maintenant (TLS 1.3 sur `:7443`, base dans `DATA_DIR`,
  health check gRPC standard `grpc.health.v1.Health`).
- Dans `docker-compose.yml`, `node-3` publie le port hôte **7443**, qui est aussi le
  port par défaut du coordinateur côté client (`COORD_ADDR=localhost:7443`).
  Un client lancé hors Docker parlerait au nœud 3 au lieu du coordinateur.

## Changement proposé

```diff
   node-3:
     <<: *node
     environment: { <<: *node-env, NODE_X: "3" }
-    ports: ["7443:7444"]
+    ports: ["7453:7444"]

+  coordinator:
+    build:
+      context: .
+      args:
+        CMD: coordinator
+    restart: unless-stopped
+    environment:
+      LISTEN_ADDR: ":7443"
+      DATA_DIR: /data
+      TLS_CERT_PATH: /certs/coordinator.crt
+      TLS_KEY_PATH: /certs/coordinator.key
+      SV_N: "5"
+      SV_T: "3"
+    ports: ["7443:7443"]
+    volumes:
+      - coordinator-data:/data
+      - ./certs/coordinator.crt:/certs/coordinator.crt:ro
+      - ./certs/coordinator.key:/certs/coordinator.key:ro

 volumes:
+  coordinator-data:
```

(Ou bien publier les nœuds sur 7451 à 7455 pour éviter tout chevauchement.)

Le certificat `coordinator` est déjà produit par `scripts/gen_certs.sh`. Le Dockerfile
fonctionne tel quel avec `--build-arg CMD=coordinator`.

CI, job `docker` : ajouter `docker build --build-arg CMD=coordinator -t safevault-coordinator .`

Plus tard (SV-51) : une variable `NODES=1=node-1:7444,...` pour le registre des nœuds.
