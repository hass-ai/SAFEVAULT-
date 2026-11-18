#!/usr/bin/env bash
# Génère la CA interne de SafeVault et un certificat par composant.
# Certificats de développement uniquement : ils ne doivent pas être commités.
#
# Usage : scripts/gen-certs.sh [dossier de sortie]   (défaut : certs)
set -euo pipefail

OUT="${1:-certs}"
NODES="${NODES:-5}"
DAYS=365

mkdir -p "$OUT"
cd "$OUT"

# 1. L'autorité de certification (CA), créée une seule fois.
if [ ! -f ca.key ]; then
  openssl req -x509 -new -noenc -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout ca.key -out ca.crt -days "$DAYS" -subj "/CN=SafeVault CA"
fi

# 2. Un certificat signé par la CA, valable pour le nom Docker du composant.
sign() {
  local name=$1
  openssl req -new -noenc -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$name.key" -out "$name.csr" -subj "/CN=$name"
  printf 'subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n' \
    "$name" > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "$name.crt" -days "$DAYS" -extfile "$name.ext"
  rm "$name.csr" "$name.ext"
  # Lisible par l'utilisateur non-root des conteneurs.
  chmod 644 "$name.key"
}

for i in $(seq 1 "$NODES"); do
  sign "node-$i"
done
sign coordinator

echo "Certificats générés dans $OUT/"