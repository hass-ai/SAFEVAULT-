package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Noms portés par les certificats des composants internes (champ CN), tels que les
// produit scripts/gen_certs.sh.
const coordinatorName = "coordinator"

func nodeName(x uint32) string {
	return fmt.Sprintf("node-%d", x)
}

// requirePeer vérifie que l'appelant a présenté un certificat signé par la CA au nom
// want. Le serveur TLS a déjà vérifié la signature (VerifyClientCertIfGiven) : il reste
// à vérifier qu'un certificat a bien été présenté et qu'il est au bon nom.
func requirePeer(ctx context.Context, want string) error {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "appelant inconnu")
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.VerifiedChains) == 0 {
		return status.Error(codes.Unauthenticated, "certificat client requis")
	}
	if got := info.State.PeerCertificates[0].Subject.CommonName; got != want {
		return status.Errorf(codes.PermissionDenied, "réservé à %s, appelant %q", want, got)
	}
	return nil
}

// peerTLSConfig renvoie la configuration TLS du nœud quand il appelle un autre nœud :
// il présente son propre certificat et vérifie celui de l'autre avec la CA.
func peerTLSConfig(cert tls.Certificate, ca *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      ca,
		MinVersion:   tls.VersionTLS13,
	}
}
