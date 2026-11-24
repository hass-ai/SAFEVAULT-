// Package access signe et vérifie les autorisations de partage (Grant) et les retraits
// d'accès (Revocation). Le propriétaire d'un fichier les signe avec sa clé Ed25519 ;
// les nœuds les vérifient avec la clé du propriétaire qu'ils ont enregistrée au dépôt.
// Le coordinateur les transmet mais ne peut pas en fabriquer : il n'a pas la clé privée
// du propriétaire.
//
// Données signées (entiers en gros-boutiste) :
//
//	étiquette || 0x00 || len(file_id) sur 4 octets || file_id
//	         || clé du propriétaire (32) || clé du destinataire (32) || date (8) [|| expiration (8)]
package access

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	pb "safevault/proto"
)

const (
	labelGrant      = "safevault/grant/v1"
	labelRevocation = "safevault/revoke/v1"

	// clockSkew est l'avance tolérée sur l'horloge du vérificateur pour une date d'émission.
	clockSkew = 2 * time.Minute
)

var (
	ErrMalformed   = errors.New("autorisation mal formée")
	ErrSignature   = errors.New("signature invalide")
	ErrExpired     = errors.New("autorisation expirée")
	ErrNotYetValid = errors.New("autorisation datée dans le futur")
	ErrWrongFile   = errors.New("autorisation pour un autre fichier")
	ErrWrongOwner  = errors.New("autorisation signée par une autre clé que celle du propriétaire")
	ErrWrongHolder = errors.New("autorisation faite pour une autre clé")
)

func message(label, fileID string, owner, grantee []byte, times ...int64) []byte {
	var b bytes.Buffer
	b.WriteString(label)
	b.WriteByte(0)
	binary.Write(&b, binary.BigEndian, uint32(len(fileID)))
	b.WriteString(fileID)
	b.Write(owner)
	b.Write(grantee)
	for _, t := range times {
		binary.Write(&b, binary.BigEndian, t)
	}
	return b.Bytes()
}

func grantMessage(g *pb.Grant) []byte {
	return message(labelGrant, g.FileId, g.OwnerPublicKey, g.GranteePublicKey, g.IssuedAt, g.ExpiresAt)
}

func revocationMessage(r *pb.Revocation) []byte {
	return message(labelRevocation, r.FileId, r.OwnerPublicKey, r.GranteePublicKey, r.RevokedAt)
}

// NewGrant crée et signe une autorisation de lecture du fichier fileID pour grantee,
// valable pendant validity à partir de now.
func NewGrant(owner ed25519.PrivateKey, fileID string, grantee ed25519.PublicKey, now time.Time, validity time.Duration) *pb.Grant {
	g := &pb.Grant{
		FileId:           fileID,
		OwnerPublicKey:   owner.Public().(ed25519.PublicKey),
		GranteePublicKey: grantee,
		IssuedAt:         now.Unix(),
		ExpiresAt:        now.Add(validity).Unix(),
	}
	g.Signature = ed25519.Sign(owner, grantMessage(g))
	return g
}

// NewRevocation crée et signe le retrait de l'accès de grantee au fichier fileID.
func NewRevocation(owner ed25519.PrivateKey, fileID string, grantee ed25519.PublicKey, now time.Time) *pb.Revocation {
	r := &pb.Revocation{
		FileId:           fileID,
		OwnerPublicKey:   owner.Public().(ed25519.PublicKey),
		GranteePublicKey: grantee,
		RevokedAt:        now.Unix(),
	}
	r.Signature = ed25519.Sign(owner, revocationMessage(r))
	return r
}

func checkKeys(owner, grantee, signature []byte) error {
	if len(owner) != ed25519.PublicKeySize || len(grantee) != ed25519.PublicKeySize ||
		len(signature) != ed25519.SignatureSize {
		return ErrMalformed
	}
	return nil
}

// VerifyGrant vérifie qu'une autorisation est bien formée, signée par owner pour le
// fichier fileID, et valable à l'instant now. Elle ne regarde pas les révocations.
func VerifyGrant(g *pb.Grant, fileID string, owner ed25519.PublicKey, now time.Time) error {
	if g == nil {
		return ErrMalformed
	}
	if err := checkKeys(g.OwnerPublicKey, g.GranteePublicKey, g.Signature); err != nil {
		return err
	}
	if g.FileId != fileID {
		return ErrWrongFile
	}
	if !bytes.Equal(g.OwnerPublicKey, owner) {
		return ErrWrongOwner
	}
	if !ed25519.Verify(owner, grantMessage(g), g.Signature) {
		return ErrSignature
	}
	if time.Unix(g.IssuedAt, 0).After(now.Add(clockSkew)) {
		return ErrNotYetValid
	}
	if !now.Before(time.Unix(g.ExpiresAt, 0)) {
		return ErrExpired
	}
	return nil
}

// VerifyGrantFor vérifie en plus que l'autorisation a été faite pour la clé holder.
func VerifyGrantFor(g *pb.Grant, fileID string, owner, holder ed25519.PublicKey, now time.Time) error {
	if err := VerifyGrant(g, fileID, owner, now); err != nil {
		return err
	}
	if !bytes.Equal(g.GranteePublicKey, holder) {
		return ErrWrongHolder
	}
	return nil
}

// VerifyRevocation vérifie qu'un retrait d'accès est bien formé et signé par owner.
func VerifyRevocation(r *pb.Revocation, owner ed25519.PublicKey) error {
	if r == nil {
		return ErrMalformed
	}
	if err := checkKeys(r.OwnerPublicKey, r.GranteePublicKey, r.Signature); err != nil {
		return err
	}
	if !bytes.Equal(r.OwnerPublicKey, owner) {
		return ErrWrongOwner
	}
	if !ed25519.Verify(owner, revocationMessage(r), r.Signature) {
		return ErrSignature
	}
	return nil
}

// Fingerprint renvoie l'empreinte lisible d'une clé publique : les 16 premiers octets
// de son SHA-256, en hexadécimal, par groupes de 4. Deux personnes la comparent pour
// s'assurer que le coordinateur n'a pas substitué une clé.
func Fingerprint(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	var parts []string
	for i := 0; i < 16; i += 2 {
		parts = append(parts, fmt.Sprintf("%02X%02X", sum[i], sum[i+1]))
	}
	return strings.Join(parts, " ")
}
