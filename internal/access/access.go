// Package access signe et vérifie les droits sur les fichiers : autorisations (Grant),
// retraits d'accès (Revocation) et transferts de propriété (Transfer).
//
// La racine de confiance d'un fichier est la clé de son propriétaire, que les nœuds ont
// enregistrée au dépôt. Une autorisation est signée soit par le propriétaire, soit par
// un utilisateur qui a lui-même reçu le droit de partager (s) ou de gérer (m) : il joint
// alors sa propre autorisation (champ parent), et ainsi de suite jusqu'au propriétaire.
// Les nœuds vérifient toute la chaîne. Le coordinateur transmet ces objets mais ne peut
// pas en fabriquer : il n'a la clé privée de personne.
//
// Données signées (entiers en gros-boutiste) :
//
//	étiquette || 0x00 || len(file_id) sur 4 octets || file_id || clé de l'émetteur (32)
//	          || clé visée (32) || champs propres à l'objet (8 octets chacun)
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

// Droits sur un fichier.
const (
	Read   uint32 = 1 << iota // r : récupérer le fichier et ses versions
	Write                     // w : déposer une nouvelle version
	Share                     // s : partager à son tour, avec au plus ses propres droits
	Delete                    // d : supprimer le fichier
	Manage                    // m : donner, modifier ou retirer n'importe quel accès, renommer

	// All est l'ensemble des droits, ceux du propriétaire.
	All = Read | Write | Share | Delete | Manage
)

const (
	labelGrant      = "safevault/grant/v2"
	labelRevocation = "safevault/revoke/v2"
	labelTransfer   = "safevault/transfer/v1"

	// clockSkew est l'avance tolérée sur l'horloge du vérificateur pour une date d'émission.
	clockSkew = 2 * time.Minute
	// maxChain est la longueur maximale d'une chaîne de délégation.
	maxChain = 4
)

var (
	ErrMalformed   = errors.New("autorisation mal formée")
	ErrSignature   = errors.New("signature invalide")
	ErrExpired     = errors.New("autorisation expirée")
	ErrNotYetValid = errors.New("autorisation datée dans le futur")
	ErrWrongFile   = errors.New("autorisation pour un autre fichier")
	ErrNotOwner    = errors.New("chaîne qui ne remonte pas au propriétaire du fichier")
	ErrWrongHolder = errors.New("autorisation faite pour une autre clé")
	ErrRights      = errors.New("droits insuffisants")
	ErrDelegation  = errors.New("délégation au-delà des droits de l'émetteur")
	ErrRevoked     = errors.New("accès retiré")
	ErrTooLong     = errors.New("chaîne de délégation trop longue")
)

// Owner est une clé qui a été propriétaire du fichier. Until vaut 0 pour le propriétaire
// actuel ; pour un ancien propriétaire, c'est la date du transfert : ses autorisations
// émises avant cette date restent valables.
type Owner struct {
	Key   ed25519.PublicKey
	Until int64
}

// Context donne au vérificateur ce qu'il sait du fichier.
type Context struct {
	FileID string
	Owners []Owner
	// RevokedAt renvoie la date du dernier retrait d'accès de la clé grantee, s'il existe.
	RevokedAt func(grantee []byte) (int64, bool, error)
	Now       time.Time
}

// ---------- Création ----------

// NewGrant crée une autorisation de fileID pour grantee, avec les droits rights, signée
// par issuer. expires vaut 0 pour une autorisation sans limite de durée. parent est
// l'autorisation de l'émetteur quand il n'est pas propriétaire (nil sinon).
func NewGrant(issuer ed25519.PrivateKey, fileID string, grantee ed25519.PublicKey, rights uint32,
	issuedAt time.Time, expires time.Time, parent *pb.Grant) *pb.Grant {

	g := &pb.Grant{
		FileId:           fileID,
		IssuerPublicKey:  issuer.Public().(ed25519.PublicKey),
		GranteePublicKey: grantee,
		IssuedAt:         issuedAt.Unix(),
		Rights:           rights,
		Parent:           parent,
	}
	if !expires.IsZero() {
		g.ExpiresAt = expires.Unix()
	}
	g.Signature = ed25519.Sign(issuer, grantMessage(g))
	return g
}

// NewRevocation crée le retrait de l'accès de grantee à fileID, signé par issuer. authority
// est l'autorisation de l'émetteur (avec le droit m) quand il n'est pas propriétaire.
func NewRevocation(issuer ed25519.PrivateKey, fileID string, grantee ed25519.PublicKey, at time.Time,
	authority *pb.Grant) *pb.Revocation {

	r := &pb.Revocation{
		FileId:           fileID,
		IssuerPublicKey:  issuer.Public().(ed25519.PublicKey),
		GranteePublicKey: grantee,
		RevokedAt:        at.Unix(),
		Authority:        authority,
	}
	r.Signature = ed25519.Sign(issuer, revocationMessage(r))
	return r
}

// NewTransfer crée le transfert de la propriété de fileID à newOwner, signé par le
// propriétaire actuel.
func NewTransfer(owner ed25519.PrivateKey, fileID string, newOwner ed25519.PublicKey, at time.Time) *pb.Transfer {
	t := &pb.Transfer{
		FileId:            fileID,
		OwnerPublicKey:    owner.Public().(ed25519.PublicKey),
		NewOwnerPublicKey: newOwner,
		TransferredAt:     at.Unix(),
	}
	t.Signature = ed25519.Sign(owner, transferMessage(t))
	return t
}

func message(label, fileID string, issuer, subject []byte, fields ...int64) []byte {
	var b bytes.Buffer
	b.WriteString(label)
	b.WriteByte(0)
	binary.Write(&b, binary.BigEndian, uint32(len(fileID)))
	b.WriteString(fileID)
	b.Write(issuer)
	b.Write(subject)
	for _, f := range fields {
		binary.Write(&b, binary.BigEndian, f)
	}
	return b.Bytes()
}

func grantMessage(g *pb.Grant) []byte {
	return message(labelGrant, g.FileId, g.IssuerPublicKey, g.GranteePublicKey,
		g.IssuedAt, g.ExpiresAt, int64(g.Rights))
}

func revocationMessage(r *pb.Revocation) []byte {
	return message(labelRevocation, r.FileId, r.IssuerPublicKey, r.GranteePublicKey, r.RevokedAt)
}

func transferMessage(t *pb.Transfer) []byte {
	return message(labelTransfer, t.FileId, t.OwnerPublicKey, t.NewOwnerPublicKey, t.TransferredAt)
}

// ---------- Vérification ----------

func validKey(k []byte) bool { return len(k) == ed25519.PublicKeySize }

// VerifyGrant vérifie toute la chaîne de l'autorisation g pour le fichier du contexte, et
// renvoie les droits qu'elle donne à son détenteur.
func VerifyGrant(g *pb.Grant, c Context) (uint32, error) {
	return verifyLink(g, c, 0)
}

// VerifyGrantFor vérifie en plus que g a été faite pour la clé holder et qu'elle donne
// au moins les droits want.
func VerifyGrantFor(g *pb.Grant, holder []byte, want uint32, c Context) (uint32, error) {
	rights, err := VerifyGrant(g, c)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(g.GranteePublicKey, holder) {
		return 0, ErrWrongHolder
	}
	if rights&want != want {
		return 0, ErrRights
	}
	return rights, nil
}

func verifyLink(g *pb.Grant, c Context, depth int) (uint32, error) {
	if g == nil || !validKey(g.IssuerPublicKey) || !validKey(g.GranteePublicKey) ||
		len(g.Signature) != ed25519.SignatureSize || g.Rights == 0 || g.Rights&^All != 0 {
		return 0, ErrMalformed
	}
	if depth >= maxChain {
		return 0, ErrTooLong
	}
	if g.FileId != c.FileID {
		return 0, ErrWrongFile
	}
	if !ed25519.Verify(g.IssuerPublicKey, grantMessage(g), g.Signature) {
		return 0, ErrSignature
	}
	if time.Unix(g.IssuedAt, 0).After(c.Now.Add(clockSkew)) {
		return 0, ErrNotYetValid
	}
	if g.ExpiresAt != 0 && !c.Now.Before(time.Unix(g.ExpiresAt, 0)) {
		return 0, ErrExpired
	}
	if err := checkNotRevoked(g, c); err != nil {
		return 0, err
	}

	if g.Parent == nil {
		// L'émetteur doit être le propriétaire (ou l'avoir été quand il a signé).
		if !isOwner(g.IssuerPublicKey, g.IssuedAt, c.Owners) {
			return 0, ErrNotOwner
		}
		return g.Rights, nil
	}

	parentRights, err := verifyLink(g.Parent, c, depth+1)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(g.Parent.GranteePublicKey, g.IssuerPublicKey) {
		return 0, ErrNotOwner
	}
	switch {
	case parentRights&Manage != 0:
		// Un co-administrateur peut donner n'importe quels droits.
	case parentRights&Share != 0:
		if g.Rights&^parentRights != 0 {
			return 0, ErrDelegation
		}
		if g.Parent.ExpiresAt != 0 && (g.ExpiresAt == 0 || g.ExpiresAt > g.Parent.ExpiresAt) {
			return 0, ErrDelegation
		}
	default:
		return 0, ErrDelegation
	}
	return g.Rights, nil
}

func checkNotRevoked(g *pb.Grant, c Context) error {
	if c.RevokedAt == nil {
		return nil
	}
	at, revoked, err := c.RevokedAt(g.GranteePublicKey)
	if err != nil {
		return err
	}
	if revoked && g.IssuedAt <= at {
		return ErrRevoked
	}
	return nil
}

func isOwner(key []byte, at int64, owners []Owner) bool {
	for _, o := range owners {
		if bytes.Equal(o.Key, key) && (o.Until == 0 || at <= o.Until) {
			return true
		}
	}
	return false
}

// CurrentOwner renvoie la clé du propriétaire actuel.
func CurrentOwner(owners []Owner) ed25519.PublicKey {
	for _, o := range owners {
		if o.Until == 0 {
			return o.Key
		}
	}
	return nil
}

// Authorize renvoie les droits de la clé holder sur le fichier : tous s'il est le
// propriétaire actuel, sinon ceux de son autorisation g (qui doit contenir want).
func Authorize(holder []byte, g *pb.Grant, want uint32, c Context) (uint32, error) {
	if bytes.Equal(holder, CurrentOwner(c.Owners)) {
		return All, nil
	}
	if g == nil {
		return 0, ErrRights
	}
	return VerifyGrantFor(g, holder, want, c)
}

// VerifyRevocation vérifie qu'un retrait d'accès est signé par le propriétaire actuel ou
// par un utilisateur qui a le droit de gérer les accès (m).
func VerifyRevocation(r *pb.Revocation, c Context) error {
	if r == nil || !validKey(r.IssuerPublicKey) || !validKey(r.GranteePublicKey) ||
		len(r.Signature) != ed25519.SignatureSize {
		return ErrMalformed
	}
	if r.FileId != c.FileID {
		return ErrWrongFile
	}
	if !ed25519.Verify(r.IssuerPublicKey, revocationMessage(r), r.Signature) {
		return ErrSignature
	}
	_, err := Authorize(r.IssuerPublicKey, r.Authority, Manage, c)
	return err
}

// VerifyTransfer vérifie qu'un transfert de propriété est signé par le propriétaire actuel.
func VerifyTransfer(t *pb.Transfer, c Context) error {
	if t == nil || !validKey(t.OwnerPublicKey) || !validKey(t.NewOwnerPublicKey) ||
		len(t.Signature) != ed25519.SignatureSize {
		return ErrMalformed
	}
	if t.FileId != c.FileID {
		return ErrWrongFile
	}
	if !bytes.Equal(t.OwnerPublicKey, CurrentOwner(c.Owners)) {
		return ErrNotOwner
	}
	if !ed25519.Verify(t.OwnerPublicKey, transferMessage(t), t.Signature) {
		return ErrSignature
	}
	return nil
}

// Expiry renvoie la date de fin effective d'une autorisation : la plus proche des dates
// d'expiration de sa chaîne (0 = sans limite).
func Expiry(g *pb.Grant) int64 {
	var end int64
	for ; g != nil; g = g.Parent {
		if g.ExpiresAt != 0 && (end == 0 || g.ExpiresAt < end) {
			end = g.ExpiresAt
		}
	}
	return end
}

// ---------- Affichage ----------

// ParseRights lit des droits écrits « rwsdm » (dans n'importe quel ordre).
func ParseRights(s string) (uint32, error) {
	var rights uint32
	for _, c := range strings.ToLower(s) {
		switch c {
		case 'r':
			rights |= Read
		case 'w':
			rights |= Write
		case 's':
			rights |= Share
		case 'd':
			rights |= Delete
		case 'm':
			rights |= Manage
		default:
			return 0, fmt.Errorf("droit %q inconnu (r, w, s, d ou m)", c)
		}
	}
	if rights == 0 {
		return 0, errors.New("aucun droit")
	}
	return rights | Read, nil // tous les droits supposent la lecture
}

// RightsString écrit des droits sous la forme « rwsdm », avec « - » pour un droit absent.
func RightsString(rights uint32) string {
	letters := []struct {
		bit uint32
		c   byte
	}{{Read, 'r'}, {Write, 'w'}, {Share, 's'}, {Delete, 'd'}, {Manage, 'm'}}
	out := make([]byte, len(letters))
	for i, l := range letters {
		out[i] = '-'
		if rights&l.bit != 0 {
			out[i] = l.c
		}
	}
	return string(out)
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
