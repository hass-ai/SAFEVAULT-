package crypto

// Confidentialité des métadonnées envoyées au coordinateur :
//
//   - le nom d'un fichier est chiffré côté client. Pour le propriétaire, avec une clé
//     dérivée de sa clé privée Ed25519 ; pour un destinataire de partage, avec sa clé
//     publique (X25519 éphémère + HKDF + AES-GCM), si bien que lui seul peut le lire ;
//   - le contenu est complété par du remplissage jusqu'à une taille arrondie : le
//     coordinateur et les nœuds ne voient que l'ordre de grandeur de la taille.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
)

const (
	namesLabel  = "safevault/v1/names"
	sharedLabel = "safevault/v1/shared-name"
	nameAAD     = "safevault/v1/name"

	// MinPaddedSize est la plus petite taille arrondie d'un fichier (64 Kio).
	MinPaddedSize = 64 << 10
	lengthHeader  = 8 // taille réelle, en tête du contenu remplissé
)

var (
	ErrName    = errors.New("crypto : nom chiffré invalide ou clé incorrecte")
	ErrPadding = errors.New("crypto : remplissage invalide")
)

// ---------- Noms chiffrés pour soi ----------

// NamesKey dérive de la clé privée Ed25519 de l'utilisateur la clé qui chiffre les noms
// de ses fichiers. Elle n'est jamais stockée ni transmise.
func NamesKey(private ed25519.PrivateKey) ([]byte, error) {
	return hkdf.Key(sha256.New, private.Seed(), nil, namesLabel, KeySize)
}

// SealName chiffre un nom avec key (AES-256-GCM, nonce aléatoire) : nonce || chiffré.
func SealName(key []byte, name string) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, []byte(name), []byte(nameAAD)), nil
}

// OpenName déchiffre un nom chiffré par SealName.
func OpenName(key, sealed []byte) (string, error) {
	aead, err := newGCM(key)
	if err != nil {
		return "", err
	}
	if len(sealed) < aead.NonceSize() {
		return "", ErrName
	}
	plain, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], []byte(nameAAD))
	if err != nil {
		return "", ErrName
	}
	return string(plain), nil
}

// ---------- Noms chiffrés pour un destinataire ----------

// SealNameFor chiffre un nom pour le détenteur de la clé publique Ed25519 recipient :
// clé X25519 éphémère, secret partagé avec la clé X25519 équivalente du destinataire,
// clé AES dérivée par HKDF. Format : clé éphémère (32) || nonce (12) || chiffré.
func SealNameFor(recipient ed25519.PublicKey, name string) ([]byte, error) {
	recipientX, err := x25519Public(recipient)
	if err != nil {
		return nil, err
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := ephemeral.ECDH(recipientX)
	if err != nil {
		return nil, err
	}
	key, err := sharedNameKey(shared, ephemeral.PublicKey().Bytes(), recipientX.Bytes())
	if err != nil {
		return nil, err
	}
	sealed, err := SealName(key, name)
	if err != nil {
		return nil, err
	}
	return append(ephemeral.PublicKey().Bytes(), sealed...), nil
}

// OpenNameFrom déchiffre, avec la clé privée Ed25519 du destinataire, un nom chiffré
// par SealNameFor.
func OpenNameFrom(private ed25519.PrivateKey, sealed []byte) (string, error) {
	if len(sealed) < 32 {
		return "", ErrName
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(sealed[:32])
	if err != nil {
		return "", ErrName
	}
	own, err := x25519Private(private)
	if err != nil {
		return "", err
	}
	shared, err := own.ECDH(ephemeral)
	if err != nil {
		return "", ErrName
	}
	key, err := sharedNameKey(shared, sealed[:32], own.PublicKey().Bytes())
	if err != nil {
		return "", err
	}
	return OpenName(key, sealed[32:])
}

func sharedNameKey(shared, ephemeral, recipient []byte) ([]byte, error) {
	salt := append(append([]byte{}, ephemeral...), recipient...)
	return hkdf.Key(sha256.New, shared, salt, sharedLabel, KeySize)
}

// x25519Public convertit une clé publique Ed25519 en clé publique X25519 (même courbe,
// forme de Montgomery). Un utilisateur n'a ainsi qu'une seule paire de clés.
func x25519Public(public ed25519.PublicKey) (*ecdh.PublicKey, error) {
	point, err := new(edwards25519.Point).SetBytes(public)
	if err != nil {
		return nil, fmt.Errorf("crypto : clé publique invalide : %w", err)
	}
	return ecdh.X25519().NewPublicKey(point.BytesMontgomery())
}

// x25519Private convertit une clé privée Ed25519 en clé privée X25519 : le scalaire
// Ed25519 est la première moitié de SHA-512(graine), réduite par X25519 elle-même.
func x25519Private(private ed25519.PrivateKey) (*ecdh.PrivateKey, error) {
	h := sha512.Sum512(private.Seed())
	return ecdh.X25519().NewPrivateKey(h[:32])
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("crypto : la clé doit faire %d octets, pas %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// ---------- Remplissage ----------

// PaddedSize renvoie la taille arrondie d'un contenu de n octets : la plus petite
// puissance de 2 (au moins MinPaddedSize) qui contient n octets et l'en-tête de taille.
func PaddedSize(n int) int {
	size := MinPaddedSize
	for size < n+lengthHeader {
		size *= 2
	}
	return size
}

// Pad renvoie data précédé de sa taille réelle et complété par des zéros jusqu'à
// PaddedSize(len(data)). Le remplissage est chiffré avec le reste : il ne se voit pas.
func Pad(data []byte) []byte {
	padded := make([]byte, PaddedSize(len(data)))
	binary.BigEndian.PutUint64(padded, uint64(len(data)))
	copy(padded[lengthHeader:], data)
	return padded
}

// Unpad retire l'en-tête et le remplissage ajoutés par Pad.
func Unpad(padded []byte) ([]byte, error) {
	if len(padded) < lengthHeader {
		return nil, ErrPadding
	}
	n := binary.BigEndian.Uint64(padded)
	if n > uint64(len(padded)-lengthHeader) {
		return nil, ErrPadding
	}
	return padded[lengthHeader : lengthHeader+int(n)], nil
}
