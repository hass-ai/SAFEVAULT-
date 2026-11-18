// Package crypto chiffre les fichiers de SafeVault.
//
// Chaîne côté client :
//
//	secret (scalaire partagé par Shamir) ──HKDF-SHA256──▶ clé AES-256 du fichier
//	fichier ──découpage en blocs──▶ AES-256-GCM par bloc ──▶ blocs chiffrés déposés sur les nœuds
//
// Chaque bloc est authentifié avec, en données associées, l'identifiant du
// fichier, son numéro et un drapeau « dernier bloc ». Un nœud malveillant ne
// peut donc ni modifier un bloc, ni l'échanger avec un autre (du même fichier
// ou d'un autre), ni réordonner les blocs, ni tronquer le fichier sans que le
// déchiffrement échoue.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// KeySize est la taille d'une clé de fichier (AES-256).
	KeySize = 32
	// SecretSize est la taille de l'encodage d'un scalaire edwards25519.
	SecretSize = 32
	// DefaultBlockSize est la taille par défaut d'un bloc en clair (1 Mio).
	DefaultBlockSize = 1 << 20
	// Overhead est le nombre d'octets ajoutés à chaque bloc (étiquette GCM).
	Overhead = 16

	keyLabel   = "safevault/v1/file-key"
	blockLabel = "safevault/v1/block"
)

var (
	ErrDecrypt   = errors.New("crypto : bloc invalide (modifié, déplacé, tronqué ou mauvaise clé)")
	ErrNoBlocks  = errors.New("crypto : aucun bloc")
	ErrBlockSize = errors.New("crypto : taille de bloc invalide")
)

// DeriveFileKey dérive la clé AES-256 du fichier fileID à partir du secret
// partagé (encodage canonique sur 32 octets d'un scalaire, voir
// edwards25519.Scalar.Bytes).
//
// On ne chiffre pas directement avec le scalaire : il vit dans un corps
// d'ordre ≈ 2^252, ce n'est pas une chaîne uniforme de 256 bits. HKDF en
// extrait une clé uniforme et la lie à fileID.
func DeriveFileKey(secret, fileID []byte) ([]byte, error) {
	if len(secret) != SecretSize {
		return nil, fmt.Errorf("crypto : le secret doit faire %d octets, pas %d", SecretSize, len(secret))
	}
	return hkdf.Key(sha256.New, secret, nil, keyLabel+string(fileID), KeySize)
}

// FileCipher chiffre et déchiffre les blocs d'un fichier.
//
// Le nonce GCM est le numéro du bloc. C'est sûr parce que chaque fichier a sa
// propre clé, tirée d'un secret neuf : une même clé ne doit JAMAIS chiffrer
// deux contenus différents (une nouvelle version d'un fichier = un nouveau secret).
type FileCipher struct {
	aead   cipher.AEAD
	prefix []byte // label || len(fileID) || fileID
}

// NewFileCipher prépare le chiffrement des blocs du fichier fileID avec key.
func NewFileCipher(key, fileID []byte) (*FileCipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("crypto : la clé doit faire %d octets, pas %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	prefix := make([]byte, 0, len(blockLabel)+4+len(fileID))
	prefix = append(prefix, blockLabel...)
	prefix = binary.BigEndian.AppendUint32(prefix, uint32(len(fileID)))
	prefix = append(prefix, fileID...)
	return &FileCipher{aead: aead, prefix: prefix}, nil
}

func (c *FileCipher) nonce(index uint64) []byte {
	n := make([]byte, c.aead.NonceSize())
	binary.BigEndian.PutUint64(n[len(n)-8:], index)
	return n
}

func (c *FileCipher) aad(index uint64, last bool) []byte {
	aad := make([]byte, 0, len(c.prefix)+9)
	aad = append(aad, c.prefix...)
	aad = binary.BigEndian.AppendUint64(aad, index)
	if last {
		return append(aad, 1)
	}
	return append(aad, 0)
}

// SealBlock chiffre le bloc numéro index. last indique le dernier bloc du fichier.
func (c *FileCipher) SealBlock(index uint64, last bool, plaintext []byte) []byte {
	return c.aead.Seal(nil, c.nonce(index), plaintext, c.aad(index, last))
}

// OpenBlock déchiffre et vérifie le bloc numéro index.
func (c *FileCipher) OpenBlock(index uint64, last bool, ciphertext []byte) ([]byte, error) {
	plaintext, err := c.aead.Open(nil, c.nonce(index), ciphertext, c.aad(index, last))
	if err != nil {
		return nil, fmt.Errorf("%w : bloc %d", ErrDecrypt, index)
	}
	return plaintext, nil
}

// EncryptStream lit r par blocs de blockSize octets, chiffre chaque bloc et le
// passe à emit, dans l'ordre. Elle renvoie le nombre de blocs. Un fichier vide
// donne un unique bloc vide (marqué dernier), pour qu'il reste authentifié.
func (c *FileCipher) EncryptStream(r io.Reader, blockSize int, emit func(index uint64, block []byte) error) (uint64, error) {
	if blockSize <= 0 {
		return 0, ErrBlockSize
	}
	cur := make([]byte, blockSize)
	next := make([]byte, blockSize)

	n, done, err := readBlock(r, cur)
	if err != nil {
		return 0, err
	}
	for index := uint64(0); ; index++ {
		if done {
			return index + 1, emit(index, c.SealBlock(index, true, cur[:n]))
		}
		m, nextDone, err := readBlock(r, next)
		if err != nil {
			return index, err
		}
		if m == 0 { // la lecture précédente finissait pile sur une frontière de bloc
			return index + 1, emit(index, c.SealBlock(index, true, cur[:n]))
		}
		if err := emit(index, c.SealBlock(index, false, cur[:n])); err != nil {
			return index, err
		}
		cur, next = next, cur
		n, done = m, nextDone
	}
}

// readBlock remplit buf autant que possible ; done indique la fin de r.
func readBlock(r io.Reader, buf []byte) (n int, done bool, err error) {
	n, err = io.ReadFull(r, buf)
	switch err {
	case nil:
		return n, false, nil
	case io.EOF, io.ErrUnexpectedEOF:
		return n, true, nil
	default:
		return n, false, err
	}
}

// EncryptBlocks chiffre r et renvoie tous les blocs en mémoire.
func (c *FileCipher) EncryptBlocks(r io.Reader, blockSize int) ([][]byte, error) {
	var blocks [][]byte
	_, err := c.EncryptStream(r, blockSize, func(_ uint64, b []byte) error {
		blocks = append(blocks, b)
		return nil
	})
	return blocks, err
}

// DecryptBlocks déchiffre les blocs, dans l'ordre, et écrit le clair dans w.
// Le dernier bloc doit porter le drapeau « dernier » : un fichier tronqué est rejeté.
// En cas d'erreur, w peut avoir reçu le début du fichier : l'appelant doit
// écrire dans un fichier temporaire et ne le garder que si DecryptBlocks réussit.
func (c *FileCipher) DecryptBlocks(blocks [][]byte, w io.Writer) error {
	if len(blocks) == 0 {
		return ErrNoBlocks
	}
	for i, b := range blocks {
		plaintext, err := c.OpenBlock(uint64(i), i == len(blocks)-1, b)
		if err != nil {
			return err
		}
		if _, err := w.Write(plaintext); err != nil {
			return err
		}
	}
	return nil
}
