package obfs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

const (
        chameleonSaltLen   = 8
        chameleonKeyLen    = 32 // AES-256 key length
        chameleonNonceLen  = 12 // GCM nonce length
        chameleonTagLen    = 16 // GCM tag length
        chameleonMinPSKLen = 4
)

var _ Obfuscator = (*ChameleonObfuscator)(nil)

var (
        ErrInvalidPacket = errors.New("invalid packet")
)

type ChameleonObfuscator struct {
	PSK   []byte
	block cipher.Block
	gcm   cipher.AEAD
}

func NewChameleonObfuscator(psk []byte) (*ChameleonObfuscator, error) {
	if len(psk) < chameleonMinPSKLen {
		return nil, ErrPSKTooShort
	}

	o := &ChameleonObfuscator{PSK: psk}

	// Derive static key
	hash := sha256.Sum256(psk)
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	o.block = block
	o.gcm = gcm
	return o, nil
}

func (o *ChameleonObfuscator) Obfuscate(in, out []byte) int {
	nonce := make([]byte, chameleonNonceLen)
	_, _ = rand.Read(nonce) // Thread-safe

	ciphertext := o.gcm.Seal(nil, nonce, in, nil)
	outLen := chameleonNonceLen + len(ciphertext)
	if len(out) < outLen {
		return 0
	}

	copy(out[:chameleonNonceLen], nonce)
	copy(out[chameleonNonceLen:], ciphertext)
	return outLen
}

func (o *ChameleonObfuscator) Deobfuscate(in, out []byte) int {
	if len(in) < chameleonNonceLen {
		return 0
	}

	nonce := in[:chameleonNonceLen]
	ciphertext := in[chameleonNonceLen:]

	plaintext, err := o.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil || len(out) < len(plaintext) {
		return 0
	}

	copy(out, plaintext)
	return len(plaintext)
}
