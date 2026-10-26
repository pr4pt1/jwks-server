package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"time"
)

// KeyPair is an RSA key with a unique key ID and an expiry time.
type KeyPair struct {
	KID     string
	Private *rsa.PrivateKey
	Expiry  time.Time
}

// JWK is the public-key representation served from the JWKS endpoint (RFC 7517).
type JWK struct {
	KTY string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// NewKeyPair generates a 2048-bit RSA key that expires ttl from now.
// A negative ttl produces an already-expired key.
func NewKeyPair(ttl time.Duration) (*KeyPair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	return &KeyPair{
		KID:     hex.EncodeToString(id),
		Private: priv,
		Expiry:  time.Now().Add(ttl),
	}, nil
}

// Expired reports whether the key's expiry has passed.
func (k *KeyPair) Expired() bool {
	return time.Now().After(k.Expiry)
}

// JWK converts the public half of the key into JWK form.
// Per the RFC, n and e are big-endian, base64url-encoded with no padding.
func (k *KeyPair) JWK() JWK {
	pub := k.Private.PublicKey
	return JWK{
		KTY: "RSA",
		Use: "sig",
		Alg: "RS256",
		KID: k.KID,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}