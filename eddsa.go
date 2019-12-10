package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
)

// EdDSASigner contains configuration for signing JWSs using EdDSA + Edwards25519
type EdDSASigner struct {
	algorithm Algorithm
	prvKey    *ed25519.PrivateKey
	rng       io.Reader
}

// InitEdDSASigner initializes a new ECDSA family signer.
func InitEdDSASigner(alg Algorithm, key *ed25519.PrivateKey) (*EdDSASigner, error) {
	if nil == key {
		return nil, errors.New("Cannot init EdDSASigner with empty key")
	}

	if "" == alg {
		return nil, errors.New("Cannot init EdDSASigner with no algorithm")
	}

	return &EdDSASigner{
		algorithm: alg,
		prvKey:    key,
		rng:       rand.Reader,
	}, nil
}

// Sign signs a payload using the key the ECDSASigner was initialized with.
func (sv *EdDSASigner) Sign(plaintext []byte) ([]byte, error) {
	return ed25519.Sign(*sv.prvKey, plaintext), nil
}

// EdDSAVerifier contains configuration for verifying JWSs using the ECDSA 256/384/512 family.
type EdDSAVerifier struct {
	algorithm Algorithm
	pubKey    *ed25519.PublicKey
}

// InitEdDSAVerifier initializes a new ECDSA family signer.
func InitEdDSAVerifier(alg Algorithm, key *ed25519.PublicKey) (*EdDSAVerifier, error) {
	if nil == key {
		return nil, errors.New("Cannot init EdDSAVerifier with empty key")
	}

	if "" == alg {
		return nil, errors.New("Cannot init EdDSAVerifier with no algorithm")
	}

	if EdDSA != alg {
		return nil, errors.New("Signing algorithm unexpected, must be: EdDSA")
	}

	return &EdDSAVerifier{
		algorithm: alg,
		pubKey:    key,
	}, nil
}

// Verify verifies a payload using the key the EdDSAVerifier was initialized with
// against the provided ciphertext.
func (sv *EdDSAVerifier) Verify(plaintext []byte, signature []byte) (bool, error) {
	return ed25519.Verify(*sv.pubKey, plaintext, signature), nil
}
