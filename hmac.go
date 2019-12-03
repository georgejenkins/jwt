package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
)

// HMACSignerVerifier contains configuration for signing
// and verifying JWSs using the HS256/384/512 family.
type HMACSignerVerifier struct {
	algorithm Algorithm
	key       []byte
}

// InitHMACSignerVerifier initializes a new HMAC signer/verifier.
func InitHMACSignerVerifier(alg Algorithm, key []byte) (*HMACSignerVerifier, error) {
	if len(key) == 0 {
		return nil, errors.New("Cannot initialize HMACSignerVerifier with an empty key")
	}

	if "" == alg {
		return nil, errors.New("Cannot initialize HMACSignerVerifier with no algorithm")
	}

	if HS256 != alg && HS384 != alg && HS512 != alg {
		return nil, errors.New("Signing algorithm unexpected, must be one of: HS256, HS384, HS512")
	}

	return &HMACSignerVerifier{
		algorithm: alg,
		key:       key,
	}, nil
}

// Sign signs a payload using the key the HMACSignerVerifier was initialized with.
func (sv *HMACSignerVerifier) Sign(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("Payload cannot be empty")
	}

	hash, err := sv.initHash()
	if nil != err {
		return nil, err
	}

	hash.Write(plaintext)

	return hash.Sum(nil), nil
}

// Verify verifies a payload using the key the HMACSignerVerifier was initialized with
// against the provided ciphertext.
func (sv *HMACSignerVerifier) Verify(plaintext []byte, signature []byte) (bool, error) {
	if len(plaintext) == 0 {
		return false, errors.New("Plaintext cannot be empty")
	}

	if len(signature) == 0 {
		return false, errors.New("Signature cannot be empty")
	}

	output, err := sv.Sign(plaintext)
	if nil != err {
		return false, err
	}

	return (subtle.ConstantTimeCompare(signature, output) == 1), nil
}

func (sv *HMACSignerVerifier) initHash() (hash.Hash, error) {
	switch sv.algorithm {
	case HS256:
		return hmac.New(sha256.New, sv.key), nil
	case HS384:
		return hmac.New(sha512.New384, sv.key), nil
	case HS512:
		return hmac.New(sha512.New, sv.key), nil
	}

	return nil, fmt.Errorf("Cannot HMACSignerVerifier hash with the configured algorithm %s", sv.algorithm)
}
