package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
)

// RSASigner contains configuration for signing JWSs using the
// RS/PS 256/384/512 family.
type RSASigner struct {
	algorithm Algorithm
	hash      crypto.Hash
	prvKey    *rsa.PrivateKey
	rng       io.Reader
}

// InitRSASigner initializes a new RSA family signer.
func InitRSASigner(alg Algorithm, key *rsa.PrivateKey) (*RSASigner, error) {
	if nil == key {
		return nil, errors.New("Cannot init RSASigner with empty key")
	}

	if "" == alg {
		return nil, errors.New("Cannot init RSASigner with no algorithm")
	}

	if RS256 != alg && RS384 != alg && RS512 != alg &&
		PS256 != alg && PS384 != alg && PS512 != alg {
		return nil, errors.New("Signing algorithm unexpected, must be one of: RS256, RS384, RS512, PS256, PS384, PS512")
	}

	hashFunc, err := getHashAlgorithm(alg)
	if err != nil {
		return nil, err
	}

	return &RSASigner{
		algorithm: alg,
		hash:      hashFunc,
		prvKey:    key,
		rng:       rand.Reader,
	}, nil
}

// Sign signs a payload using the key the RSASigner was initialized with.
func (sv *RSASigner) Sign(plaintext []byte) ([]byte, error) {
	hash, err := GetHash(sv.algorithm, plaintext)
	if nil != err {
		return nil, err
	}

	var signature []byte

	switch sv.algorithm {
	case RS256, RS384, RS512:
		signature, err = rsa.SignPKCS1v15(sv.rng, sv.prvKey, sv.hash, hash)
	case PS256, PS384, PS512:
		signature, err = rsa.SignPSS(sv.rng, sv.prvKey, sv.hash, hash, nil)
	}

	if err != nil {
		return nil, fmt.Errorf("error from signing: %s", err)
	}

	return signature, nil
}

// RSAVerifier contains configuration for verifying JWSs using the RS/PS 256/384/512 family.
type RSAVerifier struct {
	algorithm Algorithm
	hash      crypto.Hash
	pubKey    *rsa.PublicKey
}

// InitRSAVerifier initializes a new RS-family signer.
func InitRSAVerifier(alg Algorithm, key *rsa.PublicKey) (*RSAVerifier, error) {
	if nil == key {
		return nil, errors.New("Cannot init RSAVerifier with empty key")
	}

	if "" == alg {
		return nil, errors.New("Cannot init RSAVerifier with no algorithm")
	}

	hashFunc, err := getHashAlgorithm(alg)
	if err != nil {
		return nil, err
	}

	return &RSAVerifier{
		algorithm: alg,
		hash:      hashFunc,
		pubKey:    key,
	}, nil
}

// Verify verifies a payload using the key the HMACSignerVerifier was initialized with
// against the provided ciphertext.
func (sv *RSAVerifier) Verify(plaintext []byte, signature []byte) (bool, error) {
	hash, err := GetHash(sv.algorithm, plaintext)
	if nil != err {
		return false, err
	}

	// Verification functions return an error on validation failure.
	switch sv.algorithm {
	case RS256, RS384, RS512:
		err = rsa.VerifyPKCS1v15(sv.pubKey, sv.hash, hash, signature)
	case PS256, PS384, PS512:
		err = rsa.VerifyPSS(sv.pubKey, sv.hash, hash, signature, nil)
	}

	if nil != err {
		return false, fmt.Errorf("Error from verification: %s", err)
	}

	return true, nil
}

// getHashAlgorithm returns the crypto hash algorithm suitable for the JWS type
func getHashAlgorithm(alg Algorithm) (crypto.Hash, error) {
	switch alg {
	case RS256, PS256:
		return crypto.SHA256, nil
	case RS384, PS384:
		return crypto.SHA384, nil
	case RS512, PS512:
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("No compatible hash function found for algorithm type %s", alg)
}
