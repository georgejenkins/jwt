package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// ECDSASigner contains configuration for signing JWSs using the
// ECDSA 256/384/512 family.
type ECDSASigner struct {
	algorithm Algorithm
	prvKey    *ecdsa.PrivateKey
	rng       io.Reader
}

// getExpectedKeyParameters returns the key parameters needed to validate
// against user key input when initializing the signer/verifier.
func getExpectedKeyParameters(alg Algorithm) (int, elliptic.Curve, error) {
	switch alg {
	case ES256:
		return 32, elliptic.P256(), nil
	case ES384:
		return 48, elliptic.P384(), nil
	case ES512:
		return 66, elliptic.P521(), nil
	}

	return 0, nil, fmt.Errorf(
		"Could not determine parameters for algorithm %v; Expected alg to be one of: ES256, ES384, ES512",
		alg,
	)
}

// validateKeyMatchesAlgorithm validates the key provided matches
// the parameters of the algorithm it is to be used with.
func validateKeyMatchesAlgorithm(alg Algorithm, key *ecdsa.PrivateKey) error {
	expectedBitSize, expectedCurve, err := getExpectedKeyParameters(alg)
	if nil != err {
		return err
	}

	if key.Params().Name != expectedCurve.Params().Name { //key.Params().BitSize != expectedBitSize || - need to do some math on the bit size to make sure it matches the curve
		return fmt.Errorf(
			"Key does not match expected parameters for algorithm %v; Expected bitsize %v, curve %v, received %v %v",
			alg,
			expectedBitSize,
			key.Params().BitSize,
			expectedCurve.Params().Name,
			key.Params().Name,
		)
	}

	// Key validated against expected parameters, no error returned.
	return nil
}

// InitECDSASigner initializes a new ECDSA family signer.
func InitECDSASigner(alg Algorithm, key *ecdsa.PrivateKey) (*ECDSASigner, error) {
	if nil == key {
		return nil, errors.New("Cannot init ECDSASigner with empty key")
	}

	if "" == alg {
		return nil, errors.New("Cannot init ECDSASigner with no algorithm")
	}

	keyValidationErr := validateKeyMatchesAlgorithm(alg, key)
	if nil != keyValidationErr {
		return nil, keyValidationErr
	}

	return &ECDSASigner{
		algorithm: alg,
		prvKey:    key,
		rng:       rand.Reader,
	}, nil
}

// Sign signs a payload using the key the ECDSASigner was initialized with.
func (sv *ECDSASigner) Sign(plaintext []byte) ([]byte, error) {
	hash, err := GetHash(sv.algorithm, plaintext)
	if nil != err {
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, sv.prvKey, hash)
	if nil != err {
		return nil, err
	}

	return sv.padAndJoin(r, s), nil
}

// getSignatureLength returns the length of the expected
// r/s signature portions, useful for padding and splitting
func getSignatureLength(curve elliptic.Curve) int {
	keySize := curve.Params().BitSize

	// (256 / 8) mod 8 == 0
	// (384 / 8) mod 8 == 0
	// (521 / 8) mod 8 == 0 > 0, adjust to bump the non-base 2 prime field case of ES521 from x < 65 -> x == 66
	adjustedSize := keySize / 8
	if adjustedSize%8 > 0 {
		adjustedSize++
	}
	return adjustedSize
}

// padAndJoin pads the r & s values out to the expected
// length based on the configured signing key.
// https://stackoverflow.com/questions/50002149/why-p-521-public-key-x-y-some-time-is-65-bytes-some-time-is-66-bytes
func (sv *ECDSASigner) padAndJoin(r *big.Int, s *big.Int) []byte {
	// keySize := getSignatureLength(sv.prvKey.Curve)

	keySize := getSignatureLength(sv.prvKey.Curve)

	rBytesPadded := make([]byte, keySize)
	copy(rBytesPadded[keySize-len(r.Bytes()):], r.Bytes())

	sBytesPadded := make([]byte, keySize)
	copy(sBytesPadded[keySize-len(s.Bytes()):], s.Bytes())

	return append(rBytesPadded, sBytesPadded...)
}

// ECDSAVerifier contains configuration for verifying JWSs using the ECDSA 256/384/512 family.
type ECDSAVerifier struct {
	algorithm Algorithm
	pubKey    *ecdsa.PublicKey
}

// InitECDSAVerifier initializes a new ECDSA family signer.
func InitECDSAVerifier(alg Algorithm, key *ecdsa.PublicKey) (*ECDSAVerifier, error) {
	if nil == key {
		return nil, errors.New("Cannot init ECDSAVerifier with empty key")
	}

	if "" == alg {
		return nil, errors.New("Cannot init ECDSAVerifier with no algorithm")
	}

	if ES256 != alg && ES384 != alg && ES512 != alg {
		return nil, errors.New("Signing algorithm unexpected, must be one of: ES256, ES384, ES512")
	}

	return &ECDSAVerifier{
		algorithm: alg,
		pubKey:    key,
	}, nil
}

// Verify verifies a payload using the key the ECDSAVerifier was initialized with
// against the provided ciphertext.
func (sv *ECDSAVerifier) Verify(plaintext []byte, signature []byte) (bool, error) {
	hash, err := GetHash(sv.algorithm, plaintext)
	if nil != err {
		return false, err
	}

	rsSplitLen := getSignatureLength(sv.pubKey.Curve)

	// conjecture - do we need to validate the signature length of
	// the signature, since we know the r/s split length that
	// determines the length of the total signature?
	if len(signature) != (rsSplitLen * 2) {
		return false, fmt.Errorf("Signature length invalid: expected %v, received %v", rsSplitLen*2, len(signature))
	}

	return ecdsa.Verify(
		sv.pubKey,
		hash,
		new(big.Int).SetBytes(signature[:rsSplitLen]),
		new(big.Int).SetBytes(signature[rsSplitLen:]),
	), nil
}
