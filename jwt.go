package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
)

type JOSESignerVerifieriface interface {
	GenerateToken(header interface{}, body interface{}) ([]byte, error)
	VerifySignature(token []byte) (bool, error)
	VerifyToken(token []byte) (bool, error)
}

type JOSESignerVerifier struct {
	algorithm Algorithm
	signer    TokenSigner
	verifier  TokenVerifier
}

//	NewJOSESignerVerifier creates a new JOSESignerVerifier, given a valid
//	symmetric or asymmetric key.
//	Symmetric algorithms (HS) will allow you to create and verify tokens
//	with the same key. A symmetric key must be kept secure.
//	Asymmetric algorithms (RS, PS, ED, ES) provide a public and private
//	key pair. If used with the private key, you will be able to create
//	and verify tokens. If used with the public key, you will be able to
//	verify tokens only.
//	The JOSE standard also sets aside the option of 'None' for unsigned
//	and unverifiable tokens. Since this is inherently insecure, a separate
//	constructor is provided - 'NewJOSESignerVerifierInsecure'
func NewJOSESignerVerifier(alg Algorithm, key interface{}) (*JOSESignerVerifier, error) {
	switch keyType := key.(type) {
	// RSA
	case *rsa.PrivateKey:
		rsaKey := key.(*rsa.PrivateKey)
		return newFromRSAPrivate(alg, rsaKey)
	case *rsa.PublicKey:
		rsaKey := key.(*rsa.PublicKey)
		return newFromRSAPublic(alg, rsaKey)
	// ECDSA
	case *ecdsa.PrivateKey:
		ecdsaKey := key.(*ecdsa.PrivateKey)
		return newFromECDSAPrivate(alg, ecdsaKey)
	case *ecdsa.PublicKey:
		ecdsaKey := key.(*ecdsa.PublicKey)
		return newFromECDSAPublic(alg, ecdsaKey)
	// EdDSA
	case *ed25519.PrivateKey:
		ed25519Key := key.(*ed25519.PrivateKey)
		return newFromEd25519Private(alg, ed25519Key)
	case *ed25519.PublicKey:
		ed25519Key := key.(*ed25519.PublicKey)
		return newFromEd25519Public(alg, ed25519Key)
	// HMAC
	case []byte:
		hmacKey := key.([]byte)
		return newFromHMACBytes(alg, hmacKey)
	// Unexpected type or unsupported key type
	default:
		return nil, fmt.Errorf("Cannot create JOSESignerVerifier from key type %T", keyType)
	}
}

// newFromEd25519Public configures a new JOSESignerVerifier from an Ed25519
// public key and algorithm.
func newFromEd25519Public(alg Algorithm, key *ed25519.PublicKey) (*JOSESignerVerifier, error) {
	v, err := InitEdDSAVerifier(alg, key)
	if nil != err {
		return nil, err
	}

	return &JOSESignerVerifier{
		algorithm: alg,
		verifier:  v,
	}, nil
}

// newFromEd25519Private configures a new JOSESignerVerifier from an Ed25519
// private key and algorithm.
func newFromEd25519Private(alg Algorithm, key *ed25519.PrivateKey) (*JOSESignerVerifier, error) {
	public := key.Public().(ed25519.PublicKey)
	sv, err := newFromEd25519Public(alg, &public)
	if nil != err {
		return nil, err
	}

	s, err := InitEdDSASigner(alg, key)
	if nil != err {
		return nil, err
	}

	sv.signer = s
	return sv, nil
}

// newFromECDSAPublic configures a new JOSESignerVerifier from an ECDSA
// public key and algorithm.
func newFromECDSAPublic(alg Algorithm, key *ecdsa.PublicKey) (*JOSESignerVerifier, error) {
	v, err := InitECDSAVerifier(alg, key)
	if nil != err {
		return nil, err
	}

	return &JOSESignerVerifier{
		algorithm: alg,
		verifier:  v,
	}, nil
}

// newFromECDSAPrivate configures a new JOSESignerVerifier from an ECDSA
// private key and algorithm.
func newFromECDSAPrivate(alg Algorithm, key *ecdsa.PrivateKey) (*JOSESignerVerifier, error) {
	sv, err := newFromECDSAPublic(alg, &key.PublicKey)
	if nil != err {
		return nil, err
	}

	s, err := InitECDSASigner(alg, key)
	if nil != err {
		return nil, err
	}

	sv.signer = s
	return sv, nil
}

// newFromRSAPrivate configures a new JOSESignerVerifier from a RSA
// public key and algorithm.
func newFromRSAPublic(alg Algorithm, key *rsa.PublicKey) (*JOSESignerVerifier, error) {
	v, err := InitRSAVerifier(alg, key)
	if nil != err {
		return nil, err
	}

	return &JOSESignerVerifier{
		algorithm: alg,
		verifier:  v,
	}, nil
}

// newFromRSAPrivate configures a new JOSESignerVerifier from a RSA
// private key and algorithm.
func newFromRSAPrivate(alg Algorithm, key *rsa.PrivateKey) (*JOSESignerVerifier, error) {
	sv, err := newFromRSAPublic(alg, &key.PublicKey)
	if nil != err {
		return nil, err
	}

	s, err := InitRSASigner(alg, key)
	if nil != err {
		return nil, err
	}

	sv.signer = s
	return sv, nil
}

// newFromHMACBytes configures a new HMAC-based JOSESignerVerifier from a byte array
// key and algorithm.
func newFromHMACBytes(alg Algorithm, key []byte) (*JOSESignerVerifier, error) {
	sv, err := InitHMACSignerVerifier(alg, key)
	if nil != err {
		return nil, err
	}

	// In a symmetric algorithm the key satisfies both signing and verification.
	return &JOSESignerVerifier{
		algorithm: alg,
		verifier:  sv,
		signer:    sv,
	}, nil
}

// NewInsecureJOSESignerVerifier returns a JOSESignerVerifier configured with the
// 'None' algorithm type. This is NOT RECOMMENDED but is nevertheless provided
// to conform with the JOSE specification.
func NewInsecureJOSESignerVerifier(alg Algorithm) (*JOSESignerVerifier, error) {
	if alg != None {
		return nil, errors.New(`cannot initialize an insecure JOSESignerVerifier without the algorithm 'None'.
If you want to use a key, use NewJOSESignerVerifier with the key and algorithm type`)
	}

	return &JOSESignerVerifier{
		algorithm: alg,
	}, nil
}

// GenerateToken generates a complete JWS token as a byte array from a JOSE
// header and JWS claim set body.
func (sv *JOSESignerVerifier) GenerateToken(header interface{}, body interface{}) ([]byte, error) {
	// Must be configured for token signing to be able to sign a token.
	if sv.verifier == nil {
		return nil, errors.New("JOSESignerVerifier not configured for signing - did you provide the correct key type?")
	}

	// Header and body must be json string-ified
	joseHeader, err := json.Marshal(header)
	if nil != err {
		return nil, err
	}

	jwsPayload, err := json.Marshal(body)
	if nil != err {
		return nil, err
	}

	// Header and body are appended together with a '.'
	headerAndClaims := appendWithDot(Base64URLEncode(joseHeader), Base64URLEncode(jwsPayload))

	log.Printf(string(headerAndClaims))

	// If the configured algorithm is 'None', we don't generate
	// or append a signature. This token is unsigned.
	if sv.algorithm == None {
		return headerAndClaims, nil
	}

	// Generate the signature of the header.body string
	jwSignature, err := sv.signer.Sign(headerAndClaims)
	if nil != err {
		return nil, err
	}

	return appendWithDot(headerAndClaims, Base64URLEncode(jwSignature)), nil
}

// VerifySignature verifies the signature on the token is valid. It does
// NO validation on header or claim values. This function is for internal
// use, but is made public for advanced use cases or when you have a need
// to use additional/custom validation logic against the header and claims.
//
// Header and claim validation is MANDATORY. Use the VerifyToken function
// to validate against any registered claims in addition to signature validation.
func (sv *JOSESignerVerifier) VerifySignature(rawToken []byte) (*Token, bool, error) {
	token, err := GetRawTokenParts(rawToken)
	if nil != err {
		return nil, false, err
	}

	// Base64url decode the JOSE header, validate the contents are well-formed.
	// Header validation should come after signature validation, since at this
	// stage we have not validated the authenticity of the token, so we can't
	// yet trust the contents of the header. The specification suggests simply
	// validating the header is well formed.
	var header Header
	err = GetHeader(token, &header)
	if nil != err {
		return nil, false, err
	}
	token.RegisteredHeader = header

	signatureValid, err := sv.verifier.Verify(
		appendWithDot(
			token.RawHeader,
			token.RawBody,
		),
		token.DecodedSignature,
	)
	token.signatureValid = signatureValid

	return token, signatureValid, err
}

// VerifyToken verifies the signature on the token is valid, and
// performs validation on any registered header or claim values.
func (sv *JOSESignerVerifier) VerifyToken(rawToken []byte, validationCriteria *ValidationClaims) (*Token, bool, error) {
	token, signatureValid, err := sv.VerifySignature(rawToken)
	if nil != err || !signatureValid {
		return nil, false, err
	}

	var claims Claims
	err = GetClaims(token, &claims)
	if nil != err {
		return token, false, err
	}
	token.RegisteredClaims = claims

	claimsValid, err := claims.ValidateRegisteredClaims(validationCriteria)

	return token, (signatureValid && claimsValid), err
}

// GetRawTokenParts splits and returns the raw token parts as a Token.
// The raw values are Base64URLDecoded.
func GetRawTokenParts(rawToken []byte) (*Token, error) {

	// Validate there is at least one period ('.') and not more than two periods ('.')
	parts := strings.Split(string(rawToken), ".")
	if len(parts) < 2 && len(parts) > 3 {
		return nil, errors.New("Valid tokens MUST have at least one '.' character and MUST NOT have at more than two '.' characters")
	}

	decodedHeader, err := Base64URLDecode(parts[0])
	if nil != err {
		return nil, err
	}

	decodedBody, err := Base64URLDecode(parts[1])
	if nil != err {
		return nil, err
	}

	token := &Token{
		RawToken:      rawToken,
		RawHeader:     []byte(parts[0]),
		DecodedHeader: decodedHeader,
		RawBody:       []byte(parts[1]),
		DecodedBody:   decodedBody,
	}

	if len(parts) == 3 {
		decodedSignature, err := Base64URLDecode(parts[2])
		if nil != err {
			return nil, err
		}

		token.RawSignature = []byte(parts[2])
		token.DecodedSignature = decodedSignature
	}

	return token, nil
}
