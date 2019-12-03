package main

// Token is a wrapper type for a JSON Web Signature token.
type Token struct {
	// JOSE token fields
	Alg              Algorithm
	RegisteredHeader Header
	RegisteredClaims Claims

	// Raw token information, Base64URL encoded source
	RawToken     []byte
	RawHeader    []byte
	RawBody      []byte
	RawSignature []byte

	// Raw token information, Base64URL decoded
	DecodedHeader    []byte
	DecodedBody      []byte
	DecodedSignature []byte

	// Internal validation flags
	signatureValid bool
	claimsValid    bool
}
