package main

// Algorithm represents the algorithm used to sign the JWT.
type Algorithm string

// "alg" (Algorithm) Header Parameter Values for JWS
const (
	// HS256 HMAC using SHA-256             					Required
	HS256 Algorithm = "HS256"
	// HS384 HMAC using SHA-384             					Optional
	HS384 Algorithm = "HS384"
	// HS512 HMAC using SHA-512             					Optional
	HS512 Algorithm = "HS512"
	// RS256 RSASSA-PKCS1-v1_5 using SHA-256       				Recommended
	RS256 Algorithm = "RS256"
	// RS384 RSASSA-PKCS1-v1_5 using SHA-384 		    		Optional
	RS384 Algorithm = "RS384"
	// RS512 RSASSA-PKCS1-v1_5 using SHA-512	       			Optional
	RS512 Algorithm = "RS512"
	// ES256 ECDSA using P-256 and SHA-256  					Recommended+
	ES256 Algorithm = "ES256"
	// ES384 ECDSA using P-384 and SHA-384  					Optional
	ES384 Algorithm = "ES384"
	// ES512 ECDSA using P-521 and SHA-512  					Optional
	ES512 Algorithm = "ES512"
	// PS256 RSASSA-PSS using SHA-256 and MGF1 with SHA-256  	Optional
	PS256 Algorithm = "PS256"
	// PS384 RSASSA-PSS using SHA-384 and MGF1 with SHA-384  	Optional
	PS384 Algorithm = "PS384"
	// PS512 RSASSA-PSS using SHA-512 and MGF1 with SHA-512  	Optional
	PS512 Algorithm = "PS512"

	// EdDSA as per https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-03
	EdDSA Algorithm = "EdDSA"

	// none no digital signature or MAC performed   			Optional
	None Algorithm = "none"
)
