package main

import "encoding/json"

type Header struct {
	// MUST be present
	Algorithm string `json:"alg"`

	JWKSetURL string `json:"jku,omitempty"`

	JWK string `json:"jwk,omitempty"`

	KeyID string `json:"kid,omitempty"`

	// X509URL string `json:"x5u"`

	// X509CertificateChain string `json:"x5c"`

	// X509CertificateThumbpring string `json:"x5t#S256"`

	Type string `json:"typ,omitempty"`

	ContentType string `json:"cty,omitempty"`

	// Critical string `json:"crit"`
}

func GetHeader(token *Token, outputType interface{}) error {
	return json.Unmarshal(token.DecodedHeader, outputType)
}
