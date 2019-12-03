package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"
)

// Base64URLEncode encodes a byte array into a base64url string
// Adapted to Go from RFC 7515 JSON Web Signature (JWS)
// Appendix C. Notes on Implementing base64url Encoding without Padding
func Base64URLEncode(arg []byte) string {
	s := base64.StdEncoding.EncodeToString(arg)

	// Remove any trailing '='s
	s = strings.Split(s, "=")[0]
	// 62nd char of encoding
	s = strings.Replace(s, "+", "-", -1)
	// 63rd char of encoding
	s = strings.Replace(s, "/", "_", -1)

	return s
}

// Base64URLDecode decodes a base64url string into a byte array
// Adapted to Go from RFC 7515 JSON Web Signature (JWS)
// Appendix C. Notes on Implementing base64url Encoding without Padding
func Base64URLDecode(arg string) ([]byte, error) {

	arg = strings.Replace(arg, "-", "+", -1)
	arg = strings.Replace(arg, "_", "/", -1)

	// Pad with trailing '='s
	switch len(arg) % 4 {
	case 0:
		// No pad chars in this case
		break
	case 2:
		// Two pad chars
		arg += "=="
		break
	case 3:
		// One pad char
		arg += "="
		break
	default:
		return nil, errors.New("Illegal base64url string")
	}

	data, err := base64.StdEncoding.DecodeString(arg)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// GetHash returns the hash calculated from the plaintext, as required by the algorithm
func GetHash(algorithm Algorithm, plaintext []byte) ([]byte, error) {
	var hash hash.Hash

	switch algorithm {
	case RS256, PS256, ES256:
		hash = sha256.New()
	case RS384, PS384, ES384:
		hash = sha512.New384()
	case RS512, PS512, ES512, EdDSA:
		hash = sha512.New()
	}

	if nil == hash {
		return nil, fmt.Errorf("Cannot generate hash with the configured algorithm %s", algorithm)
	}

	hash.Write(plaintext)
	return hash.Sum(nil), nil
}

func appendWithDot(first interface{}, second interface{}) []byte {
	return []byte(
		fmt.Sprintf("%s.%s",
			stringOrBytesToBytes(first),
			stringOrBytesToBytes(second),
		),
	)
}

// stringOrBytesToBytes casts input into a byte array
func stringOrBytesToBytes(input interface{}) []byte {
	var bytes []byte

	bytes, ok := input.([]byte)
	if !ok {
		firstString := input.(string)
		bytes = []byte(firstString)
	}

	return bytes
}
