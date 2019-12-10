package main

import (
	"encoding/hex"
	"math/big"
)

// mustBase64URLDecode is Base64URLDecode that ignores errors.
// Used for converting base64url strings from various RFCs
// to byte slices for use in testing.
//
// Internal testing utility, use for testing only!
func mustBase64URLDecode(arg string) []byte {
	data, _ := Base64URLDecode(arg)
	return data
}

// mustBase64URLDecode is xex decoder that ignores errors.
// Used for converting hex strings from various RFCs
// to byte slices for use in testing.
//
// Internal testing utility, use for testing only!
func mustHexDecode(arg string) []byte {
	data, _ := hex.DecodeString(arg)
	return data
}

// getBigIntFromBase64URLString is a helper that returns a
// big int from a byte array, useful for converting big
// numbers encoded as base64URL strings, used for testing.
//
// Internal testing utility, use for testing only!
func getBigIntFromBase64URLString(input string) *big.Int {
	return new(big.Int).SetBytes(mustBase64URLDecode(input))
}
