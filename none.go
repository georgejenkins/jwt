package main

import (
	"fmt"
)

// NoneSignerVerifier provides support for the 'None' alg type.
// NoneSignerVerifier really does nothing, but due to the insecure
// nature of this 'algorithm', there is a benefit in being explicit.
type NoneSignerVerifier struct {
	algorithm Algorithm
	key       []byte
}

// InitNoneSignerVerifier initializes a new 'None' signer/verifier.
func InitNoneSignerVerifier(alg Algorithm) (*NoneSignerVerifier, error) {
	if None != alg {
		return nil, fmt.Errorf("Expected alg to be None but received %v", alg)
	}
	return &NoneSignerVerifier{}, nil
}

// Sign provides fall-though signing. Nothing is signed.
func (sv *NoneSignerVerifier) Sign(plaintext []byte) ([]byte, error) {
	return nil, nil
}

// Verify provides fall-though verification. Nothing is verified.
// All invocations of this will result in a verification successful
// response, be sure you know what you are doing when using this!
func (sv *NoneSignerVerifier) Verify(plaintext []byte, signature []byte) (bool, error) {
	return true, nil
}
