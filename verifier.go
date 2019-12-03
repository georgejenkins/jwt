package main

type TokenVerifier interface {
	Verify(plaintext []byte, hash []byte) (bool, error)
}
