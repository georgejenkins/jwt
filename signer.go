package main

type TokenSigner interface {
	Sign(plaintext []byte) ([]byte, error)
}
