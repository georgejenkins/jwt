package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"reflect"
	"testing"
)

// Example values from https://tools.ietf.org/html/rfc7515#appendix-A.3
func getECDSA256PublicTestKey() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     getBigIntFromBase64URLString("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"),
		Y:     getBigIntFromBase64URLString("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"),
	}
}

func getECDSA256PrivateTestKey() *ecdsa.PrivateKey {
	return &ecdsa.PrivateKey{
		D:         getBigIntFromBase64URLString("jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"),
		PublicKey: *getECDSA256PublicTestKey(),
	}
}

// No example values are provided in RFC 7515 for ECDSA 384
func getECDSA384PublicTestKey() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: elliptic.P384(),
		X:     getBigIntFromBase64URLString("Hlxngt9Bg5l51yo_N8_jDXekjuhUQdael_Bg2-DvAqdWewoHXLUbyu3F5JkKi5D7"),
		Y:     getBigIntFromBase64URLString("68EjCg4UaFmFj7in4WhCv3nEBg91vAGHhytc2v5cvpKdrisO1Zqrbcuh48xFWvg1"),
	}
}

func getECDSA384PrivateTestKey() *ecdsa.PrivateKey {
	return &ecdsa.PrivateKey{
		D:         getBigIntFromBase64URLString("ljxgOVwV9ij1N6Sd9sekTAXn3NW7-MbU5KIaNWclLS9VyV73lGPfkk99SjCMPrRP"),
		PublicKey: *getECDSA384PublicTestKey(),
	}
}

// Example values from https://tools.ietf.org/html/rfc7515#appendix-A.4
func getECDSA512PublicTestKey() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: elliptic.P521(),
		X:     getBigIntFromBase64URLString("AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk"),
		Y:     getBigIntFromBase64URLString("ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2"),
	}
}

func getECDSA512PrivateTestKey() *ecdsa.PrivateKey {
	return &ecdsa.PrivateKey{
		D:         getBigIntFromBase64URLString("AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C"),
		PublicKey: *getECDSA512PublicTestKey(),
	}
}

func TestInitECDSASigner(t *testing.T) {
	type args struct {
		alg Algorithm
		key *ecdsa.PrivateKey
	}
	tests := []struct {
		name    string
		args    args
		want    *ECDSASigner
		wantErr bool
	}{
		{
			"Must initialize ECDSASigner given valid key and ES256",
			args{
				ES256,
				getECDSA256PrivateTestKey(),
			},
			&ECDSASigner{
				algorithm: ES256,
				prvKey:    getECDSA256PrivateTestKey(),
				rng:       rand.Reader,
			},
			false,
		},
		{
			"Must initialize ECDSASigner given valid key and ES384",
			args{
				ES384,
				getECDSA384PrivateTestKey(),
			},
			&ECDSASigner{
				algorithm: ES384,
				prvKey:    getECDSA384PrivateTestKey(),
				rng:       rand.Reader,
			},
			false,
		},
		{
			"Must initialize ECDSASigner given valid key and ES512",
			args{
				ES512,
				getECDSA512PrivateTestKey(),
			},
			&ECDSASigner{
				algorithm: ES512,
				prvKey:    getECDSA512PrivateTestKey(),
				rng:       rand.Reader,
			},
			false,
		},
		{
			"Must fail to initialize ECDSASigner given a nil key",
			args{
				ES256,
				nil,
			},
			nil,
			true,
		},
		{
			"Must fail to initialize ECDSASigner given an unexpected algorithm",
			args{
				RS256,
				getECDSA256PrivateTestKey(),
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := InitECDSASigner(tt.args.alg, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("InitECDSASigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("InitECDSASigner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInitECDSAVerifier(t *testing.T) {
	type args struct {
		alg Algorithm
		key *ecdsa.PublicKey
	}
	tests := []struct {
		name    string
		args    args
		want    *ECDSAVerifier
		wantErr bool
	}{
		{
			"Must initialize ECDSAVerifier given valid key and ES256",
			args{
				ES256,
				getECDSA256PublicTestKey(),
			},
			&ECDSAVerifier{
				algorithm: ES256,
				pubKey:    getECDSA256PublicTestKey(),
			},
			false,
		},
		{
			"Must initialize ECDSAVerifier given valid key and ES384",
			args{
				ES384,
				getECDSA256PublicTestKey(),
			},
			&ECDSAVerifier{
				algorithm: ES384,
				pubKey:    getECDSA256PublicTestKey(),
			},
			false,
		},
		{
			"Must initialize ECDSAVerifier given valid key and ES512",
			args{
				ES512,
				getECDSA256PublicTestKey(),
			},
			&ECDSAVerifier{
				algorithm: ES512,
				pubKey:    getECDSA256PublicTestKey(),
			},
			false,
		},
		{
			"Must fail to initialize ECDSAVerifier given a nil key",
			args{
				ES256,
				nil,
			},
			nil,
			true,
		},
		{
			"Must fail to initialize ECDSAVerifier given an unexpected algorithm",
			args{
				RS256,
				getECDSA256PublicTestKey(),
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := InitECDSAVerifier(tt.args.alg, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("InitECDSAVerifier() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("InitECDSAVerifier() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestECDSASigner_Sign ensures signatures are generated properly for
// the configured signer. ECDSA signatures are non-deterministic and will
// change on each generation.
func TestECDSASigner_Sign(t *testing.T) {
	type args struct {
		plaintext []byte
	}
	tests := []struct {
		name    string
		sv      *ECDSASigner
		args    args
		wantErr bool
	}{
		{
			"Must sign payload using ES256 successfully",
			&ECDSASigner{
				algorithm: ES256,
				prvKey:    getECDSA256PrivateTestKey(),
				rng:       rand.Reader,
			},
			args{
				plaintext: []byte("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"),
			},
			false,
		},
		{
			"Must sign payload using ES384 successfully",
			&ECDSASigner{
				algorithm: ES384,
				prvKey:    getECDSA256PrivateTestKey(),
				rng:       rand.Reader,
			},
			args{
				plaintext: []byte("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"),
			},
			false,
		},
		{
			"Must sign payload using ES512 successfully",
			&ECDSASigner{
				algorithm: ES512,
				prvKey:    getECDSA256PrivateTestKey(),
				rng:       rand.Reader,
			},
			args{
				plaintext: []byte("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.sv.Sign(tt.args.plaintext)
			if (err != nil) != tt.wantErr {
				t.Errorf("ECDSASigner.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestECDSAVerifier_Verify(t *testing.T) {
	type args struct {
		plaintext []byte
		signature []byte
	}
	tests := []struct {
		name    string
		sv      *ECDSAVerifier
		args    args
		want    bool
		wantErr bool
	}{
		// Test values from https://tools.ietf.org/html/rfc7515#appendix-A.3
		{
			"Must verify ES256 signature",
			&ECDSAVerifier{
				algorithm: ES256,
				pubKey:    getECDSA256PublicTestKey(),
			},
			args{
				plaintext: []byte("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"),
				signature: mustBase64URLDecode("DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"),
			},
			true,
			false,
		},
		// Test values from https://tools.ietf.org/html/rfc7515#appendix-A.4
		{
			"Must verify ES512 signature",
			&ECDSAVerifier{
				algorithm: ES512,
				pubKey:    getECDSA512PublicTestKey(),
			},
			args{
				plaintext: []byte("eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA"),
				signature: mustBase64URLDecode("AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"),
			},
			true,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.sv.Verify(tt.args.plaintext, tt.args.signature)
			if (err != nil) != tt.wantErr {
				t.Errorf("ECDSAVerifier.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ECDSAVerifier.Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestECDSASigner_ECDSAVerifier_EndToEnd runs an end-to-end test of
// generating the signature from the provided key, signing a
// payload, validating the signature and attempting to validate
// against an incorrect signature.
func TestECDSASigner_ECDSAVerifier_EndToEnd(t *testing.T) {
	type args struct {
		plaintext []byte
	}
	tests := []struct {
		name      string
		algorithm Algorithm
		curve     elliptic.Curve
		args      args
	}{
		{
			"Must sign and verify using ES256",
			ES256,
			elliptic.P256(),
			args{
				plaintext: plaintext,
			},
		},
		{
			"Must sign and verify using ES384",
			ES384,
			elliptic.P384(),
			args{
				plaintext: plaintext,
			},
		},
		{
			"Must sign and verify using ES512",
			ES512,
			elliptic.P521(),
			args{
				plaintext: plaintext,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if nil != err {
				t.Errorf("ECDSA End To End failed to generate key for %v: %v", tt.algorithm, err)
			}

			s, err := InitECDSASigner(tt.algorithm, key)
			if nil != err {
				t.Errorf("ECDSA End To End failed to InitECDSASigner for %v: %v", tt.algorithm, err)
			}

			v, err := InitECDSAVerifier(tt.algorithm, &key.PublicKey)
			if nil != err {
				t.Errorf("ECDSA End To End failed to InitECDSAVerifier key for %v: %v", tt.algorithm, err)
			}

			signature, err := s.Sign(tt.args.plaintext)
			if nil != err {
				t.Errorf("ECDSA End To End failed to generate signature for %v: %v", tt.algorithm, err)
			}

			passesVerification, err := v.Verify(tt.args.plaintext, signature)
			if nil != err {
				t.Errorf("Could validate signature for %v: %v", tt.algorithm, err)
			}
			if false == passesVerification {
				t.Errorf("ECDSA End To End failed to verify payload")
			}

			invalidPayloadPassesVerification, err := v.Verify(incorrectPlaintext, signature)
			if nil != err {
				t.Errorf("ECDSA End To End failed to verify payload: %v", err)
			}
			if true == invalidPayloadPassesVerification {
				t.Errorf("ECDSA End To End failed: %v", "Validation passed on an incorrect payload")
			}

		})
	}
}
