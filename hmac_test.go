package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"reflect"
	"testing"
)

// Key and Payload from RFC 7515 - Example JWS Using HMAC SHA-256
// https://tools.ietf.org/html/rfc7515#appendix-A.1.1
var exampleKey = []byte{3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166, 143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80,
	46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119, 98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103, 208, 128, 163}

var examplePayload = []byte("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ")

// TestInitHMACSignerVerifier ensures the HMACSignerVerifier can be initialized
// properly and handles misconfigured input an initialization time.
func TestInitHMACSignerVerifier(t *testing.T) {
	type args struct {
		alg Algorithm
		key []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *HMACSignerVerifier
		wantErr bool
	}{
		{
			"Must initialize HMACSignerVerifier given valid key and HS256",
			args{
				HS256,
				exampleKey,
			},
			&HMACSignerVerifier{
				algorithm: HS256,
				key:       exampleKey,
			},
			false,
		},
		{
			"Must initialize HMACSignerVerifier given valid key and HS386",
			args{
				HS384,
				exampleKey,
			},
			&HMACSignerVerifier{
				algorithm: HS384,
				key:       exampleKey,
			},
			false,
		},
		{
			"Must initialize HMACSignerVerifier given valid key and HS512",
			args{
				HS512,
				exampleKey,
			},
			&HMACSignerVerifier{
				algorithm: HS512,
				key:       exampleKey,
			},
			false,
		},
		{
			"Must fail to initialize HMACSignerVerifier given empty valid key",
			args{
				HS512,
				nil,
			},
			nil,
			true,
		},
		{
			"Must fail to initialize HMACSignerVerifier given an unexpected algorithm",
			args{
				RS256,
				exampleKey,
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := InitHMACSignerVerifier(tt.args.alg, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("InitHMACSignerVerifier() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("InitHMACSignerVerifier() = %v, want %v", got, tt.want)
			}
		})
	}
}

//TestHMACSignerVerifier_initHash ensures the internal hash generator
// works to create the correct hash and throws on misconfiguration.
func TestHMACSignerVerifier_initHash(t *testing.T) {
	tests := []struct {
		name    string
		sv      *HMACSignerVerifier
		want    hash.Hash
		wantErr bool
	}{
		{
			"Must initialize hash with HS256",
			&HMACSignerVerifier{
				algorithm: HS256,
				key:       exampleKey,
			},
			hmac.New(sha256.New, exampleKey),
			false,
		},
		{
			"Must initialize hash with HS384",
			&HMACSignerVerifier{
				algorithm: HS384,
				key:       exampleKey,
			},
			hmac.New(sha512.New384, exampleKey),
			false,
		},
		{
			"Must initialize hash with HS512",
			&HMACSignerVerifier{
				algorithm: HS512,
				key:       exampleKey,
			},
			hmac.New(sha512.New, exampleKey),
			false,
		},
		{
			"Must fail to initialize hash with unknown algorithm",
			&HMACSignerVerifier{
				algorithm: RS256,
				key:       exampleKey,
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.sv.initHash()
			if (err != nil) != tt.wantErr {
				t.Errorf("HMACSignerVerifier.initHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HMACSignerVerifier.initHash() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestHMACSignerVerifier_Sign ensures signing of the payload
// results in the correct signed response.
func TestHMACSignerVerifier_Sign(t *testing.T) {
	type args struct {
		plaintext []byte
	}
	tests := []struct {
		name    string
		sv      *HMACSignerVerifier
		args    args
		want    []byte
		wantErr bool
	}{
		{
			// Test case from RFC 7515 - Example JWS Using HMAC SHA-256
			// https://tools.ietf.org/html/rfc7515#appendix-A.1.1
			"Must sign payload using HS256",
			&HMACSignerVerifier{
				algorithm: HS256,
				key:       exampleKey,
			},
			args{
				examplePayload,
			},
			[]byte{116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121},
			false,
		},
		{
			"Must sign payload using HS384",
			&HMACSignerVerifier{
				algorithm: HS384,
				key:       exampleKey,
			},
			args{
				examplePayload,
			},
			[]byte{107, 53, 87, 243, 237, 170, 252, 49, 29, 71, 156, 209, 185, 119, 6, 210, 165, 192, 185, 209, 179, 114, 22, 71, 153, 106, 62, 184, 163, 80, 139, 244, 185, 171, 217, 105, 26, 185, 71, 238, 25, 195, 200, 130, 132, 133, 153, 151},
			false,
		},
		{
			"Must sign payload using HS512",
			&HMACSignerVerifier{
				algorithm: HS512,
				key:       exampleKey,
			},
			args{
				examplePayload,
			},
			[]byte{48, 209, 193, 241, 95, 26, 7, 65, 100, 157, 241, 242, 20, 67, 73, 28, 153, 41, 138, 83, 164, 158, 226, 134, 52, 33, 249, 196, 151, 63, 155, 87, 148, 30, 214, 51, 139, 76, 205, 141, 42, 155, 67, 146, 10, 244, 22, 16, 111, 223, 221, 200, 140, 240, 179, 134, 99, 183, 112, 28, 178, 226, 153, 2},
			false,
		},
		{
			"Must throw on signing an empty payload",
			&HMACSignerVerifier{
				algorithm: HS512,
				key:       exampleKey,
			},
			args{
				[]byte(""),
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.sv.Sign(tt.args.plaintext)
			if (err != nil) != tt.wantErr {
				t.Errorf("HMACSignerVerifier.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HMACSignerVerifier.Sign() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestHMACSignerVerifier_Verify ensures verification of an HMAC signature
// retuns the correct result.
func TestHMACSignerVerifier_Verify(t *testing.T) {
	type args struct {
		plaintext []byte
		signature []byte
	}
	tests := []struct {
		name    string
		sv      *HMACSignerVerifier
		args    args
		want    bool
		wantErr bool
	}{
		{
			"Must validate HS256 signature",
			&HMACSignerVerifier{
				algorithm: HS256,
				key:       exampleKey,
			},
			args{
				examplePayload,
				[]byte{116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121},
			},
			true,
			false,
		},
		{
			"Must validate HS384 signature",
			&HMACSignerVerifier{
				algorithm: HS384,
				key:       exampleKey,
			},
			args{
				examplePayload,
				[]byte{107, 53, 87, 243, 237, 170, 252, 49, 29, 71, 156, 209, 185, 119, 6, 210, 165, 192, 185, 209, 179, 114, 22, 71, 153, 106, 62, 184, 163, 80, 139, 244, 185, 171, 217, 105, 26, 185, 71, 238, 25, 195, 200, 130, 132, 133, 153, 151},
			},
			true,
			false,
		},
		{
			"Must validate HS512 signature",
			&HMACSignerVerifier{
				algorithm: HS512,
				key:       exampleKey,
			},
			args{
				examplePayload,
				[]byte{48, 209, 193, 241, 95, 26, 7, 65, 100, 157, 241, 242, 20, 67, 73, 28, 153, 41, 138, 83, 164, 158, 226, 134, 52, 33, 249, 196, 151, 63, 155, 87, 148, 30, 214, 51, 139, 76, 205, 141, 42, 155, 67, 146, 10, 244, 22, 16, 111, 223, 221, 200, 140, 240, 179, 134, 99, 183, 112, 28, 178, 226, 153, 2},
			},
			true,
			false,
		},
		{
			"Must validate fail to validate incorrect HS256 signature",
			&HMACSignerVerifier{
				algorithm: HS256,
				key:       exampleKey,
			},
			args{
				examplePayload,
				[]byte{116, 24, 223, 180, 151, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121},
			},
			false,
			false,
		},
		{
			"Must validate fail to validate incorrect  HS384 signature",
			&HMACSignerVerifier{
				algorithm: HS384,
				key:       exampleKey,
			},
			args{
				examplePayload,
				[]byte{107, 53, 87, 243, 237, 170, 252, 49, 29, 71, 156, 209, 185, 119, 6, 210, 165, 192, 185, 209, 179, 114, 22, 71, 153, 106, 62, 184, 163, 80, 244, 185, 171, 217, 105, 26, 185, 71, 238, 25, 195, 200, 130, 132, 133, 153, 151},
			},
			false,
			false,
		},
		{
			"Must validate fail to validate incorrect  HS512 signature",
			&HMACSignerVerifier{
				algorithm: HS512,
				key:       exampleKey,
			},
			args{
				examplePayload,
				[]byte{48, 209, 193, 241, 95, 26, 7, 65, 100, 157, 242, 20, 67, 73, 28, 153, 41, 138, 83, 164, 158, 226, 134, 52, 33, 249, 196, 151, 63, 155, 87, 148, 30, 214, 51, 139, 76, 205, 141, 42, 155, 67, 146, 10, 244, 22, 16, 111, 223, 221, 200, 140, 240, 179, 134, 99, 183, 112, 28, 178, 226, 153, 2},
			},
			false,
			false,
		},
		{
			"Must validate fail to validate empty plaintext",
			&HMACSignerVerifier{
				algorithm: HS256,
				key:       exampleKey,
			},
			args{
				[]byte{},
				[]byte{},
			},
			false,
			true,
		},
		{
			"Must validate fail to validate empty signature",
			&HMACSignerVerifier{
				algorithm: HS256,
				key:       exampleKey,
			},
			args{
				examplePayload,
				[]byte{},
			},
			false,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.sv.Verify(tt.args.plaintext, tt.args.signature)
			if (err != nil) != tt.wantErr {
				t.Errorf("HMACSignerVerifier.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("HMACSignerVerifier.Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestHMACSignerVerifier_EndToEnd runs an end-to-end test of
// generating the signature from a generated key, signing a
// payload, validating the signature and attempting to validate
// against an incorrect signature.
func TestHMACSignerVerifier_EndToEnd(t *testing.T) {
	testKeyBytes := []byte("Reasons of State")
	testPayload := plaintext

	// Initialize the signer/verifier with a test key
	sv, err := InitHMACSignerVerifier(HS256, testKeyBytes)
	if nil != err {
		t.Errorf("HMACSignerVerifier End To End failed to initialize: %v", err)
	}

	// Sign the example payload
	signedPayload, err := sv.Sign(testPayload)
	if nil != err {
		t.Errorf("HMACSignerVerifier End To End failed to sign payload: %v", err)
	}

	// Validate the payload against the configured key
	passesVerification, err := sv.Verify(testPayload, signedPayload)
	if nil != err {
		t.Errorf("HMACSignerVerifier End To End failed to verify payload: %v", err)
	}
	if false == passesVerification {
		t.Errorf("HMACSignerVerifier End To End failed: %v", "Validation failed without error")
	}

	// Attempt to validate against an invalid signature
	invalidPayloadPassesVerification, err := sv.Verify(incorrectPlaintext, signedPayload)
	if nil != err {
		t.Errorf("HMACSignerVerifier End To End failed to verify payload: %v", err)
	}
	if true == invalidPayloadPassesVerification {
		t.Errorf("HMACSignerVerifier End To End failed: %v", "Validation passed on an incorrect payload")
	}
}
