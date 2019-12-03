package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"reflect"
	"testing"
)

func getRSAPublicTestKey() *rsa.PublicKey {
	return &rsa.PublicKey{
		N: getBigIntFromBase64URLString("ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"),
		E: 65537,
	}
}

func getRSAPrivateTestKey() *rsa.PrivateKey {
	return &rsa.PrivateKey{
		PublicKey: *getRSAPublicTestKey(),
		D:         getBigIntFromBase64URLString("Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"),
		Primes: []*big.Int{
			getBigIntFromBase64URLString("4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"),
			getBigIntFromBase64URLString("uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"),
		},
	}
}

func TestInitRSASigner(t *testing.T) {
	testKey2048, _ := rsa.GenerateKey(rand.Reader, 2048)

	type args struct {
		alg Algorithm
		key *rsa.PrivateKey
	}
	tests := []struct {
		name    string
		args    args
		want    *RSASigner
		wantErr bool
	}{
		{
			"Must initialize RSASigner with valid RSA key + RS256",
			args{
				RS256,
				testKey2048,
			},
			&RSASigner{
				algorithm: RS256,
				hash:      crypto.SHA256,
				prvKey:    testKey2048,
				rng:       rand.Reader,
			},
			false,
		},
		{
			"Must initialize RSASigner with valid RSA key + RS384",
			args{
				RS384,
				testKey2048,
			},
			&RSASigner{
				algorithm: RS384,
				hash:      crypto.SHA384,
				prvKey:    testKey2048,
				rng:       rand.Reader,
			},
			false,
		},
		{
			"Must initialize RSASigner with valid RSA key + RS512",
			args{
				RS512,
				testKey2048,
			},
			&RSASigner{
				algorithm: RS512,
				hash:      crypto.SHA512,
				prvKey:    testKey2048,
				rng:       rand.Reader,
			},
			false,
		},
		{
			"Must initialize RSASigner with valid RSA key + PS256",
			args{
				PS256,
				testKey2048,
			},
			&RSASigner{
				algorithm: PS256,
				hash:      crypto.SHA256,
				prvKey:    testKey2048,
				rng:       rand.Reader,
			},
			false,
		},
		{
			"Must initialize RSASigner with valid RSA key + PS384",
			args{
				PS384,
				testKey2048,
			},
			&RSASigner{
				algorithm: PS384,
				hash:      crypto.SHA384,
				prvKey:    testKey2048,
				rng:       rand.Reader,
			},
			false,
		},
		{
			"Must initialize RSASigner with valid RSA key + PS512",
			args{
				PS512,
				testKey2048,
			},
			&RSASigner{
				algorithm: PS512,
				hash:      crypto.SHA512,
				prvKey:    testKey2048,
				rng:       rand.Reader,
			},
			false,
		},
		{
			"Must fail to initialize RSASigner with nil RSA key",
			args{
				RS256,
				nil,
			},
			nil,
			true,
		},
		{
			"Must fail to initialize RSASigner with unexpected algorithm",
			args{
				HS256,
				nil,
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := InitRSASigner(tt.args.alg, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("InitRSASigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("InitRSASigner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRSASigner_Sign(t *testing.T) {
	type args struct {
		plaintext []byte
	}
	tests := []struct {
		name    string
		sv      *RSASigner
		args    args
		want    []byte
		wantErr bool
	}{
		{
			"Must sign payload successfully with RS256",
			&RSASigner{
				algorithm: RS256,
				hash:      crypto.SHA256,
				prvKey:    getRSAPrivateTestKey(),
				rng:       rand.Reader,
			},
			args{
				plaintext: []byte("eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"),
			},
			mustBase64URLDecode("cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"),
			false,
		},
		{
			"Must sign payload successfully with RS384",
			&RSASigner{
				algorithm: RS384,
				hash:      crypto.SHA384,
				prvKey:    getRSAPrivateTestKey(),
				rng:       rand.Reader,
			},
			args{
				plaintext: []byte("eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"),
			},
			mustBase64URLDecode("QMlqnIk4Jg6V4BsZGDb3PTKORZPw-eoUq-FsnjYifl08H95otuD2EHkUuDdfTGjEcJ6tgIehmwfchztWsgwuobaeMbRS44doIjGi4FaIHX4XlKcIlUxSnJPQ2O8bWZF6vkvQaPBXjzwLDGKUTkJwwP052sCL-ivRWakkNETy66m2ODQjg4mN6EJI2o6_hRsklNEHPHjrTdOWnugAcEJ44e_fZ3cCFlP9009ITkx9ZgiVR8ViI-KBgCY90JDhxneWKNzWidZaTg6TcEUQo73V1H4WSbzUVa7aLTFVc5OTSX-kO6GNrlCSKHx-M_yPDowT9ovfNX_UXJzxxMWWwGaYCA"),
			false,
		},
		{
			"Must sign payload successfully with RS512",
			&RSASigner{
				algorithm: RS512,
				hash:      crypto.SHA512,
				prvKey:    getRSAPrivateTestKey(),
				rng:       rand.Reader,
			},
			args{
				plaintext: []byte("eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"),
			},
			mustBase64URLDecode("jVVNFquIjYtsXWDHTCFaq0UoNhuL2qq0KNQ3hx6V-dfxtc2obZ81vcL-mpmCxsnW5VzZtAuEM__uUpFTtoP65kGyVR8ebwUMhr_ra0JzpO4fS1SrHTu-f-GqPoN9LYXM_7pmT2dYbGw2-AqbLTutv-lBG04TQHbgJ3ISx14bjdACIRh8DGtQwvHQBpV_S-KM_yweOiqt5ff5GckMaaGqSuDTlVupVE46NfXiE3tjf3PnnztWuOJ-lNNtQ0ojc-jGX7DpreVDWFkh4WpnC_dPVlhTpq8F-mKSsOEBc4B7-J_bnR80VNx2sCEq3GH49TRs2js-J0VIef8hX7H-3aQt4g"),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.sv.Sign(tt.args.plaintext)
			if (err != nil) != tt.wantErr {
				t.Errorf("RSASigner.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RSASigner.Sign() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInitRSAVerifier(t *testing.T) {
	type args struct {
		alg Algorithm
		key *rsa.PublicKey
	}
	tests := []struct {
		name    string
		args    args
		want    *RSAVerifier
		wantErr bool
	}{
		{
			"Must initialize RSAVerifier with valid RSA public key + RS256",
			args{
				RS256,
				getRSAPublicTestKey(),
			},
			&RSAVerifier{
				algorithm: RS256,
				hash:      crypto.SHA256,
				pubKey:    getRSAPublicTestKey(),
			},
			false,
		},
		{
			"Must initialize RSAVerifier with valid RSA public key + RS384",
			args{
				RS384,
				getRSAPublicTestKey(),
			},
			&RSAVerifier{
				algorithm: RS384,
				hash:      crypto.SHA384,
				pubKey:    getRSAPublicTestKey(),
			},
			false,
		},
		{
			"Must initialize RSAVerifier with valid RSA public key + RS512",
			args{
				RS512,
				getRSAPublicTestKey(),
			},
			&RSAVerifier{
				algorithm: RS512,
				hash:      crypto.SHA512,
				pubKey:    getRSAPublicTestKey(),
			},
			false,
		},
		{
			"Must initialize RSAVerifier with valid RSA public key + PS256",
			args{
				PS256,
				getRSAPublicTestKey(),
			},
			&RSAVerifier{
				algorithm: PS256,
				hash:      crypto.SHA256,
				pubKey:    getRSAPublicTestKey(),
			},
			false,
		},
		{
			"Must initialize RSAVerifier with valid RSA public key + PS384",
			args{
				PS384,
				getRSAPublicTestKey(),
			},
			&RSAVerifier{
				algorithm: PS384,
				hash:      crypto.SHA384,
				pubKey:    getRSAPublicTestKey(),
			},
			false,
		},
		{
			"Must initialize RSAVerifier with valid RSA public key + PS512",
			args{
				PS512,
				getRSAPublicTestKey(),
			},
			&RSAVerifier{
				algorithm: PS512,
				hash:      crypto.SHA512,
				pubKey:    getRSAPublicTestKey(),
			},
			false,
		},
		{
			"Must fail to initialize RSAVerifier with nil RSA public key",
			args{
				RS256,
				nil,
			},
			nil,
			true,
		},
		{
			"Must fail to initialize RSAVerifier with unexpected algorithm",
			args{
				HS256,
				nil,
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := InitRSAVerifier(tt.args.alg, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("InitRSAVerifier() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("InitRSAVerifier() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRSAVerifier_Verify(t *testing.T) {
	type args struct {
		plaintext []byte
		signature []byte
	}
	tests := []struct {
		name    string
		sv      *RSAVerifier
		args    args
		want    bool
		wantErr bool
	}{
		{
			"Must verify RS256 payload successfully",
			&RSAVerifier{
				algorithm: RS256,
				hash:      crypto.SHA256,
				pubKey:    getRSAPublicTestKey(),
			},
			args{
				plaintext: []byte("eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"),
				signature: mustBase64URLDecode("cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"),
			},
			true,
			false,
		},
		{
			"Must verify RS384 payload successfully",
			&RSAVerifier{
				algorithm: RS384,
				hash:      crypto.SHA384,
				pubKey:    getRSAPublicTestKey(),
			},
			args{
				plaintext: []byte("eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"),
				signature: mustBase64URLDecode("QMlqnIk4Jg6V4BsZGDb3PTKORZPw-eoUq-FsnjYifl08H95otuD2EHkUuDdfTGjEcJ6tgIehmwfchztWsgwuobaeMbRS44doIjGi4FaIHX4XlKcIlUxSnJPQ2O8bWZF6vkvQaPBXjzwLDGKUTkJwwP052sCL-ivRWakkNETy66m2ODQjg4mN6EJI2o6_hRsklNEHPHjrTdOWnugAcEJ44e_fZ3cCFlP9009ITkx9ZgiVR8ViI-KBgCY90JDhxneWKNzWidZaTg6TcEUQo73V1H4WSbzUVa7aLTFVc5OTSX-kO6GNrlCSKHx-M_yPDowT9ovfNX_UXJzxxMWWwGaYCA"),
			},
			true,
			false,
		},
		{
			"Must verify RS512 payload successfully",
			&RSAVerifier{
				algorithm: RS512,
				hash:      crypto.SHA512,
				pubKey:    getRSAPublicTestKey(),
			},
			args{
				plaintext: []byte("eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"),
				signature: mustBase64URLDecode("jVVNFquIjYtsXWDHTCFaq0UoNhuL2qq0KNQ3hx6V-dfxtc2obZ81vcL-mpmCxsnW5VzZtAuEM__uUpFTtoP65kGyVR8ebwUMhr_ra0JzpO4fS1SrHTu-f-GqPoN9LYXM_7pmT2dYbGw2-AqbLTutv-lBG04TQHbgJ3ISx14bjdACIRh8DGtQwvHQBpV_S-KM_yweOiqt5ff5GckMaaGqSuDTlVupVE46NfXiE3tjf3PnnztWuOJ-lNNtQ0ojc-jGX7DpreVDWFkh4WpnC_dPVlhTpq8F-mKSsOEBc4B7-J_bnR80VNx2sCEq3GH49TRs2js-J0VIef8hX7H-3aQt4g"),
			},
			true,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.sv.Verify(tt.args.plaintext, tt.args.signature)
			if (err != nil) != tt.wantErr {
				t.Errorf("RSAVerifier.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("RSAVerifier.Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRSASigner_RSAVerifier_EndToEnd runs an end-to-end test of
// generating the signature from a generated key, signing a
// payload, validating the signature and attempting to validate
// against an incorrect signature.
func TestRSASigner_RSAVerifier_EndToEnd(t *testing.T) {
	type args struct {
		plaintext []byte
	}
	tests := []struct {
		name      string
		algorithm Algorithm
		args      args
	}{
		{
			"Must sign and verify using RS256",
			RS256,
			args{
				plaintext: plaintext,
			},
		},
		{
			"Must sign and verify using RS384",
			RS384,
			args{
				plaintext: plaintext,
			},
		},
		{
			"Must sign and verify using RS512",
			RS512,
			args{
				plaintext: plaintext,
			},
		},
		{
			"Must sign and verify using PS256",
			PS256,
			args{
				plaintext: plaintext,
			},
		},
		{
			"Must sign and verify using PS384",
			PS384,
			args{
				plaintext: plaintext,
			},
		},
		{
			"Must sign and verify using PS512",
			PS512,
			args{
				plaintext: plaintext,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if nil != err {
				t.Errorf("RSA End To End failed to generate key for %v: %v", tt.algorithm, err)
			}

			s, err := InitRSASigner(tt.algorithm, key)
			if nil != err {
				t.Errorf("RSA End To End failed to InitRSASigner for %v: %v", tt.algorithm, err)
			}

			v, err := InitRSAVerifier(tt.algorithm, &key.PublicKey)
			if nil != err {
				t.Errorf("RSA End To End failed to InitRSAVerifier key for %v: %v", tt.algorithm, err)
			}

			signature, err := s.Sign(tt.args.plaintext)
			if nil != err {
				t.Errorf("RSA End To End failed to generate signature for %v: %v", tt.algorithm, err)
			}

			passesVerification, err := v.Verify(tt.args.plaintext, signature)
			if nil != err {
				t.Errorf("Could validate signature for %v: %v", tt.algorithm, err)
			}
			if false == passesVerification {
				t.Errorf("RSA End To End failed to verify payload using %v", tt.algorithm)
			}

			invalidPayloadPassesVerification, err := v.Verify(incorrectPlaintext, signature)
			if nil == err {
				t.Errorf("RSA End To End failed to throw for invalid signature using %v", tt.algorithm)
			}
			if true == invalidPayloadPassesVerification {
				t.Errorf("RSA End To End failed: %v", "Validation passed on an incorrect payload")
			}

		})
	}
}
