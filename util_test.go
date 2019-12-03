package main

import (
	"reflect"
	"testing"
)

func TestBase64URLEncode(t *testing.T) {
	type args struct {
		arg []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			"Base64URLEncode encodes correctly",
			args{
				arg: plaintext,
			},
			"VGhlIEJsdWUgU3RyaXBlcyB3aWxsIGFtYnVzaCBSYWRvdmlkIG9uIHRoZSBicmlkZ2UgdG8gVGVtcGxlIElzbGU",
		},
		{
			"Base64URLEncode handles nil content",
			args{
				arg: []byte{},
			},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Base64URLEncode(tt.args.arg); got != tt.want {
				t.Errorf("Base64URLEncode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBase64URLDecode(t *testing.T) {
	type args struct {
		arg string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			"Base64URLDecode decodes correctly",
			args{
				arg: "VGhlIEJsdWUgU3RyaXBlcyB3aWxsIGFtYnVzaCBSYWRvdmlkIG9uIHRoZSBicmlkZ2UgdG8gVGVtcGxlIElzbGU",
			},
			[]byte(plaintext),
			false,
		},
		{
			"Base64URLDecode throws on invalid content",
			args{
				arg: "*VGhlIEJsdWUgU3RyaXBlcyB3aWxsIGFtYnVzaCBSYWRvdmlkIG9uIHRoZSBicmlkZ2UgdG8gVGVtcGxlIElzbGU",
			},
			nil,
			true,
		},
		{
			"Base64URLDecode handles nil content",
			args{
				arg: "",
			},
			[]byte{},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Base64URLDecode(tt.args.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("Base64URLDecode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Base64URLDecode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetHash(t *testing.T) {
	type args struct {
		algorithms []Algorithm
		plaintext  []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			"GetHash hashes correctly for *256 families",
			args{
				[]Algorithm{
					RS256,
					PS256,
					ES256,
				},
				plaintext,
			},
			[]byte{186, 238, 177, 124, 3, 218, 20, 110, 115, 254, 90, 51, 192, 50, 42, 50, 165, 76, 19, 95, 30, 64, 19, 231, 191, 219, 89, 255, 211, 209, 193, 52},
			false,
		},
		{
			"GetHash hashes correctly for *384 families",
			args{
				[]Algorithm{
					RS384,
					PS384,
					ES384,
				},
				plaintext,
			},
			[]byte{215, 140, 234, 127, 224, 35, 115, 207, 154, 74, 252, 242, 135, 11, 87, 78, 13, 126, 66, 49, 148, 37, 27, 212, 191, 84, 22, 122, 83, 73, 190, 247, 149, 89, 38, 113, 190, 64, 66, 249, 127, 106, 181, 104, 27, 213, 237, 101},
			false,
		},
		{
			"GetHash hashes correctly for *512 families",
			args{
				[]Algorithm{
					RS512,
					PS512,
					ES512,
				},
				plaintext,
			},
			[]byte{59, 155, 152, 31, 42, 73, 169, 106, 97, 147, 182, 183, 133, 104, 120, 56, 73, 216, 252, 212, 38, 69, 36, 35, 94, 59, 242, 217, 177, 171, 19, 171, 38, 163, 245, 40, 244, 218, 237, 221, 238, 211, 97, 91, 151, 159, 1, 94, 1, 212, 55, 207, 165, 25, 237, 145, 235, 193, 134, 43, 151, 170, 227, 13},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, alg := range tt.args.algorithms {
				got, err := GetHash(alg, tt.args.plaintext)
				if (err != nil) != tt.wantErr {
					t.Errorf("GetHash() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("GetHash() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
