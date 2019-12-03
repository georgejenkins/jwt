package main

import (
	"reflect"
	"testing"
)

func TestInitNoneSignerVerifier(t *testing.T) {
	type args struct {
		alg Algorithm
	}
	tests := []struct {
		name    string
		args    args
		want    *NoneSignerVerifier
		wantErr bool
	}{
		{
			"Must InitNoneSignerVerifier given None",
			args{
				alg: None,
			},
			&NoneSignerVerifier{},
			false,
		},
		{
			"Must fail to InitNoneSignerVerifier given invalid algorithm",
			args{
				alg: RS256,
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := InitNoneSignerVerifier(tt.args.alg)
			if (err != nil) != tt.wantErr {
				t.Errorf("InitNoneSignerVerifier() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("InitNoneSignerVerifier() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNoneSignerVerifier_Sign(t *testing.T) {
	type args struct {
		plaintext []byte
	}
	tests := []struct {
		name    string
		sv      *NoneSignerVerifier
		args    args
		want    []byte
		wantErr bool
	}{
		{
			"Must InitNoneSignerVerifier given None",
			&NoneSignerVerifier{},
			args{
				plaintext: examplePayload,
			},
			nil,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.sv.Sign(tt.args.plaintext)
			if (err != nil) != tt.wantErr {
				t.Errorf("NoneSignerVerifier.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NoneSignerVerifier.Sign() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNoneSignerVerifier_Verify(t *testing.T) {
	type args struct {
		plaintext []byte
		signature []byte
	}
	tests := []struct {
		name    string
		sv      *NoneSignerVerifier
		args    args
		want    bool
		wantErr bool
	}{
		{
			"Must verify given None",
			&NoneSignerVerifier{},
			args{
				plaintext: examplePayload,
			},
			true,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.sv.Verify(tt.args.plaintext, tt.args.signature)
			if (err != nil) != tt.wantErr {
				t.Errorf("NoneSignerVerifier.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("NoneSignerVerifier.Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}
