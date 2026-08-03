// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package mldsa44

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"testing"
)

func loadEIP8051CompactVector(t testing.TB, name string) ([]byte, []byte) {
	t.Helper()
	blob, err := ioutil.ReadFile("testdata/eip8051.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors map[string]testVector
	if err := json.Unmarshal(blob, &vectors); err != nil {
		t.Fatal(err)
	}
	vector, ok := vectors[name]
	if !ok {
		t.Fatalf("missing EIP-8051 %s vector", name)
	}
	decode := func(label, encoded string) []byte {
		value, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("invalid %s encoding: %v", label, err)
		}
		return value
	}
	return decode("public key", vector.PublicKey), decode("message", vector.Message)
}

func TestEIP8051KeygenAndSign(t *testing.T) {
	var seed [EIP8051SeedSize]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	for _, test := range []struct {
		name    string
		variant EIP8051Variant
	}{
		{"nist", EIP8051MLDSA},
		{"eth", EIP8051MLDSAETH},
	} {
		t.Run(test.name, func(t *testing.T) {
			expectedPublicKey, message := loadEIP8051CompactVector(t, test.name)
			_, _, expectedSignature := loadEIP8051Vector(t, test.name)
			publicKey, privateKey, err := NewEIP8051KeyFromSeed(&seed, test.variant)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(publicKey, expectedPublicKey) {
				t.Fatalf("public key mismatch:\nhave %x\nwant %x", publicKey, expectedPublicKey)
			}
			if !bytes.Equal(privateKey.PublicKey(), publicKey) || !bytes.Equal(privateKey.Seed(), seed[:]) {
				t.Fatal("private key accessors returned different key material")
			}

			signature, err := SignEIP8051(privateKey, message, bytes.NewReader(make([]byte, 32)))
			if err != nil {
				t.Fatal(err)
			}
			if len(signature) != SignatureSize {
				t.Fatalf("signature has %d bytes, want %d", len(signature), SignatureSize)
			}
			if !bytes.Equal(signature, expectedSignature) {
				t.Fatalf("deterministic signature does not match the ZKNOX reference vector")
			}
			var expanded []byte
			var expandedOK, valid bool
			if test.variant == EIP8051MLDSAETH {
				expanded, expandedOK = ExpandPublicKeyETH(publicKey)
				valid = VerifyExpandedETH(expanded, message, signature)
			} else {
				expanded, expandedOK = ExpandPublicKey(publicKey)
				valid = VerifyExpanded(expanded, message, signature)
			}
			if !expandedOK || !valid {
				t.Fatal("newly generated signature was rejected")
			}
			modified := append([]byte{}, signature...)
			modified[0] ^= 1
			if test.variant == EIP8051MLDSAETH && VerifyExpandedETH(expanded, message, modified) {
				t.Fatal("modified ETH signature was accepted")
			}
			if test.variant == EIP8051MLDSA && VerifyExpanded(expanded, message, modified) {
				t.Fatal("modified NIST signature was accepted")
			}
		})
	}
}

func TestEIP8051SigningErrors(t *testing.T) {
	if _, _, err := NewEIP8051KeyFromSeed(nil, EIP8051MLDSA); err == nil {
		t.Fatal("nil seed accepted")
	}
	var seed [EIP8051SeedSize]byte
	if _, _, err := NewEIP8051KeyFromSeed(&seed, EIP8051Variant(99)); err == nil {
		t.Fatal("invalid variant accepted")
	}
	_, privateKey, err := NewEIP8051KeyFromSeed(&seed, EIP8051MLDSA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignEIP8051(privateKey, make([]byte, 31), bytes.NewReader(make([]byte, 32))); err == nil {
		t.Fatal("short message accepted")
	}
	if _, err := SignEIP8051(privateKey, make([]byte, 32), bytes.NewReader(make([]byte, 31))); err == nil {
		t.Fatal("short randomness accepted")
	}
}
