package main

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
)

func TestPlistRoundTrip(t *testing.T) {
	orig := map[string]interface{}{
		"Header": map[string]interface{}{"Version": "1.0.1"},
		"Request": map[string]interface{}{
			"u":         "test@hotmail.com",
			"o":         "init",
			"ps":        []string{"s2k", "s2k_fo"},
			"A2k":       []byte{1, 2, 3, 4, 5},
			"bootstrap": true,
			"pbe":       false,
			"rep":       1,
		},
	}
	xmlBytes := BuildPlistXML(orig)
	parsed, err := ParsePlistBytes(xmlBytes)
	if err != nil {
		t.Fatalf("ParsePlistBytes failed: %v", err)
	}
	req, ok := parsed["Request"].(map[string]interface{})
	if !ok {
		t.Fatalf("Request missing")
	}
	if req["u"] != "test@hotmail.com" {
		t.Fatalf("unexpected u: %v", req["u"])
	}
	if !bytes.Equal(req["A2k"].([]byte), []byte{1, 2, 3, 4, 5}) {
		t.Fatalf("unexpected A2k: %v", req["A2k"])
	}
}

func TestSRPVectorAgainstPySRP(t *testing.T) {
	// Deterministic vector test
	salt, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f10")
	pwKey := EncryptApplePassword("MAbdo123#", salt, 20000, "s2k")
	if len(pwKey) != 32 {
		t.Fatalf("expected 32-byte key")
	}
	aBytes := bytes.Repeat([]byte{0x42}, 256)
	aBytes[0] |= 0x80
	a := new(big.Int).SetBytes(aBytes)
	A := new(big.Int).Exp(srpG, a, srpN)
	u := &SRPUser{
		Username: "test@hotmail.com",
		Password: pwKey,
		a:        a,
		A:        A,
	}
	bBytes := bytes.Repeat([]byte{0x24}, 256)
	B := new(big.Int).Exp(srpG, new(big.Int).SetBytes(bBytes), srpN)
	m1, err := u.ProcessChallenge(salt, B.Bytes())
	if err != nil || len(m1) != 32 {
		t.Fatalf("ProcessChallenge failed: %v", err)
	}
	t.Logf("pwKey=%x M1=%x K=%x", pwKey, m1, u.K)
}
