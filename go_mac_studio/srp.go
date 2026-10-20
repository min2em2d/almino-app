package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"time"
)

const ng2048Hex = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4" +
	"A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60" +
	"95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF" +
	"747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907" +
	"8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861" +
	"60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB" +
	"FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"

var (
	srpN *big.Int
	srpG *big.Int
	srpK *big.Int
)

func init() {
	nBytes, _ := hex.DecodeString(ng2048Hex)
	srpN = new(big.Int).SetBytes(nBytes)
	srpG = big.NewInt(2)
	width := len(nBytes)
	srpK = new(big.Int).SetBytes(srpHashPadded(width, srpN.Bytes(), srpG.Bytes()))
}

func srpHashPadded(width int, chunks ...[]byte) []byte {
	h := sha256.New()
	for _, c := range chunks {
		if width > len(c) {
			pad := make([]byte, width-len(c))
			h.Write(pad)
		}
		h.Write(c)
	}
	return h.Sum(nil)
}

func srpHashRaw(chunks ...[]byte) []byte {
	h := sha256.New()
	for _, c := range chunks {
		h.Write(c)
	}
	return h.Sum(nil)
}

// PBKDF2SHA256 implements standard RFC 2898 PBKDF2-HMAC-SHA256 in pure Go.
func PBKDF2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := func(key, data []byte) []byte {
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		return mac.Sum(nil)
	}
	hashLen := 32
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var dk []byte
	var blockBuf [4]byte
	for block := 1; block <= numBlocks; block++ {
		binary.BigEndian.PutUint32(blockBuf[:], uint32(block))
		u := prf(password, append(append([]byte(nil), salt...), blockBuf[:]...))
		t := make([]byte, len(u))
		copy(t, u)
		for i := 2; i <= iter; i++ {
			u = prf(password, u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// EncryptApplePassword derives Apple's s2k / s2k_fo password verifier key.
func EncryptApplePassword(password string, salt []byte, iterations int, protocol string) []byte {
	sum := sha256.Sum256([]byte(password))
	var p []byte
	if protocol == "s2k_fo" {
		p = []byte(hex.EncodeToString(sum[:]))
	} else {
		p = sum[:]
	}
	return PBKDF2SHA256(p, salt, iterations, 32)
}

// SRPUser implements Apple's exact RFC 5054 2048-bit SRP-6a client with no_username_in_x.
type SRPUser struct {
	Username   string
	Password   []byte
	a          *big.Int
	A          *big.Int
	S          *big.Int
	K          []byte
	M1         []byte
	H_AMK      []byte
	SessionKey []byte
}

func NewSRPUser(username string) (*SRPUser, []byte, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	randBytes := make([]byte, 256)
	if _, err := rand.Read(randBytes); err != nil {
		return nil, nil, err
	}
	randBytes[0] |= 0x80 // matches get_random_of_length(256)
	a := new(big.Int).SetBytes(randBytes)
	A := new(big.Int).Exp(srpG, a, srpN)
	u := &SRPUser{
		Username: username,
		a:        a,
		A:        A,
	}
	return u, A.Bytes(), nil
}

func (u *SRPUser) ProcessChallenge(salt, bytesB []byte) ([]byte, error) {
	B := new(big.Int).SetBytes(bytesB)
	modCheck := new(big.Int).Mod(B, srpN)
	if modCheck.Sign() == 0 {
		return nil, errors.New("SRP safety check failed: B mod N == 0")
	}

	width := len(srpN.Bytes())
	uBytes := srpHashPadded(width, u.A.Bytes(), B.Bytes())
	uVal := new(big.Int).SetBytes(uBytes)
	if uVal.Sign() == 0 {
		return nil, errors.New("SRP safety check failed: u == 0")
	}

	// no_username_in_x = true -> H(salt, H(":" + password_bytes))
	colonPass := append([]byte(":"), u.Password...)
	innerH := srpHashRaw(colonPass)
	xBytes := srpHashRaw(salt, innerH)
	x := new(big.Int).SetBytes(xBytes)

	// v = g^x mod N
	v := new(big.Int).Exp(srpG, x, srpN)

	// base = (B - k*v) mod N
	kv := new(big.Int).Mul(srpK, v)
	base := new(big.Int).Sub(B, kv)
	base.Mod(base, srpN)
	if base.Sign() < 0 {
		base.Add(base, srpN)
	}

	// exp = a + u*x
	ux := new(big.Int).Mul(uVal, x)
	exp := new(big.Int).Add(u.a, ux)

	// S = base^exp mod N
	S := new(big.Int).Exp(base, exp, srpN)
	u.S = S
	u.K = srpHashRaw(S.Bytes())
	u.SessionKey = u.K

	// HNxorg = SHA256(N) XOR SHA256(pad(g, 256))
	nRaw := srpN.Bytes()
	gRaw := srpG.Bytes()
	hN := srpHashRaw(nRaw)
	gPadded := make([]byte, len(nRaw))
	copy(gPadded[len(nRaw)-len(gRaw):], gRaw)
	hG := srpHashRaw(gPadded)
	hnXorG := make([]byte, len(hN))
	for i := range hN {
		hnXorG[i] = hN[i] ^ hG[i]
	}

	hI := srpHashRaw([]byte(u.Username))
	u.M1 = srpHashRaw(hnXorG, hI, salt, u.A.Bytes(), B.Bytes(), u.K)
	u.H_AMK = srpHashRaw(u.A.Bytes(), u.M1, u.K)
	return u.M1, nil
}

func (u *SRPUser) DeriveSessionHMAC(label string) []byte {
	mac := hmac.New(sha256.New, u.SessionKey)
	mac.Write([]byte(label))
	return mac.Sum(nil)
}

func (u *SRPUser) DecryptSPD(encryptedSPD []byte) (map[string]interface{}, error) {
	if len(u.SessionKey) == 0 {
		return nil, errors.New("empty SRP session key")
	}
	if len(encryptedSPD) == 0 || len(encryptedSPD)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid encrypted spd length: %d", len(encryptedSPD))
	}
	extraKey := u.DeriveSessionHMAC("extra data key:")
	extraIV := u.DeriveSessionHMAC("extra data iv:")[:16]

	block, err := aes.NewCipher(extraKey)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(encryptedSPD))
	mode := cipher.NewCBCDecrypter(block, extraIV)
	mode.CryptBlocks(plain, encryptedSPD)

	// PKCS7 unpad
	padLen := int(plain[len(plain)-1])
	if padLen <= 0 || padLen > aes.BlockSize || padLen > len(plain) {
		return nil, errors.New("invalid PKCS7 padding on spd")
	}
	rawPlist := bytes.TrimSpace(plain[:len(plain)-padLen])
	if bytes.HasPrefix(rawPlist, []byte("<dict>")) {
		header := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
			`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n" +
			`<plist version="1.0">` + "\n"
		rawPlist = append([]byte(header), append(rawPlist, []byte("\n</plist>")...)...)
	}
	return ParsePlistBytes(rawPlist)
}

// ComputeTOTP calculates a real RFC 6238 TOTP code for fallback accounts without adi_pb_b64.
func ComputeTOTP(secretStr string, period int, digits int, algo string, nowUnix float64) (string, int, int64) {
	if period <= 0 {
		period = 30
	}
	if digits <= 0 {
		digits = 6
	}
	if nowUnix <= 0 {
		nowUnix = float64(time.Now().Unix())
	}
	keyBytes := normalizeSecretBytes(secretStr)
	secInt := int64(nowUnix)
	counter := secInt / int64(period)
	rem := period - int(secInt%int64(period))

	var hashFunc func() hash.Hash
	switch strings.ToLower(algo) {
	case "sha256":
		hashFunc = sha256.New
	case "sha512":
		hashFunc = sha512.New
	default:
		hashFunc = sha1.New
	}

	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	mac := hmac.New(hashFunc, keyBytes)
	mac.Write(msg[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	binCode := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	codeInt := binCode % mod
	return fmt.Sprintf("%0*d", digits, codeInt), rem, counter
}

func normalizeSecretBytes(s string) []byte {
	s = strings.TrimSpace(s)
	if len(s)%2 == 0 {
		if b, err := hex.DecodeString(s); err == nil {
			return b
		}
	}
	cleanB32 := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), "-", ""))
	if rem := len(cleanB32) % 8; rem != 0 {
		cleanB32 += strings.Repeat("=", 8-rem)
	}
	if b, err := base32.StdEncoding.DecodeString(cleanB32); err == nil {
		return b
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b
	}
	return []byte(s)
}
