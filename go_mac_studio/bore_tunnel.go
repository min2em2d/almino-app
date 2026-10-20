package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"time"
)

const (
	BoreServerIP   = "159.223.110.159"
	BoreCtrlPort   = 7835
	BorePublicPort = 8188
)

type peekedConn struct {
	net.Conn
	firstByte byte
	hasPeeked bool
}

func (c *peekedConn) Read(p []byte) (int, error) {
	if c.hasPeeked && len(p) > 0 {
		p[0] = c.firstByte
		c.hasPeeked = false
		return 1, nil
	}
	return c.Conn.Read(p)
}

func generateSelfSignedTLSConfig() *tls.Config {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil
	}
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Apple Auth Relay"},
			CommonName:   BoreServerIP,
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP(BoreServerIP), net.ParseIP("127.0.0.1")},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil
	}
	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
}

func handleBoreStream(uuidStr string, localPort int, tlsCfg *tls.Config) {
	dataConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", BoreServerIP, BoreCtrlPort), 10*time.Second)
	if err != nil {
		return
	}
	defer dataConn.Close()

	acceptMsg, _ := json.Marshal(map[string]string{"Accept": uuidStr})
	acceptMsg = append(acceptMsg, 0)
	if _, err := dataConn.Write(acceptMsg); err != nil {
		return
	}

	_ = dataConn.SetReadDeadline(time.Now().Add(15 * time.Second))
	var first [1]byte
	if _, err := io.ReadFull(dataConn, first[:]); err != nil {
		return
	}
	_ = dataConn.SetReadDeadline(time.Time{})

	var clientStream net.Conn = &peekedConn{
		Conn:      dataConn,
		firstByte: first[0],
		hasPeeked: true,
	}

	// 0x16 (22) is TLS Handshake record type -> serve HTTPS!
	if first[0] == 0x16 && tlsCfg != nil {
		tlsConn := tls.Server(clientStream, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		clientStream = tlsConn
	}

	localConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", localPort), 5*time.Second)
	if err != nil {
		return
	}
	defer localConn.Close()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(localConn, clientStream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientStream, localConn)
		done <- struct{}{}
	}()
	<-done
}

func StartBoreIPPortTunnel(localPort int, remotePort int, linker *LinkerManager) {
	tlsCfg := generateSelfSignedTLSConfig()
	go func() {
		for {
			ctrlConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", BoreServerIP, BoreCtrlPort), 10*time.Second)
			if err != nil {
				time.Sleep(3 * time.Second)
				continue
			}

			helloMsg, _ := json.Marshal(map[string]int{"Hello": remotePort})
			helloMsg = append(helloMsg, 0)
			if _, err := ctrlConn.Write(helloMsg); err != nil {
				ctrlConn.Close()
				time.Sleep(3 * time.Second)
				continue
			}

			reader := bufio.NewReader(ctrlConn)
			for {
				_ = ctrlConn.SetReadDeadline(time.Now().Add(45 * time.Second))
				raw, err := reader.ReadBytes(0)
				if err != nil {
					break
				}
				msgStr := strings.TrimSpace(string(raw[:len(raw)-1]))
				if msgStr == "" || msgStr == `"Heartbeat"` {
					continue
				}
				var obj map[string]interface{}
				if err := json.Unmarshal([]byte(msgStr), &obj); err == nil {
					if connUUID, ok := obj["Connection"].(string); ok && connUUID != "" {
						go handleBoreStream(connUUID, localPort, tlsCfg)
					}
				}
			}
			ctrlConn.Close()
			time.Sleep(2 * time.Second)
		}
	}()
}
