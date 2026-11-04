// KEMTLS laboratory implementation of the KEM-SIG and SIG-KEM flows.
//
// This is a standalone two-message protocol following the message flow in
// Fig. 2 and Fig. 3: one side uses a static KEM certificate, the other uses a
// static signature certificate.  It is intentionally separate from crypto/tls
// so the message flow and key schedule can be tested without the TLS 1.3
// certificate/CertificateVerify ordering constraints.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"crypto/myx509"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

const (
	modeKEMSIG = "kemsig"
	modeSIGKEM = "sigkem"
	label      = "KEMTLS-LAB-v1"
)

type clientHello struct {
	Mode             string `json:"mode"`
	EphemeralPK      []byte `json:"ephemeral_pk"`
	StaticCiphertext []byte `json:"static_ciphertext,omitempty"`
	Signature        []byte `json:"signature,omitempty"`
}

type serverHello struct {
	EphemeralCiphertext []byte `json:"ephemeral_ciphertext"`
	StaticCiphertext    []byte `json:"static_ciphertext,omitempty"`
	Signature           []byte `json:"signature,omitempty"`
	Finished            []byte `json:"finished"`
}

type finishedMsg struct {
	Finished []byte `json:"finished"`
}

type secureMsg struct {
	Data []byte `json:"data"`
}

type config struct {
	mode     string
	cert     string
	peerCert string
	sigKey   string
	kemKey   string
	timeout  time.Duration
}

func main() {
	server := flag.Bool("server", false, "run as server")
	mode := flag.String("mode", modeKEMSIG, "kemsig or sigkem")
	listen := flag.String("listen", "127.0.0.1:9443", "server listen address")
	connect := flag.String("connect", "127.0.0.1:9443", "client connect address")
	cert := flag.String("cert", "", "own leaf certificate (PEM)")
	peerCert := flag.String("peer-cert", "", "peer leaf certificate (PEM)")
	sigKey := flag.String("sig-key", "", "own Dilithium2 private key (when this side is SIG)")
	kemKey := flag.String("kem-key", "", "own Kyber768 private key (when this side is KEM)")
	timeout := flag.Duration("timeout", 15*time.Second, "connection timeout")
	flag.Parse()

	if *mode != modeKEMSIG && *mode != modeSIGKEM {
		fatal("mode must be kemsig or sigkem")
	}
	cfg := config{mode: *mode, cert: *cert, peerCert: *peerCert, sigKey: *sigKey, kemKey: *kemKey, timeout: *timeout}
	if cfg.cert == "" || cfg.peerCert == "" {
		fatal("-cert and -peer-cert are required")
	}

	if *server {
		ln, err := net.Listen("tcp", *listen)
		if err != nil {
			fatal("listen: %v", err)
		}
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			fatal("accept: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(cfg.timeout))
		if err := runServer(conn, cfg); err != nil {
			fatal("server: %v", err)
		}
		fmt.Println("PASS: server handshake and echo")
		return
	}

	conn, err := net.DialTimeout("tcp", *connect, cfg.timeout)
	if err != nil {
		fatal("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(cfg.timeout))
	if err := runClient(conn, cfg); err != nil {
		fatal("client: %v", err)
	}
	fmt.Println("PASS: client handshake and echo")
}

func runServer(conn net.Conn, cfg config) error {
	ownCert, err := loadCert(cfg.cert)
	if err != nil {
		return fmt.Errorf("load own cert: %w", err)
	}
	peerCert, err := loadCert(cfg.peerCert)
	if err != nil {
		return fmt.Errorf("load peer cert: %w", err)
	}
	cc := certHash(peerCert) // client certificate
	sc := certHash(ownCert)  // server certificate

	var ch clientHello
	if err := recvJSON(conn, &ch); err != nil {
		return err
	}
	if ch.Mode != cfg.mode {
		return fmt.Errorf("mode mismatch: got %q want %q", ch.Mode, cfg.mode)
	}

	switch cfg.mode {
	case modeKEMSIG:
		return serverKEMSIG(conn, cfg, peerCert, cc, sc, &ch)
	case modeSIGKEM:
		return serverSIGKEM(conn, cfg, peerCert, cc, sc, &ch)
	default:
		return fmt.Errorf("unsupported mode %q", cfg.mode)
	}
}

func runClient(conn net.Conn, cfg config) error {
	ownCert, err := loadCert(cfg.cert)
	if err != nil {
		return fmt.Errorf("load own cert: %w", err)
	}
	peerCert, err := loadCert(cfg.peerCert)
	if err != nil {
		return fmt.Errorf("load peer cert: %w", err)
	}
	cc := certHash(ownCert)  // client certificate
	sc := certHash(peerCert) // server certificate

	switch cfg.mode {
	case modeKEMSIG:
		return clientKEMSIG(conn, cfg, peerCert, cc, sc)
	case modeSIGKEM:
		return clientSIGKEM(conn, cfg, peerCert, cc, sc)
	default:
		return fmt.Errorf("unsupported mode %q", cfg.mode)
	}
}

// serverKEMSIG: server has the SIG identity, peer (client) has the KEM identity.
func serverKEMSIG(conn net.Conn, cfg config, peerCert *x509.Certificate, cc, sc []byte, ch *clientHello) error {
	if cfg.sigKey == "" {
		return errors.New("-sig-key is required for KEM-SIG server")
	}
	if len(ch.EphemeralPK) == 0 {
		return errors.New("missing ephemeral KEM public key")
	}
	scheme := kyber768.Scheme()
	ephPub, err := scheme.UnmarshalBinaryPublicKey(ch.EphemeralPK)
	if err != nil {
		return fmt.Errorf("parse ephemeral KEM public key: %w", err)
	}
	ctEph, ssEph, err := scheme.Encapsulate(ephPub)
	if err != nil {
		return fmt.Errorf("encapsulate ephemeral KEM: %w", err)
	}
	// Encapsulate to the client's static KEM certificate public key.
	ctStatic, ssStatic, err := myx509.EncryptionFromCert(peerCert)
	if err != nil {
		return fmt.Errorf("encapsulate to client KEM certificate: %w", err)
	}

	ctx := contextBytes(modeKEMSIG, cc, sc, ch.EphemeralPK, ctEph, ctStatic)
	sig, err := myx509.QuantumSignWithLocalKey(ctx, cfg.sigKey)
	if err != nil {
		return fmt.Errorf("sign server hello: %w", err)
	}
	key := deriveKey(ctx, sig, ssEph, ssStatic)
	sh := serverHello{
		EphemeralCiphertext: ctEph,
		StaticCiphertext:    ctStatic,
		Signature:           sig,
		Finished:            finished(key, "server", ctx),
	}
	if err := sendJSON(conn, sh); err != nil {
		return err
	}
	var fin finishedMsg
	if err := recvJSON(conn, &fin); err != nil {
		return err
	}
	if !hmac.Equal(fin.Finished, finished(key, "client", ctx)) {
		return errors.New("client Finished mismatch")
	}
	return serverEcho(conn, key)
}

// clientKEMSIG: client has the KEM identity, peer (server) has the SIG identity.
func clientKEMSIG(conn net.Conn, cfg config, peerCert *x509.Certificate, cc, sc []byte) error {
	if cfg.kemKey == "" {
		return errors.New("-kem-key is required for KEM-SIG client")
	}
	scheme := kyber768.Scheme()
	ephPub, ephPriv, err := scheme.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate ephemeral KEM: %w", err)
	}
	ephBytes, err := ephPub.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal ephemeral KEM public key: %w", err)
	}
	ch := clientHello{Mode: modeKEMSIG, EphemeralPK: ephBytes}
	if err := sendJSON(conn, ch); err != nil {
		return err
	}
	var sh serverHello
	if err := recvJSON(conn, &sh); err != nil {
		return err
	}
	ctx := contextBytes(modeKEMSIG, cc, sc, ephBytes, sh.EphemeralCiphertext, sh.StaticCiphertext)
	ok, err := myx509.VerifyQuantumSignatureFromCert(peerCert, ctx, sh.Signature)
	if err != nil {
		return fmt.Errorf("verify server signature: %w", err)
	}
	if !ok {
		return errors.New("server signature invalid")
	}
	ssEph, err := scheme.Decapsulate(ephPriv, sh.EphemeralCiphertext)
	if err != nil {
		return fmt.Errorf("decapsulate ephemeral KEM: %w", err)
	}
	// Missing/wrong client KEM private key must fail here.
	ssStatic, err := myx509.QuantumDecryptionWithLocalKey(sh.StaticCiphertext, cfg.kemKey)
	if err != nil {
		return fmt.Errorf("decapsulate static client KEM: %w", err)
	}
	key := deriveKey(ctx, sh.Signature, ssEph, ssStatic)
	if !hmac.Equal(sh.Finished, finished(key, "server", ctx)) {
		return errors.New("server Finished mismatch")
	}
	if err := sendJSON(conn, finishedMsg{Finished: finished(key, "client", ctx)}); err != nil {
		return err
	}
	return clientEcho(conn, key)
}

// serverSIGKEM: server has the KEM identity, peer (client) has the SIG identity.
func serverSIGKEM(conn net.Conn, cfg config, peerCert *x509.Certificate, cc, sc []byte, ch *clientHello) error {
	if cfg.kemKey == "" {
		return errors.New("-kem-key is required for SIG-KEM server")
	}
	if len(ch.EphemeralPK) == 0 || len(ch.StaticCiphertext) == 0 {
		return errors.New("missing SIG-KEM client fields")
	}
	// Signature covers pk_tilde || c_R; c_tilde is not known yet.
	sigCtx := contextBytes(modeSIGKEM, cc, sc, ch.EphemeralPK, nil, ch.StaticCiphertext)
	ok, err := myx509.VerifyQuantumSignatureFromCert(peerCert, sigCtx, ch.Signature)
	if err != nil {
		return fmt.Errorf("verify client signature: %w", err)
	}
	if !ok {
		return errors.New("client signature invalid")
	}
	// Missing/wrong server KEM private key must fail here.
	ssStatic, err := myx509.QuantumDecryptionWithLocalKey(ch.StaticCiphertext, cfg.kemKey)
	if err != nil {
		return fmt.Errorf("decapsulate static server KEM: %w", err)
	}
	scheme := kyber768.Scheme()
	ephPub, err := scheme.UnmarshalBinaryPublicKey(ch.EphemeralPK)
	if err != nil {
		return fmt.Errorf("parse ephemeral KEM public key: %w", err)
	}
	ctEph, ssEph, err := scheme.Encapsulate(ephPub)
	if err != nil {
		return fmt.Errorf("encapsulate ephemeral KEM: %w", err)
	}
	ctx := contextBytes(modeSIGKEM, cc, sc, ch.EphemeralPK, ctEph, ch.StaticCiphertext)
	key := deriveKey(ctx, ch.Signature, ssEph, ssStatic)
	sh := serverHello{
		EphemeralCiphertext: ctEph,
		Finished:            finished(key, "server", ctx),
	}
	if err := sendJSON(conn, sh); err != nil {
		return err
	}
	var fin finishedMsg
	if err := recvJSON(conn, &fin); err != nil {
		return err
	}
	if !hmac.Equal(fin.Finished, finished(key, "client", ctx)) {
		return errors.New("client Finished mismatch")
	}
	return serverEcho(conn, key)
}

// clientSIGKEM: client has the SIG identity, peer (server) has the KEM identity.
func clientSIGKEM(conn net.Conn, cfg config, peerCert *x509.Certificate, cc, sc []byte) error {
	if cfg.sigKey == "" {
		return errors.New("-sig-key is required for SIG-KEM client")
	}
	scheme := kyber768.Scheme()
	ephPub, ephPriv, err := scheme.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate ephemeral KEM: %w", err)
	}
	ephBytes, err := ephPub.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal ephemeral KEM public key: %w", err)
	}
	// Encapsulate to the server's static KEM certificate.
	ctStatic, ssStatic, err := myx509.EncryptionFromCert(peerCert)
	if err != nil {
		return fmt.Errorf("encapsulate to server KEM certificate: %w", err)
	}
	sigCtx := contextBytes(modeSIGKEM, cc, sc, ephBytes, nil, ctStatic)
	sig, err := myx509.QuantumSignWithLocalKey(sigCtx, cfg.sigKey)
	if err != nil {
		return fmt.Errorf("sign client hello: %w", err)
	}
	ch := clientHello{
		Mode:             modeSIGKEM,
		EphemeralPK:      ephBytes,
		StaticCiphertext: ctStatic,
		Signature:        sig,
	}
	if err := sendJSON(conn, ch); err != nil {
		return err
	}
	var sh serverHello
	if err := recvJSON(conn, &sh); err != nil {
		return err
	}
	ctx := contextBytes(modeSIGKEM, cc, sc, ephBytes, sh.EphemeralCiphertext, ctStatic)
	ssEph, err := scheme.Decapsulate(ephPriv, sh.EphemeralCiphertext)
	if err != nil {
		return fmt.Errorf("decapsulate ephemeral KEM: %w", err)
	}
	key := deriveKey(ctx, sig, ssEph, ssStatic)
	if !hmac.Equal(sh.Finished, finished(key, "server", ctx)) {
		return errors.New("server Finished mismatch")
	}
	if err := sendJSON(conn, finishedMsg{Finished: finished(key, "client", ctx)}); err != nil {
		return err
	}
	return clientEcho(conn, key)
}

// contextBytes is the transcript covered by the signature and Finished.
func contextBytes(mode string, clientCert, serverCert, ephPK, ctEph, ctStatic []byte) []byte {
	var b bytes.Buffer
	field := func(p []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(p)))
		b.Write(n[:])
		b.Write(p)
	}
	field([]byte(label))
	field([]byte(mode))
	field(clientCert)
	field(serverCert)
	field(ephPK)
	field(ctEph)
	field(ctStatic)
	return b.Bytes()
}

func deriveKey(ctx, sig, ssEph, ssStatic []byte) []byte {
	h := sha256.New()
	h.Write([]byte("KEMTLS-LAB-key"))
	h.Write(ctx)
	h.Write(sig)
	h.Write(ssEph)
	h.Write(ssStatic)
	return h.Sum(nil)
}

func finished(key []byte, role string, ctx []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("finished:" + role))
	mac.Write(ctx)
	return mac.Sum(nil)
}

func serverEcho(conn net.Conn, key []byte) error {
	var msg secureMsg
	if err := recvJSON(conn, &msg); err != nil {
		return err
	}
	plain, err := open(key, msg.Data)
	if err != nil {
		return fmt.Errorf("decrypt client echo: %w", err)
	}
	if string(plain) != "hello" {
		return fmt.Errorf("unexpected client echo %q", plain)
	}
	reply, err := seal(key, []byte("echo:"+string(plain)))
	if err != nil {
		return err
	}
	return sendJSON(conn, secureMsg{Data: reply})
}

func clientEcho(conn net.Conn, key []byte) error {
	data, err := seal(key, []byte("hello"))
	if err != nil {
		return err
	}
	if err := sendJSON(conn, secureMsg{Data: data}); err != nil {
		return err
	}
	var msg secureMsg
	if err := recvJSON(conn, &msg); err != nil {
		return err
	}
	plain, err := open(key, msg.Data)
	if err != nil {
		return fmt.Errorf("decrypt server echo: %w", err)
	}
	if string(plain) != "echo:hello" {
		return fmt.Errorf("unexpected server echo %q", plain)
	}
	return nil
}

func appKey(key []byte) [32]byte {
	return sha256.Sum256(append([]byte("KEMTLS-LAB-app:"), key...))
}

func seal(key, plain []byte) ([]byte, error) {
	k := appKey(key)
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return append(nonce, gcm.Seal(nil, nonce, plain, nil)...), nil
}

func open(key, data []byte) ([]byte, error) {
	k := appKey(key)
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
}

func loadCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func certHash(cert *x509.Certificate) []byte {
	h := sha256.Sum256(cert.Raw)
	return h[:]
}

func sendJSON(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(data) > 16<<20 {
		return errors.New("message too large")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func recvJSON(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > 16<<20 {
		return fmt.Errorf("invalid message length %d", n)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}
