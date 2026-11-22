package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

// protocolConfigFromEnv 读取交互类型配置，便于矩阵测试不重编译：
//
//	KEMTLS_PROTOCOL_TYPE   首选类型（单个整数）
//	KEMTLS_PROTOCOL_TYPES  支持列表，逗号分隔，首项为首选
//	KEMTLS_MODE_COMPAT     1 表示愿意跟随对端类型并回退 ClassicAKE
func protocolConfigFromEnv(defaultType uint16) (uint16, []uint16, bool) {
	primary := defaultType
	if v := os.Getenv("KEMTLS_PROTOCOL_TYPE"); v != "" {
		if n, err := strconv.ParseUint(v, 0, 16); err == nil {
			primary = uint16(n)
		}
	}
	var list []uint16
	if v := os.Getenv("KEMTLS_PROTOCOL_TYPES"); v != "" {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if n, err := strconv.ParseUint(part, 0, 16); err == nil {
				list = append(list, uint16(n))
			}
		}
	}
	return primary, list, os.Getenv("KEMTLS_MODE_COMPAT") == "1"
}

// 👈 为了验证
func loadClientCAs() (*x509.CertPool, error) {
	caPEM, err := os.ReadFile("pqcerts/root-ca.pem") // 用来验证客户端证书的 CA
	if err != nil {
		return nil, fmt.Errorf("read root-ca.pem: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to append client CA")
	}
	return pool, nil
}

// 加载服务端证书：end-entity + 中间证书链
func loadServerCertificate() (tls.Certificate, error) {
	// leaf 证书
	endEntityCertPEM, err := os.ReadFile("pqcerts/end-entity.pem")
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read end-entity.pem: %w", err)
	}

	// 中间证书可选；实验室证书链可以直接是 root -> leaf。
	fullChainPEM := append([]byte(nil), endEntityCertPEM...)
	for _, name := range []string{"pqcerts/intermediate1-ca.pem", "pqcerts/intermediate2-ca.pem"} {
		if data, err := os.ReadFile(name); err == nil {
			fullChainPEM = append(fullChainPEM, data...)
		}
	}

	// 私钥
	keyPEM, err := os.ReadFile("pqcerts/end-entity-key.pem")
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read end-entity-key.pem: %w", err)
	}

	cert, err := tls.X509KeyPair(fullChainPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("X509KeyPair: %w", err)
	}

	return cert, nil
}

// loadPQRoots 读取 PQ 证书链验证所需的根证书；默认使用 pqcerts/root-ca.pem。
func loadPQRoots() ([]*x509.Certificate, error) {
	path := os.Getenv("KEMTLS_PQ_ROOT")
	if path == "" {
		path = "pqcerts/root-ca.pem"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read PQ root %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decode PQ root %s: no PEM block", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PQ root %s: %w", path, err)
	}
	return []*x509.Certificate{cert}, nil
}

// authModesFromEnv 读取双维度认证配置：KEMTLS_CLIENT_AUTH / KEMTLS_SERVER_AUTH。
func authModesFromEnv() (uint16, uint16) {
	parse := func(key string) uint16 {
		v := os.Getenv(key)
		if v == "" {
			return 0
		}
		n, err := strconv.ParseUint(v, 0, 16)
		if err != nil {
			return 0
		}
		return uint16(n)
	}
	return parse("KEMTLS_CLIENT_AUTH"), parse("KEMTLS_SERVER_AUTH")
}

func main() {
	cert, err := loadServerCertificate()
	if err != nil {
		log.Fatalf("loadServerCertificate failed: %v", err)
	}

	clientCAs, err := loadClientCAs()
	if err != nil {
		log.Fatalf("loadClientCAs failed: %v", err)
	}

	protocolType, protocolTypes, modeCompat := protocolConfigFromEnv(tls.QuantumSupportAKEX)
	clientAuthMode, serverAuthMode := authModesFromEnv()
	requirePQChain := os.Getenv("KEMTLS_PQ_CHAIN") == "1"
	var pqRoots []*x509.Certificate
	if requirePQChain {
		pqRoots, err = loadPQRoots()
		if err != nil {
			log.Fatalf("loadPQRoots failed: %v", err)
		}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// 如果只做单向认证（客户端只校验服务器），这里不用设置 ClientAuth
		// ClientAuth: tls.RequireAndVerifyClientCert,

		// 👈 新增 关键：要求客户端必须发证书，并且用 ClientCAs 去验证它
		ClientAuth: tls.RequireAnyClientCert,
		ClientCAs:  clientCAs,
		//ProtocolType:       tls.QuantumSupportAKEX,
		ProtocolType:              protocolType,
		ProtocolTypes:             protocolTypes,
		ModeCompatibilityFlag:     modeCompat,
		ProtocolTypeStrict:        0, // 👈 旧接口，保留兼容；新配置用 ModeCompatibilityFlag
		PQRoots:                   pqRoots,
		RequirePQCertificateChain: requirePQChain,
		ClientAuthMode:            clientAuthMode,
		ServerAuthMode:            serverAuthMode,
		KEMTLSSigAlg:              os.Getenv("KEMTLS_SIG_ALG"),
		KEMTLSSigKey:              os.Getenv("KEMTLS_SIG_KEY"),
		KEMTLSKEMAlg:              os.Getenv("KEMTLS_KEM_ALG"),
		KEMTLSKEMKey:              os.Getenv("KEMTLS_KEM_KEY"),
		KEMTLSKEXAlg:              os.Getenv("KEMTLS_KEX_ALG"),
	}

	// 使用 TLS 监听
	ln, err := tls.Listen("tcp", ":8443", tlsConfig)
	if err != nil {
		log.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	log.Println("TLS server listening on :8443 ...")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		log.Println("connection is not *tls.Conn")
		return
	}

	// 触发 TLS 握手（一般第一个 Read/Write 会自动触发，这里显式调用）
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake error: %v", err)
		return
	}

	log.Println("New TLS client connected")

	// 👈 这里是验证client端证书的新增打印client端证书的内容
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		c := state.PeerCertificates[0]
		log.Printf("Client cert subject=%s, issuer=%s",
			c.Subject.String(), c.Issuer.String())
	} else {
		log.Printf("No client certificate presented")
	}

	// 简单 echo：读到什么就原样写回去
	buf := make([]byte, 4096)
	for {
		n, err := tlsConn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("Read error: %v", err)
			}
			return
		}
		data := buf[:n]
		log.Printf("Server received: %s", string(data))

		if _, err := tlsConn.Write(data); err != nil {
			log.Printf("Write error: %v", err)
			return
		}
	}
}
