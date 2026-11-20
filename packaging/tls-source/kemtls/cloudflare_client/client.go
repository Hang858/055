package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// protocolConfigFromEnv 与 server 端保持一致，便于矩阵测试。
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

func loadRootCA() (*x509.CertPool, error) {
	rootPEM, err := os.ReadFile("pqcerts/root-ca.pem")
	if err != nil {
		return nil, fmt.Errorf("read root-ca.pem: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		return nil, fmt.Errorf("failed to append root CA")
	}

	return pool, nil
}

// 👈 新增用来加载客户端证书
func loadClientCertificate() (tls.Certificate, error) {
	// ✅ 客户端 leaf 证书
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

	// ✅ 客户端私钥
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

func main() {
	rootCAs, err := loadRootCA()
	if err != nil {
		log.Fatalf("loadRootCA failed: %v", err)
	}

	// 新增用来加载证书
	clientCert, err := loadClientCertificate()
	if err != nil {
		log.Fatalf("loadClientCertificate failed: %v", err)
	}

	protocolType, protocolTypes, modeCompat := protocolConfigFromEnv(tls.QuantumSupportAKEX)
	requirePQChain := os.Getenv("KEMTLS_PQ_CHAIN") == "1"
	var pqRoots []*x509.Certificate
	if requirePQChain {
		pqRoots, err = loadPQRoots()
		if err != nil {
			log.Fatalf("loadPQRoots failed: %v", err)
		}
	}

	tlsConfig := &tls.Config{
		RootCAs: rootCAs,
		// 👇 这里一定要写证书里的域名
		ServerName: "quantum-secure.example.com",
		//ProtocolType:       tls.QuantumSupportKemCert_KEX,
		ProtocolType:              protocolType,
		ProtocolTypes:             protocolTypes,
		ModeCompatibilityFlag:     modeCompat,
		ProtocolTypeStrict:        0, // 👈 旧接口，保留兼容；新配置用 ModeCompatibilityFlag
		PQRoots:                   pqRoots,
		RequirePQCertificateChain: requirePQChain,

		// 👈 新增 ✅ 关键：客户端证书（发给 server）
		Certificates: []tls.Certificate{clientCert},
		KEMTLSSigAlg: os.Getenv("KEMTLS_SIG_ALG"),
		KEMTLSSigKey: os.Getenv("KEMTLS_SIG_KEY"),
		KEMTLSKEMAlg: os.Getenv("KEMTLS_KEM_ALG"),
		KEMTLSKEMKey: os.Getenv("KEMTLS_KEM_KEY"),
	}

	//start := time.Now()
	//// 这里仍然可以连 localhost:8443
	//conn, err = tls.Dial("tcp", "localhost:8443", tlsConfig)
	//if err != nil {
	//	log.Fatalf("tls.Dial failed: %v", err)
	//}
	////defer conn.Close()
	//elapsed := time.Since(start)
	//fmt.Println("执行时间:", elapsed)

	//这里来测试执行100次的时间
	var times []time.Duration
	var total time.Duration
	var min time.Duration = time.Hour // 初始设为非常大
	var max time.Duration

	conns := 100
	if v := os.Getenv("KEMTLS_CONNECTIONS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			conns = n
		}
	}
	for i := 0; i < conns; i++ {
		start := time.Now()

		conn, err := tls.Dial("tcp", "localhost:8443", tlsConfig)
		if err != nil {
			log.Fatalf("tls.Dial failed: %v", err)
		}
		conn.Close()

		elapsed := time.Since(start)

		// 保存
		times = append(times, elapsed)
		total += elapsed

		// 统计最短
		if elapsed < min {
			min = elapsed
		}
		// 统计最长
		if elapsed > max {
			max = elapsed
		}
	}

	avg := total / time.Duration(len(times))

	fmt.Println("===============================================")
	fmt.Printf("总次数: %d\n", len(times))
	fmt.Printf("平均耗时: %v\n", avg)
	fmt.Printf("最短耗时: %v\n", min)
	fmt.Printf("最长耗时: %v\n", max)
	fmt.Println("===============================================")

	log.Println("TLS handshake OK, server verified")

	// 这里仍然可以连 localhost:8443
	conn, err := tls.Dial("tcp", "localhost:8443", tlsConfig)
	if err != nil {
		log.Fatalf("tls.Dial failed: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	log.Printf("Negotiated protocol: %s, cipher: %s",
		state.NegotiatedProtocol, tls.CipherSuiteName(state.CipherSuite))
	log.Printf("VerifiedChains length: %d", len(state.VerifiedChains))

	msg := "Hello TLS Server\n"
	if _, err := conn.Write([]byte(msg)); err != nil {
		log.Fatalf("Write failed: %v", err)
	}
	log.Printf("Client sent: %s", msg)

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		log.Fatalf("Read failed: %v", err)
	}
	log.Printf("Client received: %s", string(buf[:n]))
}
