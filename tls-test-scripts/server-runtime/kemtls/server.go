package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

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

	// 中间证书
	inter1PEM, err := os.ReadFile("pqcerts/intermediate1-ca.pem")
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read intermediate1-ca.pem: %w", err)
	}
	inter2PEM, err := os.ReadFile("pqcerts/intermediate2-ca.pem")
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read intermediate2-ca.pem: %w", err)
	}

	// 将 leaf + 中间证书拼成一份 PEM，形成完整证书链
	fullChainPEM := append(endEntityCertPEM, inter1PEM...)
	fullChainPEM = append(fullChainPEM, inter2PEM...)

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

func main() {
	cert, err := loadServerCertificate()
	if err != nil {
		log.Fatalf("loadServerCertificate failed: %v", err)
	}

	clientCAs, err := loadClientCAs()
	if err != nil {
		log.Fatalf("loadClientCAs failed: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// 如果只做单向认证（客户端只校验服务器），这里不用设置 ClientAuth
		// ClientAuth: tls.RequireAndVerifyClientCert,

		// 👈 新增 关键：要求客户端必须发证书，并且用 ClientCAs 去验证它
		ClientAuth: tls.RequireAnyClientCert,
		ClientCAs:  clientCAs,
		//ProtocolType:       tls.QuantumSupportAKEX,
		ProtocolType:       tls.QuantumSupportAKEX,
		ProtocolTypeStrict: 0, // 👈 这里表示是不是强制需要执行这个协议版本
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
