package main

import (
	"log"
	"pqtls_project/internal/crypto/mytls"
	"pqtls_project/internal/mynet/http" // 使用自定义的 HTTP 包
)

func runClient() {
	// 加载CA证书
	//caCert, err := ioutil.ReadFile("certs/ca.crt")
	//if err != nil {
	//	log.Printf("Client: Warning - Failed to load CA certificate (may skip verify): %v", err)
	//}

	// 注意：这里使用 mytls 包中的 x509
	//caCertPool := tls.NewCertPool()
	//if len(caCert) > 0 {
	//	if !caCertPool.AppendCertsFromPEM(caCert) {
	//		log.Printf("Client: Warning - Could not append CA cert to pool.")
	//	}
	//}

	// 配置自定义 TLS
	config := &tls.Config{
		//RootCAs:            caCertPool,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // 仅用于测试
	}

	// 使用自定义的 HTTP 客户端
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}

	log.Println("Client: Sending request to server")
	resp, err := client.Get("https://localhost:8443")
	if err != nil {
		log.Fatalf("Client: Failed to make request: %v", err)
	}

	log.Printf("Client: Received response: %s", string(resp.Body))
	log.Printf("Client: Status code: %d", resp.StatusCode)

	//conn, err := tls.Dial("tcp", "localhost:8443", config)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//state := conn.ConnectionState()
	//log.Printf("Negotiated protocol: %v", state.NegotiatedProtocol) // ALPN
	//log.Printf("TLS version: %x", state.Version)                    // 0x0304 表示 TLS 1.3

}
