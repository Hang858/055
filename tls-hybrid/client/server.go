package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	// 输出请求信息
	fmt.Fprintf(w, "Hello, you've requested: %s\n", r.URL.Path)
}

func main1() {
	// 创建自定义的 TLS 配置
	config := &tls.Config{
		CurvePreferences: []tls.CurveID{
			tls.SM2Kyber512Draft00,
			tls.X25519Kyber768Draft00, // 使用混合 KEM
			tls.X25519,                // 回退到经典 X25519
		},
		MinVersion: tls.VersionTLS13, // 强制使用 TLS 1.3
		MaxVersion: tls.VersionTLS13,
	}

	// 创建一个 HTTP 处理器
	http.HandleFunc("/", handler)

	// 创建一个 HTTPS 服务器
	server := &http.Server{
		Addr:      ":8080", // 设置监听端口
		TLSConfig: config,
	}

	// 启动 HTTPS 服务器，监听端口 8080
	log.Println("启动 HTTPS 服务器，监听端口 8080")
	err := server.ListenAndServeTLS("./server.crt", "./server.key") // 使用当前目录下的证书和私钥文件
	if err != nil {
		log.Fatalf("启动 HTTPS 服务器失败: %s", err)
	}
}
