package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
)

func main1() {
	// 创建自定义的 TLS 配置
	config := &tls.Config{
		InsecureSkipVerify: true, // 跳过证书验证
		CurvePreferences: []tls.CurveID{
			tls.SM2Kyber512Draft00,
			tls.X25519Kyber768Draft00, // 优先使用混合 KEM
			tls.X25519,                // 回退到经典 X25519
		},
		MinVersion: tls.VersionTLS13, // 强制使用 TLS 1.3
		MaxVersion: tls.VersionTLS13,
	}
	fmt.Println(config.CurvePreferences)
	// 创建 HTTP 请求，并绑定事件处理器
	req, err := http.NewRequestWithContext(
		context.WithValue(
			context.Background(),
			tls.CFEventHandlerContextKey{}, // 绑定事件处理器
			func(ev tls.CFEvent) {
				switch e := ev.(type) {
				case tls.CFEventTLS13NegotiatedKEX:
					// 打印实际使用的密钥交换算法
					switch e.KEX {
					case tls.SM2Kyber512Draft00:
						fmt.Println("Used Kyber768sm2")
					case tls.X25519Kyber768Draft00:
						fmt.Println("Used X25519Kyber768Draft00")
					case tls.X25519:
						fmt.Println("Used X25519")
					default:
						fmt.Printf("Used unknown curve: %d\n", e.KEX)
					}
				case tls.CFEventTLS13HRR:
					fmt.Println("HelloRetryRequest triggered")
				}
			},
		),
		"GET",
		"https://localhost:8080", // 服务器地址
		// "https://pq.cloudflareresearch.com",
		nil,
	)
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return
	}

	// 创建 HTTP 客户端，并将 config 应用到 Transport
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config, // 使用自定义的 TLS 配置
		},
	}

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("请求成功，状态码:", resp.StatusCode)
}
