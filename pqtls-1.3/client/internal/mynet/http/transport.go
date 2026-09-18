package http

import (
	"pqtls_project/internal/crypto/mytls"
)

// Transport 自定义的 HTTP 传输
type Transport struct {
	TLSClientConfig *tls.Config
}

// Client 自定义的 HTTP 客户端
type Client struct {
	Transport *Transport
}

// Get 发送 GET 请求
func (c *Client) Get(url string) (*Response, error) {
	// 简化实现，实际应解析 URL 并建立连接
	conn, err := tls.Dial("tcp", "localhost:8443", c.Transport.TLSClientConfig)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 发送请求
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	if err != nil {
		return nil, err
	}

	// 读取响应 (简化)
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return &Response{
		StatusCode: 200,
		Body:       buf[:n],
	}, nil
}

// Response HTTP 响应
type Response struct {
	StatusCode int
	Body       []byte
}
