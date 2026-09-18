package http

import (
	"net"
	"pqtls_project/internal/crypto/mytls"
)

// Server 自定义的 HTTP 服务器
type Server struct {
	Addr      string
	Handler   Handler
	TLSConfig *tls.Config
}

// ListenAndServeTLS 启动 TLS 服务器
func (srv *Server) ListenAndServeTLS(certFile, keyFile string) error {
	addr := srv.Addr
	if addr == "" {
		addr = ":https"
	}

	ln, err := tls.Listen("tcp", addr, srv.TLSConfig)
	if err != nil {
		return err
	}

	return srv.Serve(ln)
}

// Serve 处理传入的连接
func (srv *Server) Serve(l net.Listener) error {
	defer l.Close()

	for {
		rw, err := l.Accept()
		if err != nil {
			return err
		}
		go srv.handleConnection(rw)
	}
}

func (srv *Server) handleConnection(c net.Conn) {
	defer c.Close()

	// 这里简化处理，实际应实现完整的 HTTP 协议
	_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"))
	if srv.Handler != nil {
		srv.Handler.ServeHTTP(newResponseWriter(c), nil)
	}
}

// Handler 处理程序接口
type Handler interface {
	ServeHTTP(ResponseWriter, *Request)
}

// ResponseWriter 响应写入器
type ResponseWriter interface {
	Write([]byte) (int, error)
}

// Request 请求结构 (简化)
type Request struct{}

// HandlerFunc 处理函数适配器
type HandlerFunc func(ResponseWriter, *Request)

func (f HandlerFunc) ServeHTTP(w ResponseWriter, r *Request) {
	f(w, r)
}

// NewResponseWriter 创建响应写入器
func newResponseWriter(c net.Conn) ResponseWriter {
	return &responseWriter{conn: c}
}

type responseWriter struct {
	conn net.Conn
}

func (rw *responseWriter) Write(p []byte) (int, error) {
	return rw.conn.Write(p)
}
