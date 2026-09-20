// tlsbench 是 TLS 协议源码库的性能测试工具：
// 进程内测量"单连接建立耗时"（握手，不含进程启动与 HTTP 开销）与并发连接建立性能。
//
// 用法（需用打补丁的 GOROOT 编译，见 docs/BUILD.md A 节）：
//
//	# 服务端（也可用 tls-hybrid/server 的程序）
//	tlsbench -mode server -addr :8099 -cert ../server/server_root_cert1.pem \
//	         -key ../server/server_root_key1.pem -kex X25519Kyber1024Draft00
//
//	# 客户端：200 次单连接（TLS-2-1/2-2/2-3）
//	tlsbench -mode client -addr localhost:8099 -kex X25519Kyber1024Draft00 -n 200
//
//	# 客户端：并发 50、共 1000 次（TLS-2-4）
//	tlsbench -mode client -addr localhost:8099 -kex X25519Kyber1024Draft00 -c 50 -n 1000
//
// HQC 组需要带 -tags pq_hqc 且链接 liboqs 构建。
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var kexByName = map[string]tls.CurveID{
	"SM2Kyber512Draft00":     tls.SM2Kyber512Draft00,
	"SM2Kyber768Draft00":     tls.SM2Kyber768Draft00,
	"SM2Kyber1024Draft00":    tls.SM2Kyber1024Draft00,
	"X25519Kyber512Draft00":  tls.X25519Kyber512Draft00,
	"X25519Kyber768Draft00":  tls.X25519Kyber768Draft00,
	"X25519Kyber1024Draft00": tls.X25519Kyber1024Draft00,
	"X25519":                 tls.X25519,
	"DummyKex":               tls.DummyKex,
	"X25519HQC-128":          tls.X25519HQC128,
	"X25519HQC-256":          tls.X25519HQC256,
	"X25519HQC1":             tls.X25519HQC128,
	"X25519HQC5":             tls.X25519HQC256,
	"SM2HQC-128":             tls.SM2HQC128,
	"SM2HQC-256":             tls.SM2HQC256,
	"SM2HQC1":                tls.SM2HQC128,
	"SM2HQC5":                tls.SM2HQC256, "X25519HQC1Draft00": tls.X25519HQC128,
	"X25519HQC5Draft00": tls.X25519HQC256,
	"SM2HQC1Draft00":    tls.SM2HQC128,
	"SM2HQC5Draft00":    tls.SM2HQC256,
}

var kexDisplayName = map[tls.CurveID]string{
	tls.SM2Kyber512Draft00:     "SM2Kyber512Draft00",
	tls.SM2Kyber768Draft00:     "SM2Kyber768Draft00",
	tls.SM2Kyber1024Draft00:    "SM2Kyber1024Draft00",
	tls.X25519Kyber512Draft00:  "X25519Kyber512Draft00",
	tls.X25519Kyber768Draft00:  "X25519Kyber768Draft00",
	tls.X25519Kyber1024Draft00: "X25519Kyber1024Draft00",
	tls.X25519HQC128:           "X25519HQC-128",
	tls.X25519HQC256:           "X25519HQC-256",
	tls.SM2HQC128:              "SM2HQC-128",
	tls.SM2HQC256:              "SM2HQC-256",
	tls.DummyKex:               "DummyKex",
	tls.X25519:                 "X25519",
}

var supportedKEX = func() []tls.CurveID {
	list := []tls.CurveID{
		tls.SM2Kyber512Draft00,
		tls.X25519Kyber512Draft00,
		tls.X25519Kyber1024Draft00,
		tls.SM2Kyber1024Draft00,
		tls.X25519Kyber768Draft00,
	}
	if tls.HQCEnabled() {
		list = append(list, tls.X25519HQC128, tls.X25519HQC256)
	}
	return append(list, tls.X25519)
}()

const kexHelp = "SM2Kyber512Draft00、X25519Kyber512Draft00、X25519Kyber768Draft00、" +
	"SM2Kyber1024Draft00、X25519Kyber1024Draft00、X25519HQC-128、X25519HQC-256、X25519"

func selectKEX(spec string) []tls.CurveID {
	if spec == "" {
		return supportedKEX
	}
	var out []tls.CurveID
	for _, name := range strings.Split(spec, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		id, ok := kexByName[name]
		if !ok {
			log.Fatalf("未知密钥交换组 %q；可选：%s", name, kexHelp)
		}
		if (id == tls.X25519HQC128 || id == tls.X25519HQC256) && !tls.HQCEnabled() {
			log.Fatalf("HQC 组需要带 -tags pq_hqc 构建并链接 liboqs；当前构建不含 HQC")
		}
		out = append(out, id)
	}
	if len(out) == 0 {
		log.Fatalf("-kex 未指定有效的密钥交换组")
	}
	return out
}

func kexNames(ids []tls.CurveID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if n, ok := kexDisplayName[id]; ok {
			out = append(out, n)
		} else {
			out = append(out, fmt.Sprintf("CurveID(%d)", uint16(id)))
		}
	}
	return out
}

// runServer 起一个仅供压测的最小 TLS 服务端。
func runServer(addr string, certFile, keyFile string, curves []tls.CurveID, payload int) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("加载证书失败: %v", err)
	}
	cfg := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		CurvePreferences: curves,
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		KeyLogWriter:     keyLogWriter(), // 设置 SSLKEYLOGFILE 时导出密钥供 Wireshark 解密
	}
	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}
	log.Printf("tlsbench 服务端监听 %s，密钥交换组: %v", addr, kexNames(curves))
	var conns int64
	buf := make([]byte, 65536)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatalf("accept: %v", err)
		}
		go func(c net.Conn) {
			defer c.Close()
			if tc, ok := c.(*tls.Conn); ok {
				if err := tc.Handshake(); err != nil {
					return
				}
			}
			atomic.AddInt64(&conns, 1)
			for i := 0; i < payload; {
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				if _, err := c.Write(buf[:n]); err != nil {
					return
				}
				i += n
			}
			if payload == 0 {
				// 保持一小会儿，便于观察并发连接与资源占用
				time.Sleep(50 * time.Millisecond)
			}
		}(conn)
	}
}

// runClient 做 n 次连接建立，c 个并发，统计耗时分布。
func runClient(addr, caFile string, verify bool, curves []tls.CurveID, n, c, payload int, timeout time.Duration) int {
	var pool *x509.CertPool
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			log.Fatalf("读取 CA 失败: %v", err)
		}
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			log.Fatalf("CA 解析失败: %s", caFile)
		}
	}
	cfg := &tls.Config{
		InsecureSkipVerify: !verify,
		RootCAs:            pool,
		CurvePreferences:   curves,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		KeyLogWriter:       keyLogWriter(), // 设置 SSLKEYLOGFILE 时导出密钥供 Wireshark 解密
	}

	log.Printf("tlsbench 客户端 -> %s，密钥交换组: %v，并发=%d，总次数=%d",
		addr, kexNames(curves), c, n)

	durs := make([]time.Duration, 0, n)
	var mu sync.Mutex
	var okCnt, errCnt int64
	var firstErr atomic.Value

	jobs := make(chan int, n)
	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)

	start := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < c; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				t0 := time.Now()
				d := net.Dialer{Timeout: timeout}
				conn, err := tls.DialWithDialer(&d, "tcp", addr, cfg)
				if err != nil {
					atomic.AddInt64(&errCnt, 1)
					firstErr.Store(err.Error())
					continue
				}
				elapsed := time.Since(t0)
				if payload > 0 {
					buf := make([]byte, payload)
					conn.SetDeadline(time.Now().Add(timeout))
					if _, err := conn.Write(buf); err != nil {
						atomic.AddInt64(&errCnt, 1)
						firstErr.Store(err.Error())
						conn.Close()
						continue
					}
					if _, err := conn.Read(buf); err != nil {
						atomic.AddInt64(&errCnt, 1)
						firstErr.Store(err.Error())
						conn.Close()
						continue
					}
				}
				conn.Close()
				mu.Lock()
				durs = append(durs, elapsed)
				mu.Unlock()
				atomic.AddInt64(&okCnt, 1)
			}
		}()
	}
	wg.Wait()
	wall := time.Since(start)

	fmt.Println("\n================ 结果 ================")
	fmt.Printf("成功 %d / 失败 %d，总墙钟耗时 %v（%.1f 连接/秒）\n",
		okCnt, errCnt, wall.Round(time.Millisecond),
		float64(okCnt)/wall.Seconds())
	if errCnt > 0 {
		if e, _ := firstErr.Load().(string); e != "" {
			fmt.Printf("失败样例: %s\n", e)
		}
	}
	if len(durs) == 0 {
		return 1
	}
	sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })
	sum := time.Duration(0)
	for _, d := range durs {
		sum += d
	}
	pct := func(p float64) time.Duration {
		idx := int(p / 100 * float64(len(durs)))
		if idx >= len(durs) {
			idx = len(durs) - 1
		}
		return durs[idx]
	}
	ms := func(d time.Duration) string { return fmt.Sprintf("%.3fms", float64(d.Microseconds())/1000) }
	fmt.Printf("握手耗时: 平均=%s 最小=%s 最大=%s P50=%s P90=%s P95=%s P99=%s\n",
		ms(sum/time.Duration(len(durs))), ms(durs[0]), ms(durs[len(durs)-1]),
		ms(pct(50)), ms(pct(90)), ms(pct(95)), ms(pct(99)))
	return 0
}

// keyLogWriter 在设置了环境变量 SSLKEYLOGFILE 时，把 TLS 会话密钥追加写入该文件，
// 便于用 Wireshark 解密抓包：Wireshark → 首选项 → Protocols → TLS →
// (Pre)-Master-Secret log filename 选择该文件。仅供测试使用。
func keyLogWriter() io.Writer {
	path := os.Getenv("SSLKEYLOGFILE")
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		log.Printf("无法打开 SSLKEYLOGFILE=%s: %v", path, err)
		return nil
	}
	return f
}

func main() {
	mode := flag.String("mode", "client", "server | client")
	addr := flag.String("addr", "localhost:8099", "server: 监听地址；client: 目标地址")
	certFile := flag.String("cert", "", "server 模式：证书文件")
	keyFile := flag.String("key", "", "server 模式：私钥文件")
	caFile := flag.String("ca", "", "client 模式：CA 证书文件（-verify 时使用）")
	verify := flag.Bool("verify", false, "client 模式：校验服务端证书")
	kex := flag.String("kex", "", "启用的密钥交换组，可用逗号分隔（默认全部）")
	n := flag.Int("n", 100, "client 模式：连接总次数")
	c := flag.Int("c", 1, "client 模式：并发连接数")
	payload := flag.Int("payload", 0, "握手后收发的字节数（0=只握手）")
	timeout := flag.Duration("timeout", 10*time.Second, "单次连接超时")
	flag.Parse()

	curves := selectKEX(*kex)
	switch *mode {
	case "server":
		if *certFile == "" || *keyFile == "" {
			log.Fatal("server 模式需要 -cert 与 -key")
		}
		runServer(*addr, *certFile, *keyFile, curves, *payload)
	case "client":
		os.Exit(runClient(*addr, *caFile, *verify, curves, *n, *c, *payload, *timeout))
	default:
		log.Fatalf("未知模式 %q（可选 server | client）", *mode)
	}
}
