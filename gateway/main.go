package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var version = "dev"

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: pqc-gateway serve|check|pki|probe|demo-backend|version [options]")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	switch args[0] {
	case "version":
		fmt.Printf("pqc-gateway %s TLS=patched-Go-1.22.12 PQ=KyberDraft00 HQC=%t auth=ECDSA-P256\n", version, tls.HQCEnabled())
		return nil
	case "pki":
		out := fs.String("out", "certs", "new or empty output directory")
		hosts := fs.String("hosts", "localhost,127.0.0.1", "comma-separated SAN DNS names and IPs")
		days := fs.Int("days", 365, "leaf certificate validity in days")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if err := generatePKI(*out, *hosts, *days); err != nil {
			return err
		}
		fmt.Println("PKI generated in", *out, "(ECDSA authentication; PQ KEX is configured separately)")
		return nil
	case "serve", "check":
		path := fs.String("config", "config/gateway.json", "configuration JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		c, err := loadConfig(*path)
		if err != nil {
			return err
		}
		server, err := newGateway(c)
		if err != nil {
			return err
		}
		if args[0] == "check" {
			fmt.Println("configuration and certificates OK")
			return nil
		}
		server.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
			return context.WithValue(ctx, tls.CFEventHandlerContextKey{}, func(ev tls.CFEvent) {
				if e, ok := ev.(tls.CFEventTLS13NegotiatedKEX); ok {
					log.Printf("TLS peer=%s kex=%s", conn.RemoteAddr(), groupName(e.KEX))
				}
			})
		}
		stopCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		go func() {
			<-stopCtx.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			server.Shutdown(ctx)
		}()
		log.Printf("gateway listen=%s upstream=%s kex=%v", c.Listen, c.Upstream, c.KEX)
		err = server.ListenAndServeTLS("", "")
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case "probe":
		addr := fs.String("url", "https://localhost:8443/", "HTTPS gateway URL")
		ca := fs.String("ca", "certs/ca.crt", "trusted gateway CA")
		kex := fs.String("kex", "SM2Kyber512Draft00", "comma-separated PQ groups")
		serverName := fs.String("server-name", "", "override TLS certificate DNS name (SNI)")
		cert := fs.String("cert", "", "optional mTLS client certificate")
		key := fs.String("key", "", "optional mTLS client key")
		data := fs.String("data", "", "POST body (default GET)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		u, err := url.Parse(*addr)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return fmt.Errorf("probe URL must be https without credentials")
		}
		roots, err := loadCA(*ca)
		if err != nil {
			return err
		}
		curves, err := selectGroups(strings.Split(*kex, ","))
		if err != nil {
			return err
		}
		tc := &tls.Config{RootCAs: roots, ServerName: *serverName, CurvePreferences: curves, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
		if *cert != "" || *key != "" {
			c, err := tls.LoadX509KeyPair(*cert, *key)
			if err != nil {
				return err
			}
			tc.Certificates = []tls.Certificate{c}
		}
		transport := &http.Transport{TLSClientConfig: tc}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
		var negotiated bool
		ctx := context.WithValue(context.Background(), tls.CFEventHandlerContextKey{}, func(ev tls.CFEvent) {
			if e, ok := ev.(tls.CFEventTLS13NegotiatedKEX); ok {
				negotiated = true
				fmt.Fprintln(os.Stderr, "negotiated_kex="+groupName(e.KEX))
			}
		})
		method := "GET"
		if *data != "" {
			method = "POST"
		}
		req, err := http.NewRequestWithContext(ctx, method, *addr, strings.NewReader(*data))
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if !negotiated || resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 {
			return fmt.Errorf("PQ TLS 1.3 negotiation was not observed")
		}
		fmt.Fprintln(os.Stderr, "http_status=", resp.StatusCode, "certificate_verified=true")
		if _, err = io.Copy(os.Stdout, io.LimitReader(resp.Body, 1<<20)); err != nil {
			return err
		}
		if resp.StatusCode >= 400 {
			return fmt.Errorf("HTTP status %d", resp.StatusCode)
		}
		return nil
	case "demo-backend":
		addr := fs.String("listen", "127.0.0.1:9000", "demo HTTP backend (loopback only recommended)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		server := &http.Server{Addr: *addr, ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintf(w, "factory-backend-ok method=%s path=%s\n", r.Method, r.URL.RequestURI())
			io.Copy(w, io.LimitReader(r.Body, 1<<20))
		})}
		log.Println("demo backend", *addr)
		return server.ListenAndServe()
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
