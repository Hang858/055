package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"pqc-gateway/hybridcert"
)

func loadCA(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no CA certificates in %s", path)
	}
	return roots, nil
}

func newGateway(c Config) (*http.Server, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	curves, _ := selectGroups(c.KEX)
	var cert tls.Certificate
	var err error
	if c.Auth == "" || c.Auth == "ecdsa" {
		cert, err = tls.LoadX509KeyPair(c.Cert, c.Key)
		if err != nil {
			return nil, err
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, err
		}
		if time.Now().Before(leaf.NotBefore) || time.Now().After(leaf.NotAfter) {
			return nil, fmt.Errorf("server certificate is outside its validity period")
		}
	} else {
		level, _ := authLevel(c.Auth)
		cert, err = hybridcert.ServerCertificate(c.RootCA, c.Intermediates, c.Cert, c.Key, c.PQKey, level, c.ServerName)
		if err != nil {
			return nil, err
		}
	}
	tc := &tls.Config{Certificates: []tls.Certificate{cert}, CurvePreferences: curves, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
	if c.Auth != "" && c.Auth != "ecdsa" {
		level, _ := authLevel(c.Auth)
		tc.HybridAuthScheme, _ = hybridcert.Scheme(level)
		tc.SessionTicketsDisabled = true
	}
	if c.ClientCA != "" {
		if c.Auth != "" && c.Auth != "ecdsa" {
			level, _ := authLevel(c.Auth)
			tc.VerifyHybridClient, err = hybridcert.NewClientVerifier(c.ClientCA, level)
			if err != nil {
				return nil, err
			}
			tc.ClientAuth = tls.RequireAnyClientCert
		} else {
			tc.ClientCAs, err = loadCA(c.ClientCA)
			if err != nil {
				return nil, err
			}
			tc.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}
	upstreamTLS := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.UpstreamServerName}
	if c.UpstreamCA != "" {
		upstreamTLS.RootCAs, err = loadCA(c.UpstreamCA)
		if err != nil {
			return nil, err
		}
	}
	target, _ := url.Parse(c.Upstream)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			for name := range r.Out.Header {
				if strings.HasPrefix(strings.ToLower(name), "x-forwarded-") {
					r.Out.Header.Del(name)
				}
			}
			r.SetURL(target)
			r.SetXForwarded()
		},
		Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: upstreamTLS, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 60 * time.Second, IdleConnTimeout: 90 * time.Second, MaxIdleConns: 100, MaxIdleConnsPerHost: 20},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("upstream error: %v", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && r.TLS.HybridAuthScheme != 0 {
			log.Printf("TLS auth_scheme=0x%04x client_cert_verified=%t", uint16(r.TLS.HybridAuthScheme), len(r.TLS.HybridPeerCertificates) > 0)
		}
		proxy.ServeHTTP(w, r)
	})
	return &http.Server{Addr: c.Listen, Handler: handler, TLSConfig: tc, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20}, nil
}
