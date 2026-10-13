package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
)

type Config struct {
	Listen             string   `json:"listen"`
	Upstream           string   `json:"upstream"`
	Cert               string   `json:"cert"`
	Key                string   `json:"key"`
	KEX                []string `json:"kex"`
	UpstreamCA         string   `json:"upstream_ca,omitempty"`
	UpstreamServerName string   `json:"upstream_server_name,omitempty"`
	ClientCA           string   `json:"client_ca,omitempty"`
}

var groups = map[string]tls.CurveID{
	"SM2Kyber512Draft00":     tls.SM2Kyber512Draft00,
	"SM2Kyber768Draft00":     tls.SM2Kyber768Draft00,
	"SM2Kyber1024Draft00":    tls.SM2Kyber1024Draft00,
	"X25519Kyber512Draft00":  tls.X25519Kyber512Draft00,
	"X25519Kyber768Draft00":  tls.X25519Kyber768Draft00,
	"X25519Kyber1024Draft00": tls.X25519Kyber1024Draft00,
	"X25519HQC-128":          tls.X25519HQC128,
	"X25519HQC-256":          tls.X25519HQC256,
	"SM2HQC-128":             tls.SM2HQC128,
	"SM2HQC-256":             tls.SM2HQC256,
}

func selectGroups(names []string) ([]tls.CurveID, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("kex must contain at least one PQ group")
	}
	out := make([]tls.CurveID, 0, len(names))
	for _, name := range names {
		id, ok := groups[name]
		if !ok {
			return nil, fmt.Errorf("unsupported PQ group %q", name)
		}
		if (id == tls.X25519HQC128 || id == tls.X25519HQC256 || id == tls.SM2HQC128 || id == tls.SM2HQC256) && !tls.HQCEnabled() {
			return nil, fmt.Errorf("HQC requires a pq_hqc build linked with liboqs")
		}
		out = append(out, id)
	}
	return out, nil
}

func groupName(id tls.CurveID) string {
	for name, value := range groups {
		if value == id {
			return name
		}
	}
	return fmt.Sprintf("0x%04x", uint16(id))
}

func (c Config) validate() error {
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	u, err := url.Parse(c.Upstream)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return fmt.Errorf("upstream must be an http(s) URL without credentials, query or fragment")
	}
	if c.Cert == "" || c.Key == "" {
		return fmt.Errorf("cert and key are required")
	}
	if _, err := selectGroups(c.KEX); err != nil {
		return err
	}
	return nil
}

func loadConfig(path string) (Config, error) {
	var c Config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return c, fmt.Errorf("config contains trailing data")
	}
	for _, p := range []*string{&c.Cert, &c.Key, &c.UpstreamCA, &c.ClientCA} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(filepath.Dir(path), *p)
		}
	}
	return c, c.validate()
}
