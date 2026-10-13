package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type NodeConfig struct {
	Name          string   `json:"name"`
	CommonName    string   `json:"common_name"`
	Algorithm     string   `json:"algorithm"`
	ValidDays     int      `json:"valid_days"`
	PublicKeyFile string   `json:"public_key_file,omitempty"`
	DNSNames      []string `json:"dns_names,omitempty"`
	IPAddresses   []string `json:"ip_addresses,omitempty"`
	TLSUsage      string   `json:"tls_usage,omitempty"`
}
type Config struct {
	SchemaVersion int          `json:"schema_version"`
	Mode          string       `json:"mode"`
	OutputDir     string       `json:"output_dir"`
	Root          NodeConfig   `json:"root"`
	Intermediates []NodeConfig `json:"intermediates"`
	Leaves        []NodeConfig `json:"leaves"`
}

var configField = regexp.MustCompile(`^[a-z_]+$`)

var fileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

func loadConfig(path string) (Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if len(data) > 1024*1024 {
		return c, fmt.Errorf("配置文件超过1 MiB")
	}
	if err = uniqueJSON(json.NewDecoder(bytes.NewReader(data))); err != nil {
		return c, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&c); err != nil {
		return c, fmt.Errorf("配置解析失败: %w", err)
	}
	if dec.Decode(new(any)) != io.EOF {
		return c, fmt.Errorf("配置后有多余JSON内容")
	}
	base, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return c, err
	}
	if c.OutputDir != "" && !filepath.IsAbs(c.OutputDir) {
		c.OutputDir = filepath.Join(base, c.OutputDir)
	}
	if c.OutputDir != "" {
		c.OutputDir = filepath.Clean(c.OutputDir)
	}
	for i := range c.Leaves {
		if p := c.Leaves[i].PublicKeyFile; p != "" && !filepath.IsAbs(p) {
			c.Leaves[i].PublicKeyFile = filepath.Join(base, p)
		}
	}
	return c, validateConfig(c)
}
func uniqueJSON(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				s, ok := key.(string)
				if !ok {
					return fmt.Errorf("无效JSON键")
				}
				if !configField.MatchString(s) {
					return fmt.Errorf("配置字段必须按示例使用小写名称: %s", s)
				}
				if seen[s] {
					return fmt.Errorf("重复配置字段: %s", s)
				}
				seen[s] = true
				if err := uniqueJSON(d); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := uniqueJSON(d); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("无效JSON结构")
		}
		_, err = d.Token()
		return err
	}
	return nil
}
func validateConfig(c Config) error {
	if c.SchemaVersion != 1 {
		return fmt.Errorf("schema_version 必须为1")
	}
	switch c.Mode {
	case "pure-pq", "sm2-hybrid", "rsa-hybrid", "sm2":
	default:
		return fmt.Errorf("未知mode: %s", c.Mode)
	}
	if c.OutputDir == "" || c.OutputDir == "/" {
		return fmt.Errorf("output_dir 必须为独立的新目录")
	}
	if len(c.Intermediates) > 4 || len(c.Leaves) < 1 || len(c.Leaves) > 64 {
		return fmt.Errorf("允许0至4级中间CA及1至64个用户证书")
	}
	names := map[string]bool{}
	nodes := append([]NodeConfig{c.Root}, c.Intermediates...)
	nodes = append(nodes, c.Leaves...)
	parentDays := c.Root.ValidDays
	for i, n := range nodes {
		if !fileName.MatchString(n.Name) || names[n.Name] {
			return fmt.Errorf("name无效或重复: %s", n.Name)
		}
		names[n.Name] = true
		if strings.TrimSpace(n.CommonName) == "" || len(n.CommonName) > 256 || strings.ContainsAny(n.CommonName, "\x00\r\n") {
			return fmt.Errorf("common_name无效: %s", n.Name)
		}
		if n.ValidDays < 1 || n.ValidDays > 36500 {
			return fmt.Errorf("valid_days范围为1至36500: %s", n.Name)
		}
		isCA := i <= len(c.Intermediates)
		if n.TLSUsage != "" || len(n.DNSNames) != 0 || len(n.IPAddresses) != 0 {
			if isCA || c.Mode != "sm2-hybrid" {
				return fmt.Errorf("TLS身份字段仅适用于SM2混合模式的用户证书: %s", n.Name)
			}
			if n.TLSUsage != "server" && n.TLSUsage != "client" {
				return fmt.Errorf("tls_usage必须为server或client: %s", n.Name)
			}
			if n.TLSUsage == "server" && len(n.DNSNames)+len(n.IPAddresses) == 0 {
				return fmt.Errorf("TLS服务端证书必须配置DNS或IP SAN: %s", n.Name)
			}
			if len(n.DNSNames)+len(n.IPAddresses) > 32 {
				return fmt.Errorf("TLS SAN超过32项: %s", n.Name)
			}
			for _, name := range n.DNSNames {
				if !validDNSName(name) {
					return fmt.Errorf("无效TLS DNS名称: %s", name)
				}
			}
			for _, ip := range n.IPAddresses {
				if net.ParseIP(ip) == nil {
					return fmt.Errorf("无效TLS IP地址: %s", ip)
				}
			}
		}
		if i > 0 && n.ValidDays > parentDays {
			return fmt.Errorf("证书有效期不能超过签发者: %s", n.Name)
		}
		if isCA {
			if n.PublicKeyFile != "" {
				return fmt.Errorf("仅用户证书可导入公钥")
			}
			parentDays = n.ValidDays
		}
		if c.Mode == "sm2" {
			if n.Algorithm != "SM2" {
				return fmt.Errorf("sm2模式算法必须为SM2")
			}
		} else {
			a, ok := algorithm(n.Algorithm)
			if !ok {
				return fmt.Errorf("不支持算法: %s", n.Algorithm)
			}
			if isCA && a.Sign == nil {
				return fmt.Errorf("CA必须使用签名算法: %s", n.Name)
			}
		}
		if n.PublicKeyFile != "" {
			if _, err := importPublic(n.Algorithm, n.PublicKeyFile); err != nil {
				return fmt.Errorf("%s导入公钥失败: %w", n.Name, err)
			}
		}
	}
	return nil
}

func validDNSName(name string) bool {
	if len(name) < 1 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) < 1 || len(label) > 63 {
			return false
		}
		for i, c := range label {
			letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
			digit := c >= '0' && c <= '9'
			if !letter && !digit && !(c == '-' && i > 0 && i < len(label)-1) {
				return false
			}
		}
	}
	return true
}
