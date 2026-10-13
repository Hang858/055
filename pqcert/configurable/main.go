package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

var version = "development"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: pqc-certtool version|algorithms|check|generate|verify；后三项须指定 -config 文件")
	}
	switch args[0] {
	case "version":
		if len(args) != 1 {
			return fmt.Errorf("version不接受其他参数")
		}
		fmt.Println("pqc-certtool", version, "linux/amd64 configuration-schema=1")
		return nil
	case "algorithms":
		if len(args) != 1 {
			return fmt.Errorf("algorithms不接受其他参数")
		}
		return output(map[string]any{"signature": signatureNames, "kem": kemNames, "traditional": []string{"SM2", "RSA-2048"}, "modes": []string{"pure-pq", "sm2-hybrid", "rsa-hybrid", "sm2"}})
	case "check", "generate", "verify":
		fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
		path := fs.String("config", "", "JSON配置文件")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *path == "" || fs.NArg() != 0 {
			return fmt.Errorf("必须指定 -config 配置文件，且不能附带位置参数")
		}
		c, err := loadConfig(*path)
		if err != nil {
			return err
		}
		if args[0] == "check" {
			return output(map[string]any{"valid": true, "mode": c.Mode, "output_dir": c.OutputDir})
		}
		var report Report
		if args[0] == "generate" {
			report, err = generate(c)
		} else {
			report, err = verify(c, c.OutputDir)
		}
		if err != nil {
			return err
		}
		return output(report)
	default:
		return fmt.Errorf("未知命令: %s", args[0])
	}
}
func output(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
