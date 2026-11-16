// pqkey generates raw pqsig key pairs for the TLS/KEMTLS test harnesses.
package main

import (
	"flag"
	"fmt"
	"os"

	pqsig "pqsig"
)

func main() {
	algName := flag.String("alg", "Dilithium2", "signature algorithm name")
	out := flag.String("out", "", "output prefix; writes <out>.priv and <out>.pub")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "FAIL: -out is required")
		os.Exit(2)
	}
	alg, ok := pqsig.ByName(*algName)
	if !ok {
		fmt.Fprintf(os.Stderr, "FAIL: unknown algorithm %q\n", *algName)
		os.Exit(2)
	}
	kp, err := alg.GenerateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out+".priv", kp.Private.Raw, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out+".pub", kp.Public.Raw, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%s pub=%d priv=%d sig=%d\n", alg.Name(), alg.PublicKeySize(), alg.PrivateKeySize(), alg.SignatureSize())
}
