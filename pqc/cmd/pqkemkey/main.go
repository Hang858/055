// pqkemkey generates a raw KEM key pair through the pqc registry.
package main

import (
	"flag"
	"fmt"
	"os"

	"pqc"
)

func main() {
	algName := flag.String("alg", "PLACEHOLDER-KEM", "KEM algorithm name")
	out := flag.String("out", "", "output prefix; writes <out>.priv and <out>.pub")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "FAIL: -out is required")
		os.Exit(2)
	}
	alg, err := pqc.Lookup(*algName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(2)
	}
	if alg.Kind() != pqc.KindKEM {
		fmt.Fprintf(os.Stderr, "FAIL: %s is not a KEM\n", *algName)
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
	fmt.Printf("%s pub=%d priv=%d ct=%d ss=%d\n",
		alg.Name(), alg.PublicKeySize(), alg.PrivateKeySize(), alg.CiphertextSize(), alg.SharedSecretSize())
}
