// pqclist prints the single registry.  It is the operator-facing proof that
// signature and KEM algorithms are managed through one entry.
package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"pqc"
)

func main() {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tKIND\tTLS\tOID\tVERSION\tAVAILABLE")
	for _, a := range pqc.All() {
		fmt.Fprintf(w, "%s\t%d\t0x%04x\t%s\t%s\t%t\n",
			a.Name(), a.Kind(), a.TLSCode(), a.OID().String(), a.Version(), a.Available())
	}
	_ = w.Flush()
}
