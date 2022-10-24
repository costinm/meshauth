package main

import (
	"flag"
	"os"
	"path/filepath"

	"github.com/costinm/meshauth"
)

var (
	ns  = flag.String("n", "default", "namespace")
	ksa = flag.String("ksa", "default", "kubernetes service account")
)

func main() {
	home, _ := os.UserHomeDir()
	ca := meshauth.CAFromEnv(filepath.Join(home, ".ssh"))

	meshid := ca.NewID(*ns, *ksa)
	meshid.SaveCerts(".")
}
