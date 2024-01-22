package main

import "github.com/costinm/meshauth"

func main() {
	ma := meshauth.NewTempCA("cluster.local")
	ma.NewID("default", "default", nil)
}
