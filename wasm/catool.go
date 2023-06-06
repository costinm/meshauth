package main

import "github.com/costinm/meshauth"

func main() {
	ma := meshauth.NewCA("cluster.local")
	ma.NewID("default", "default")
}
