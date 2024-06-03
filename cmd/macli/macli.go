package main

import (
	"flag"

	"github.com/costinm/meshauth/cmd"
)


func main() {
	flag.Parse()
	c := flag.Arg(0)

	command := cmd.Commands[c]
	command()
}
