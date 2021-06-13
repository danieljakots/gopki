package main

import (
	"flag"
	"fmt"
)

func cli() (bool, bool) {
	create := flag.Bool("create", false, "Create a new certificate (and sign it)")
	init := flag.Bool("init", false, "Initialize a new PKI")
	flag.Parse()

	if !*create && !*init {
		flag.PrintDefaults()
	}

	if *create && *init {
		flag.PrintDefaults()
	}

	return *create, *init
}

func main() {
	create, init := cli()

	if create {
		createCertificate()
	} else if init {
		createCA()
	}
}

func createCertificate() {
	fmt.Println("create certificate")
}

func createCA() {
	fmt.Println("create ca")
}
