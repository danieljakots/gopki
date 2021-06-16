package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"os"
	"time"
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
	name := "localhost"
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Jean Canard cult."},
			Country:       []string{"CA"},
			Province:      []string{"Quebec"},
			Locality:      []string{"Montreal"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		DNSNames:     []string{name},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	buffy := new(bytes.Buffer)
	err = pem.Encode(buffy, block)
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile(name+".key", buffy.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}

	caBytes, err := os.ReadFile("ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	caBlock, _ := pem.Decode(caBytes)
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		log.Fatal("parse ", err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca,
		&privateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatal(err)
	}

	err = pem.Encode(buffy, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile(name+".crt", buffy.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func createCA() {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Jean Canard cult."},
			Country:       []string{"CA"},
			Province:      []string{"Quebec"},
			Locality:      []string{"Montreal"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	buffy := new(bytes.Buffer)

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}
	err = pem.Encode(buffy, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile("ca.key", buffy.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}

	buffy = new(bytes.Buffer)

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca,
		&privateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatal(err)
	}

	err = pem.Encode(buffy, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile("ca.crt", buffy.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}
}
