package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
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

func getKey() (string, error) {
	fmt.Println("Enter the CA private key")
	var key string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		key += scanner.Text()
		key += "\n"
		if strings.Contains(key, "-----END RSA PRIVATE KEY-----") {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}
	return key, nil
}

func createCertificate() {
	name := "localhost"
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2020),
		Subject: pkix.Name{
			Organization: []string{"Jean Canard cult."},
			Country:      []string{"CA"},
			Province:     []string{"Quebec"},
			Locality:     []string{"Montreal"},
		},
		DNSNames:     []string{name},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageAny},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
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
		log.Fatal(err)
	}
	caPrivateKey, err := getKey()
	if err != nil {
		log.Fatal(err)
	}
	block, _ = pem.Decode([]byte(caPrivateKey))
	caPK, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca,
		&privateKey.PublicKey, caPK)
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
			Organization: []string{"Jean Canard cult."},
			Country:      []string{"CA"},
			Province:     []string{"Quebec"},
			Locality:     []string{"Montreal"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		IsCA:      true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageAny},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	buffy := new(bytes.Buffer)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
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
	fmt.Println("Save the key, you'll need it to create a certificate")
	fmt.Print(buffy)
	fmt.Println("Save the key, you'll need it to create a certificate")

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
