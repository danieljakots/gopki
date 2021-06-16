// Copyright (c) 2021 Daniel Jakots

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

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

func cli() (bool, bool, string) {
	create := flag.Bool("create", false, "Create a new certificate (and sign it)")
	init := flag.Bool("init", false, "Initialize a new PKI")
	domain := flag.String("domain", "", "Domain to create a certificate for")
	flag.Parse()

	if !*create && !*init {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *create && *init {
		flag.PrintDefaults()
		os.Exit(1)
	}
	if *init && *domain != "" {
		fmt.Println("Why did you supply a domain?")
		flag.PrintDefaults()
		os.Exit(1)
	}
	if *create && *domain == "" {
		fmt.Println("Domain is missing")
		flag.PrintDefaults()
		os.Exit(1)
	}

	return *create, *init, *domain
}

func main() {
	create, init, domain := cli()

	if create {
		createCertificate(domain)
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

func createRSAKey(name string) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	buffy := new(bytes.Buffer)
	err = pem.Encode(buffy, block)
	if err != nil {
		return nil, err
	}
	if name != "" {
		err = os.WriteFile(name+".key", buffy.Bytes(), 0644)
		if err != nil {
			return nil, err
		}
	} else {
		fmt.Println("Save the key, you'll need it to create a certificate")
		fmt.Print(buffy)
		fmt.Println("Save the key, you'll need it to create a certificate")
	}
	return privateKey, nil
}

func writeCert(name string, certBytes []byte) error {
	buffy := new(bytes.Buffer)
	err := pem.Encode(buffy, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return err
	}

	err = os.WriteFile(name+".crt", buffy.Bytes(), 0644)
	if err != nil {
		return err
	}
	return nil
}

func confirmCert(certBytes []byte, ca *x509.Certificate) error {
	c, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return err
	}
	err = c.CheckSignatureFrom(ca)
	if err != nil {
		return err
	}
	return nil
}

func createCertificate(name string) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization: []string{"Jean Canard cult."},
			Country:      []string{"CA"},
			Province:     []string{"Quebec"},
			Locality:     []string{"Montreal"},
			CommonName:   name,
		},
		DNSNames:     []string{name},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageAny},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}

	pk, err := createRSAKey(name)
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
	block, _ := pem.Decode([]byte(caPrivateKey))
	caPK, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca,
		&pk.PublicKey, caPK)
	if err != nil {
		log.Fatal(err)
	}

	err = confirmCert(certBytes, ca)
	if err != nil {
		log.Fatal(err)
	}

	err = writeCert(name, certBytes)
	if err != nil {
		log.Fatal(err)
	}
}

func createCA() {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization: []string{"Jean Canard cult."},
			Country:      []string{"CA"},
			Province:     []string{"Quebec"},
			Locality:     []string{"Montreal"},
			CommonName:   "ca.chown.me",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		IsCA:      true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageAny},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	pk, err := createRSAKey("")
	if err != nil {
		log.Fatal(err)
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca,
		&pk.PublicKey, pk)
	if err != nil {
		log.Fatal(err)
	}

	err = writeCert("ca", caBytes)
	if err != nil {
		log.Fatal(err)
	}
}
