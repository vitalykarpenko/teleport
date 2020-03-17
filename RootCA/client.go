package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	client := &http.Client{}

	// Create a pool with the server certificate since it is not signed
	// by a known CA
	caCert, err := ioutil.ReadFile("./rootCA.crt")
	if err != nil {
		log.Fatalf("Reading server certificate: %s", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create TLS configuration with the certificate of the server
	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}
	_ = tlsConfig
	// Use the proper transport in the client
	client.Transport = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	// Perform the request
	resp, err := client.Post("https://detlis.com:9191/hello/sayHello", "text/plain", bytes.NewBufferString("Hello Go!"))
	if err != nil {
		log.Fatalf("Failed get: %s", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed reading response body: %s", err)
	}
	fmt.Printf("Got response %d: %s %s", resp.StatusCode, resp.Proto, string(body))
}
