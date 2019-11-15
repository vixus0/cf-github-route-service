package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
)

func main() {
	addr := ":" + os.Getenv("PORT")

	hostname := os.Getenv("HOSTNAME")
	client_id := os.Getenv("CLIENT_ID")
	client_secret := os.Getenv("CLIENT_SECRET")
	github_org := os.Getenv("GITHUB_ORG")

	if hostname == "" || client_id == "" || client_secret == "" || github_org == "" {
		log.Fatal("Must provide HOSTNAME, CLIENT_ID, CLIENT_SECRET and GITHUB_ORG")
	}

	if os.Getenv("SKIP_SSL_VALIDATION") != "" {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	proxy := NewAuthProxy(hostname, client_id, client_secret, github_org)

	err := http.ListenAndServe(addr, proxy)
	if err != nil {
		log.Fatal(err)
	}
}
