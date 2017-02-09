package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
)

func main() {
	addr := ":" + os.Getenv("PORT")

	username := os.Getenv("AUTH_USERNAME")
	password := os.Getenv("AUTH_PASSWORD")

	if username == "" || password == "" {
		log.Fatal("Must provide auth creds in AUTH_USERNAME and AUTH_PASSWORD")
	}

	if os.Getenv("SKIP_SSL_VALIDATION") != "" {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	proxy := NewAuthProxy(username, password)

	err := http.ListenAndServe(addr, proxy)
	if err != nil {
		log.Fatal(err)
	}
}
