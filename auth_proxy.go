package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

const (
	CF_FORWARDED_URL_HEADER = "X-CF-Forwarded-Url"
)

type AuthProxy struct {
	username string
	password string
	backend  http.Handler
}

func NewAuthProxy(username, password string) http.Handler {
	return &AuthProxy{
		username: username,
		password: password,
		backend:  buildBackendProxy(),
	}
}

func buildBackendProxy() http.Handler {
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			forwardedURL := req.Header.Get(CF_FORWARDED_URL_HEADER)
			if forwardedURL == "" {
				// This should never happen due to the check in AuthProxy.ServeHTTP
				panic("missing forwarded URL")
			}
			url, err := url.Parse(forwardedURL)
			if err != nil {
				// This should never happen due to the check in AuthProxy.ServeHTTP
				panic("Invalid forwarded URL: " + err.Error())
			}

			req.URL = url
			req.Host = url.Host
		},
	}
}

func (a *AuthProxy) checkAuth(user, pass string) bool {
	return user == a.username && pass == a.password
}

func (a *AuthProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	user, pass, ok := req.BasicAuth()
	if !ok || !a.checkAuth(user, pass) {
		w.Header().Set("WWW-Authenticate", `Basic realm="auth"`)
		http.Error(w, "Unauthorized.", http.StatusUnauthorized)
		return
	}

	forwardedURL := req.Header.Get(CF_FORWARDED_URL_HEADER)
	if forwardedURL == "" {
		http.Error(w, "Missing Forwarded URL", http.StatusBadRequest)
		return
	}
	_, err := url.Parse(forwardedURL)
	if err != nil {
		http.Error(w, "Invalid forward URL: "+err.Error(), http.StatusBadRequest)
		return
	}

	a.backend.ServeHTTP(w, req)
}
