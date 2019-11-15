package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
)

const (
	CF_FORWARDED_URL_HEADER = "X-CF-Forwarded-Url"
	ROUTE_SERVICE_TOKEN     = "X-GitHub-Token"
	COOKIE_STATE            = "_github_oauth_state"
	COOKIE_TOKEN            = "_github_oauth_token"
	COOKIE_FWD              = "_github_oauth_forward"

	OAUTH_PATH          = "/__oauth"
	OAUTH_CALLBACK_PATH = "/__oauth/callback"
)

type AuthProxy struct {
	hostname       string
	client_id      string
	client_secret  string
	github_org     string
	github_url     string
	github_api_url string
	backend        http.Handler
}

func NewAuthProxy(hostname, client_id, client_secret, github_org string) http.Handler {
	return &AuthProxy{
		hostname:       hostname,
		client_id:      client_id,
		client_secret:  client_secret,
		github_org:     github_org,
		github_url:     "https://github.com",
		github_api_url: "https://api.github.com",
		backend:        buildBackendProxy(),
	}
}

func OverrideAuthProxy(hostname, client_id, client_secret, github_org, github_url, github_api_url string) http.Handler {
	return &AuthProxy{
		hostname:       hostname,
		client_id:      client_id,
		client_secret:  client_secret,
		github_org:     github_org,
		github_url:     github_url,
		github_api_url: github_api_url,
		backend:        buildBackendProxy(),
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

func randomHex(n int) (string, error) {
	//-- https://sosedoff.com/2014/12/15/generate-random-hex-string-in-go.html
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func setCookie(w http.ResponseWriter, name string, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Secure:   true,
		HttpOnly: true,
		MaxAge:   3600,
	})
}

func unsetCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Secure:   true,
		HttpOnly: true,
		MaxAge:   -1,
	})
}

func (a *AuthProxy) isMember(token string) (bool, error) {
	client := &http.Client{}

	// get login
	user_req, err := http.NewRequest("GET", a.github_api_url+"/user", nil)
	user_req.SetBasicAuth("bearer", token)
	resp, err := client.Do(user_req)

	if err != nil {
		return false, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return false, err
	}

	var data map[string]interface{}

	if err := json.Unmarshal(body, &data); err != nil {
		return false, err
	}

	user := data["login"].(string)

	// check user is in right org
	member_url := fmt.Sprintf("%s/orgs/%s/members/%s", a.github_api_url, a.github_org, user)
	member_req, err := http.NewRequest("GET", member_url, nil)
	member_req.SetBasicAuth("bearer", token)
	resp, err = client.Do(member_req)

	if err != nil {
		return false, err
	}

	return (resp.StatusCode == 204), nil
}

func (a *AuthProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch req.URL.Path {
	case OAUTH_PATH:
		// redirect to oauth provider
		state, err := randomHex(16)
		if err != nil {
			http.Error(w, "Error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		redirect_url := fmt.Sprintf(
			"%s/login/oauth/authorize?client_id=%s&redirect_uri=%s/oauth/callback&allow_signup=false&state=%s&scope=read:org",
			a.github_url,
			a.client_id,
			a.hostname,
			state,
		)

		setCookie(w, COOKIE_STATE, state)
		http.Redirect(w, req, redirect_url, http.StatusSeeOther)
	case OAUTH_CALLBACK_PATH:
		// deal with response
		query := req.URL.Query()

		if query.Get("error") != "" {
			http.Error(w, "OAuth error: "+query.Get("error"), http.StatusBadRequest)
			return
		}

		state_cookie, err := req.Cookie(COOKIE_STATE)

		if err != nil {
			http.Error(w, "Cookie error: "+err.Error(), http.StatusBadRequest)
			return
		}

		code := query.Get("code")
		state := query.Get("state")

		if state != state_cookie.Value {
			http.Error(w, fmt.Sprintf("State mismatch: %s %s", state, state_cookie.Value), http.StatusBadRequest)
			return
		}

		// get access token
		resp, err := http.PostForm(
			a.github_url+"/login/oauth/access_token",
			url.Values{
				"client_id":     {a.client_id},
				"client_secret": {a.client_secret},
				"code":          {code},
				"redirect_uri":  {a.hostname + OAUTH_CALLBACK_PATH},
				"state":         {state},
			},
		)

		if err != nil {
			http.Error(w, "Error: "+err.Error(), http.StatusBadRequest)
			return
		}

		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)

		if err != nil {
			http.Error(w, "Error: "+err.Error(), http.StatusBadRequest)
			return
		}

		values, err := url.ParseQuery(string(body))

		if err != nil {
			http.Error(w, "Error: "+err.Error(), http.StatusBadRequest)
			return
		}

		token := values.Get("access_token")

		if token == "" {
			http.Error(w, "OAuth token error: "+string(body), http.StatusBadRequest)
			return
		}

		fwd_cookie, err := req.Cookie(COOKIE_FWD)
		if err != nil {
			http.Error(w, "Error: "+err.Error(), http.StatusBadRequest)
			return
		}

		setCookie(w, COOKIE_TOKEN, token)
		unsetCookie(w, COOKIE_FWD)
		http.Redirect(w, req, fwd_cookie.Value, http.StatusSeeOther)
	default:
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

		// check token cookie
		token_cookie, err := req.Cookie(COOKIE_TOKEN)

		if err != nil || token_cookie.Value == "" {
			setCookie(w, COOKIE_FWD, forwardedURL)
			http.Redirect(w, req, "/oauth", http.StatusSeeOther)
			return
		}

		// check user is authorised
		member, err := a.isMember(token_cookie.Value)

		if err != nil {
			http.Error(w, "Error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if member == false {
			http.Error(w, "Unauthorised", http.StatusUnauthorized)
			return
		}

		// forward to downstream with token
		req.Header.Add(ROUTE_SERVICE_TOKEN, token_cookie.Value)
		a.backend.ServeHTTP(w, req)
	}
}
