package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"gopkg.in/square/go-jose.v2"
)

const (
	CF_FORWARDED_URL_HEADER = "X-CF-Forwarded-Url"
	COOKIE_TOKEN            = "_github_oauth_token"

	OAUTH_PATH          = "__oauth"
	OAUTH_CALLBACK_PATH = "__oauth/callback"
)

type AuthProxy struct {
	hostname       string
	client_id      string
	client_secret  string
	github_org     string
	github_url     string
	github_api_url string
	private_key    *rsa.PrivateKey
	backend        http.Handler
}

func NewAuthProxy(hostname, client_id, client_secret, github_org string) http.Handler {
	private_key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("key error: " + err.Error())
	}

	return &AuthProxy{
		hostname:       hostname,
		client_id:      client_id,
		client_secret:  client_secret,
		github_org:     github_org,
		github_url:     "https://github.com",
		github_api_url: "https://api.github.com",
		private_key:    private_key,
		backend:        buildBackendProxy(),
	}
}

func OverrideAuthProxy(hostname, client_id, client_secret, github_org, github_url, github_api_url string, private_key *rsa.PrivateKey) http.Handler {
	return &AuthProxy{
		hostname:       hostname,
		client_id:      client_id,
		client_secret:  client_secret,
		github_org:     github_org,
		github_url:     github_url,
		github_api_url: github_api_url,
		private_key:    private_key,
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

func newCookie(name string, value string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Secure:   true,
		HttpOnly: true,
		MaxAge:   3600,
	}
}

func delCookie(name string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    "",
		Secure:   true,
		HttpOnly: true,
		MaxAge:   -1,
	}
}

func EncryptJWE(plaintext string, key *rsa.PrivateKey) (string, error) {
	encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.RSA_OAEP, Key: &key.PublicKey}, nil)
	if err != nil {
		return "", err
	}

	obj, err := encrypter.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}

	serialised, err := obj.CompactSerialize()
	if err != nil {
		return "", err
	}

	return serialised, nil
}

func DecryptJWE(serialised string, key *rsa.PrivateKey) (string, error) {
	obj, err := jose.ParseEncrypted(serialised)
	if err != nil {
		return "", err
	}

	decrypted, err := obj.Decrypt(key)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
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

	if data["login"] == nil {
		return false, fmt.Errorf("github api error: %s", string(body))
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
	switch strings.TrimPrefix(req.URL.Path, "/") {
	case OAUTH_CALLBACK_PATH:
		// deal with response
		query := req.URL.Query()

		if query.Get("error") != "" {
			http.Error(w, "OAuth error: "+query.Get("error"), http.StatusBadRequest)
			return
		}

		code := query.Get("code")
		state := query.Get("state")

		forwardedURL, err := DecryptJWE(state, a.private_key)
		if err != nil {
			http.Error(w, "State error: "+err.Error(), http.StatusBadRequest)
			return
		}

		// get access token
		resp, err := http.PostForm(
			a.github_url+"/login/oauth/access_token",
			url.Values{
				"client_id":     {a.client_id},
				"client_secret": {a.client_secret},
				"code":          {code},
				"redirect_uri":  {fmt.Sprintf("%s/%s", a.hostname, OAUTH_CALLBACK_PATH)},
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

		encryptedToken, err := EncryptJWE(token, a.private_key)
		if err != nil {
			http.Error(w, "Error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		parsedForwardURL, err := url.Parse(forwardedURL)
		if err != nil {
			http.Error(w, "Error: "+err.Error(), http.StatusBadRequest)
			return
		}

		values = parsedForwardURL.Query()
		values.Add("__token", encryptedToken)
		parsedForwardURL.RawQuery = values.Encode()

		http.Redirect(w, req, parsedForwardURL.String(), http.StatusSeeOther)
	default:
		forwardedURL := req.Header.Get(CF_FORWARDED_URL_HEADER)

		if forwardedURL == "" {
			http.Error(w, "Missing Forwarded URL", http.StatusBadRequest)
			return
		}

		parsedForwardURL, err := url.Parse(forwardedURL)
		if err != nil {
			http.Error(w, "Invalid forward URL: "+err.Error(), http.StatusBadRequest)
			return
		}

		// if __token in query, redirect to forwarded URL with token cookie set
		if encryptedToken := parsedForwardURL.Query().Get("__token"); encryptedToken != "" {
			token, err := DecryptJWE(encryptedToken, a.private_key)
			if err != nil {
				http.Error(w, "Error: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// remove __token from query to avoid redirect loop
			values := parsedForwardURL.Query()
			values.Del("__token")
			parsedForwardURL.RawQuery = values.Encode()

			http.SetCookie(w, newCookie(COOKIE_TOKEN, token))
			http.Redirect(w, req, parsedForwardURL.String(), http.StatusSeeOther)
			return
		}

		// check if token cookie set
		token_cookie, err := req.Cookie(COOKIE_TOKEN)
		if err != nil || token_cookie.Value == "" {
			// if no cookie or bad cookie, redirect to oauth flow
			state, err := EncryptJWE(forwardedURL, a.private_key)
			if err != nil {
				http.Error(w, "Error: "+err.Error(), http.StatusInternalServerError)
				return
			}

			redirect_url := fmt.Sprintf(
				"%s/login/oauth/authorize?client_id=%s&redirect_uri=%s/%s&allow_signup=false&state=%s&scope=read:org",
				a.github_url,
				a.client_id,
				a.hostname,
				OAUTH_CALLBACK_PATH,
				state,
			)

			http.Redirect(w, req, redirect_url, http.StatusSeeOther)
			return
		}

		// check user is authorised
		member, err := a.isMember(token_cookie.Value)
		if err != nil {
			http.SetCookie(w, delCookie(COOKIE_TOKEN))
			http.Error(w, "Error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if member == false {
			message := fmt.Sprintf(
				`Unauthorised, review OAuth app permissions: %s/settings/connections/applications/%s`,
				a.github_url,
				a.client_id,
			)
			http.SetCookie(w, delCookie(COOKIE_TOKEN))
			http.Error(w, message, http.StatusUnauthorized)
			return
		}

		// if all good, redirect to original destination
		a.backend.ServeHTTP(w, req)
	}
}
