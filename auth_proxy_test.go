package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
)

func TestAuthProxy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "test suite")
}

var _ = Describe("GitHub OAuth proxy", func() {

	var (
		hostname      string = "http://proxy.example.com"
		client_id     string = "client"
		client_secret string = "secret"
		github_org    string = "coolorg"
		proxy         http.Handler
		github        *ghttp.Server
		backend       *ghttp.Server
		req           *http.Request
		response      *httptest.ResponseRecorder
		private_key   *rsa.PrivateKey
	)

	BeforeEach(func() {
		github = ghttp.NewServer()
		backend = ghttp.NewServer()
		backend.AllowUnhandledRequests = true
		backend.UnhandledRequestStatusCode = http.StatusOK
		private_key, _ = rsa.GenerateKey(rand.Reader, 1024)
		proxy = OverrideAuthProxy(hostname, client_id, client_secret, github_org, github.URL(), github.URL(), private_key)
	})

	AfterEach(func() {
		github.Close()
		backend.Close()
	})

	Context("with a request to the oauth callback endpoint from github", func() {
		BeforeEach(func() {
			state, _ := EncryptJWE(backend.URL(), private_key)

			github.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("POST", "/login/oauth/access_token"),
					ghttp.VerifyForm(url.Values{
						"client_id":     {client_id},
						"client_secret": {client_secret},
						"code":          {"123456"},
						"redirect_uri":  {fmt.Sprintf("%s/%s", hostname, OAUTH_CALLBACK_PATH)},
						"state":         {state},
					}),
					ghttp.RespondWith(http.StatusOK, `access_token=token&token_type=bearer`),
				),
			)

			callback_url := fmt.Sprintf("%s/%s?state=%s&code=123456", hostname, OAUTH_CALLBACK_PATH, state)
			req = httptest.NewRequest("GET", callback_url, nil)
		})

		JustBeforeEach(func() {
			response = httptest.NewRecorder()
			proxy.ServeHTTP(response, req)
		})

		It("should redirect the user with the token in the querystring", func() {
			Expect(response.Code).To(Equal(http.StatusSeeOther))
			location := response.Header().Get("Location")
			location_url, _ := url.Parse(location)
			backend_url, _ := url.Parse(backend.URL())
			token, _ := DecryptJWE(location_url.Query().Get("__token"), private_key)
			Expect(location_url.Scheme).To(Equal(backend_url.Scheme))
			Expect(location_url.Host).To(Equal(backend_url.Host))
			Expect(location_url.Path).To(Equal(backend_url.Path))
			Expect(token).To(Equal("token"))
		})
	})

	Context("with a redirect from the callback", func() {
		var (
			forwarded_url       *url.URL
			forwarded_url_token *url.URL
		)

		BeforeEach(func() {
			forwarded_url, _ = url.Parse(backend.URL() + "/test?a=b")
			forwarded_url_token, _ = url.Parse(backend.URL() + "/test?a=b")
			enc_token, _ := EncryptJWE("token", private_key)
			values := forwarded_url_token.Query()
			values.Set("__token", enc_token)
			forwarded_url_token.RawQuery = values.Encode()
			req = httptest.NewRequest("GET", forwarded_url_token.String(), nil)
			req.Header.Set("X-CF-Forwarded-Url", forwarded_url_token.String())
			req.Header.Set("X-CF-Proxy-Signature", "Stub signature")
			req.Header.Set("X-CF-Proxy-Metadata", "Stub metadata")
		})

		JustBeforeEach(func() {
			response = httptest.NewRecorder()
			proxy.ServeHTTP(response, req)
		})

		It("should redirect to forwarded URL without token", func() {
			Expect(response.Code).To(Equal(http.StatusSeeOther))
			Expect(response.Header().Get("Location")).To(Equal(forwarded_url.String()))
		})

		It("should set the token cookie", func() {
			Expect(response.Header().Get("Set-Cookie")).To(ContainSubstring(COOKIE_TOKEN + "=token"))
		})
	})

	Context("with a request from route-services", func() {
		BeforeEach(func() {
			req = httptest.NewRequest("GET", "http://example.com/", nil)
			req.Header.Set("X-CF-Forwarded-Url", backend.URL())
			req.Header.Set("X-CF-Proxy-Signature", "Stub signature")
			req.Header.Set("X-CF-Proxy-Metadata", "Stub metadata")
		})

		JustBeforeEach(func() {
			response = httptest.NewRecorder()
			proxy.ServeHTTP(response, req)
		})

		Context("with a valid github token", func() {
			BeforeEach(func() {
				req.AddCookie(&http.Cookie{
					Name:  COOKIE_TOKEN,
					Value: "token",
				})

				github.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", "/user"),
						ghttp.VerifyBasicAuth("bearer", "token"),
						ghttp.RespondWith(http.StatusOK, `{"login":"bob"}`),
					),
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", "/orgs/coolorg/members/bob"),
						ghttp.VerifyBasicAuth("bearer", "token"),
						ghttp.RespondWith(http.StatusNoContent, nil),
					),
				)
			})

			It("should proxy the request to the backend", func() {
				Expect(response.Code).To(Equal(http.StatusOK))

				Expect(backend.ReceivedRequests()).To(HaveLen(1))

				headers := backend.ReceivedRequests()[0].Header
				Expect(headers.Get("X-CF-Proxy-Signature")).To(Equal("Stub signature"))
				Expect(headers.Get("X-CF-Proxy-Metadata")).To(Equal("Stub metadata"))
			})

			It("preserves the Host header from the forwarded URL", func() {
				url, err := url.Parse(backend.URL())
				Expect(err).NotTo(HaveOccurred())

				beReq := backend.ReceivedRequests()[0]
				Expect(beReq.Host).To(Equal(url.Host))
			})

			Context("with a path and query in the forwarded URL", func() {
				BeforeEach(func() {
					req.Header.Set("X-CF-Forwarded-Url", backend.URL()+"/foo/bar?a=b")
				})
				It("preserves the path and query from the forwarded URL", func() {
					beReq := backend.ReceivedRequests()[0]

					Expect(beReq.URL.Path).To(Equal("/foo/bar"))
					Expect(beReq.URL.RawQuery).To(Equal("a=b"))
				})
			})
		})

		Context("with an unauthorised github token", func() {
			BeforeEach(func() {
				req.AddCookie(&http.Cookie{
					Name:  COOKIE_TOKEN,
					Value: "token",
				})

				github.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", "/user"),
						ghttp.VerifyBasicAuth("bearer", "token"),
						ghttp.RespondWith(http.StatusOK, `{"login":"bob"}`),
					),
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", "/orgs/coolorg/members/bob"),
						ghttp.VerifyBasicAuth("bearer", "token"),
						ghttp.RespondWith(http.StatusNotFound, nil),
					),
				)
			})

			It("should return unauthorised", func() {
				Expect(response.Code).To(Equal(http.StatusUnauthorized))
			})
		})

		Context("with no github token", func() {
			It("should redirect to github oauth login", func() {
				redirect_url := fmt.Sprintf(
					"%s/login/oauth/authorize?client_id=%s&redirect_uri=%s/%s&allow_signup=false",
					github.URL(),
					client_id,
					hostname,
					OAUTH_CALLBACK_PATH,
				)

				Expect(response.Code).To(Equal(http.StatusSeeOther))
				Expect(response.Header().Get("Location")).To(ContainSubstring(redirect_url))
			})

			It("does not make a request to the backend", func() {
				Expect(backend.ReceivedRequests()).To(HaveLen(0))
			})
		})
	})
})
