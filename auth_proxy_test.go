package main

import (
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
		hostname      string = "http://example.com"
		client_id     string = "client"
		client_secret string = "secret"
		github_org    string = "coolorg"
		proxy         http.Handler
		github        *ghttp.Server
		backend       *ghttp.Server
		req           *http.Request
		response      *httptest.ResponseRecorder
	)

	BeforeEach(func() {
		github = ghttp.NewServer()
		backend = ghttp.NewServer()
		backend.AllowUnhandledRequests = true
		backend.UnhandledRequestStatusCode = http.StatusOK
		proxy = OverrideAuthProxy(hostname, client_id, client_secret, github_org, github.URL(), github.URL())
	})

	AfterEach(func() {
		github.Close()
		backend.Close()
	})

	Context("with a request to the oauth endpoint", func() {
		BeforeEach(func() {
			req = httptest.NewRequest("GET", "http://example.com"+OAUTH_PATH, nil)
		})

		JustBeforeEach(func() {
			response = httptest.NewRecorder()
			proxy.ServeHTTP(response, req)
		})

		It("should set the state cookie", func() {
			cookie := response.Result().Cookies()[0]

			Expect(cookie.Name).To(Equal(COOKIE_STATE))
			Expect(cookie.Value).NotTo(BeEmpty())
		})

		It("should redirect to github oauth login", func() {
			redirect_url := fmt.Sprintf(
				"%s/login/oauth/authorize?client_id=%s&redirect_uri=%s/oauth/callback&allow_signup=false",
				github.URL(),
				client_id,
				hostname,
			)

			Expect(response.Code).To(Equal(http.StatusSeeOther))
			Expect(response.Header().Get("Location")).To(ContainSubstring(redirect_url))
		})
	})

	Context("with a request to the oauth callback endpoint from github", func() {
		BeforeEach(func() {
			github.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("POST", "/login/oauth/access_token"),
					ghttp.VerifyForm(url.Values{
						"client_id":     {client_id},
						"client_secret": {client_secret},
						"code":          {"123456"},
						"redirect_uri":  {"http://example.com" + OAUTH_CALLBACK_PATH},
						"state":         {"somestate"},
					}),
					ghttp.RespondWith(http.StatusOK, `access_token=token&token_type=bearer`),
				),
			)

			callback_url := fmt.Sprintf("http://example.com%s?state=somestate&code=123456", OAUTH_CALLBACK_PATH)
			req = httptest.NewRequest("GET", callback_url, nil)
			req.AddCookie(&http.Cookie{
				Name:  COOKIE_STATE,
				Value: "somestate",
			})
			req.AddCookie(&http.Cookie{
				Name:  COOKIE_FWD,
				Value: backend.URL(),
			})
		})

		JustBeforeEach(func() {
			response = httptest.NewRecorder()
			proxy.ServeHTTP(response, req)
		})

		It("should set the user's token cookie", func() {
			cookie := response.Result().Cookies()[0]
			Expect(cookie.Name).To(Equal(COOKIE_TOKEN))
			Expect(cookie.Value).To(Equal("token"))
		})

		It("should redirect the user according to the forward cookie", func() {
			Expect(response.Code).To(Equal(http.StatusSeeOther))
			Expect(response.Header().Get("Location")).To(Equal(backend.URL()))
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
				Expect(headers.Get("X-GitHub-Token")).To(Equal("token"))
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
			It("redirects to /oauth", func() {
				Expect(response.Code).To(Equal(http.StatusSeeOther))
				Expect(response.Header().Get("Location")).To(Equal("/oauth"))
			})

			It("sets the forward cookie", func() {
				cookie := response.Result().Cookies()[0]

				Expect(cookie.Name).To(Equal(COOKIE_FWD))
				Expect(cookie.Value).To(Equal(backend.URL()))
			})

			It("does not make a request to the backend", func() {
				Expect(backend.ReceivedRequests()).To(HaveLen(0))
			})
		})
	})
})
