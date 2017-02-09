package main

import (
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

var _ = Describe("Basic Auth proxy", func() {

	var (
		username string = "user"
		password string = "secret"
		proxy    http.Handler
		backend  *ghttp.Server
		req      *http.Request
		response *httptest.ResponseRecorder
	)

	BeforeEach(func() {
		proxy = NewAuthProxy(username, password)
		backend = ghttp.NewServer()
		backend.AllowUnhandledRequests = true
		backend.UnhandledRequestStatusCode = http.StatusOK
	})

	AfterEach(func() {
		backend.Close()
	})

	Context("with a request from route-services", func() {
		BeforeEach(func() {
			req = httptest.NewRequest("GET", "http://proxy.example.com/", nil)
			req.Header.Set("X-CF-Forwarded-Url", backend.URL())
			req.Header.Set("X-CF-Proxy-Signature", "Stub signature")
			req.Header.Set("X-CF-Proxy-Metadata", "Stub metadata")
		})

		JustBeforeEach(func() {
			response = httptest.NewRecorder()
			proxy.ServeHTTP(response, req)
		})

		Context("with the correct username and password", func() {
			BeforeEach(func() {
				req.SetBasicAuth(username, password)
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

		Context("with invalid credentials", func() {
			BeforeEach(func() {
				req.SetBasicAuth(username, "not the password")
			})

			It("returns a 401 Unauthorized", func() {
				Expect(response.Code).To(Equal(http.StatusUnauthorized))
				Expect(response.Header().Get("WWW-Authenticate")).To(Equal(`Basic realm="auth"`))
			})

			It("does not make a request to the backend", func() {
				Expect(backend.ReceivedRequests()).To(HaveLen(0))
			})
		})
	})
})
