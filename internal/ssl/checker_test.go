package ssl_test

import (
	"crypto/tls"
	"crypto/x509"
	"time"

	"ssl-checker/internal/ssl"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("SSL Checker", func() {
	var (
		checker *ssl.Checker
		timeout time.Duration
	)

	BeforeEach(func() {
		timeout = 10 * time.Second
		checker = ssl.NewChecker(timeout)
	})

	Describe("NewChecker", func() {
		It("should create a new checker with correct timeout", func() {
			Expect(checker).NotTo(BeNil())
			// Since timeout is unexported, we'll test it indirectly through CheckSSL
			_, err := checker.CheckSSL("github.com", "443")
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("CheckSSL", func() {
		Context("with valid domain", func() {
			It("should successfully check SSL certificate", func() {
				info, err := checker.CheckSSL("github.com", "443")
				Expect(err).NotTo(HaveOccurred())
				Expect(info).NotTo(BeNil())
				Expect(info.Host).To(Equal("github.com"))
				Expect(info.Port).To(Equal("443"))
				Expect(info.IsExpired).To(BeFalse())
			})
		})

		Context("with invalid domain", func() {
			It("should return error", func() {
				_, err := checker.CheckSSL("invalid-domain-that-does-not-exist.com", "443")
				Expect(err).To(HaveOccurred())
			})
		})

		Context("with timeout", func() {
			It("should return timeout error", func() {
				checker = ssl.NewChecker(1 * time.Nanosecond)
				_, err := checker.CheckSSL("github.com", "443")
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("CheckSSLWithChain", func() {
		It("should successfully check SSL certificate chain", func() {
			result, err := checker.CheckSSLWithChain("github.com", "443")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).NotTo(BeNil())
			Expect(result.SSL).NotTo(BeNil())
			Expect(result.Chain).NotTo(BeNil())
		})
	})

	Describe("Certificate Analysis", func() {
		var info *ssl.SSLInfo

		BeforeEach(func() {
			var err error
			info, err = checker.CheckSSL("github.com", "443")
			Expect(err).NotTo(HaveOccurred())
		})

		It("should have valid certificate information", func() {
			Expect(info.Subject).NotTo(BeEmpty())
			Expect(info.Issuer).NotTo(BeEmpty())
			Expect(info.KeySize).NotTo(BeZero())
			Expect(info.SignatureAlgo).NotTo(BeEmpty())
		})
	})

	Describe("Hostname Validation", func() {
		var cert *x509.Certificate

		BeforeEach(func() {
			conn, err := tls.Dial("tcp", "github.com:443", &tls.Config{
				ServerName: "github.com",
			})
			Expect(err).NotTo(HaveOccurred())
			defer conn.Close()

			cert = conn.ConnectionState().PeerCertificates[0]
		})

		It("should validate hostname correctly", func() {
			err := checker.ValidateHostname(cert, "github.com")
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("Certificate Fingerprint", func() {
		var cert *x509.Certificate

		BeforeEach(func() {
			conn, err := tls.Dial("tcp", "github.com:443", &tls.Config{
				ServerName: "github.com",
			})
			Expect(err).NotTo(HaveOccurred())
			defer conn.Close()

			cert = conn.ConnectionState().PeerCertificates[0]
		})

		It("should generate valid fingerprint", func() {
			fingerprint := checker.GetCertificateFingerprint(cert)
			Expect(fingerprint).NotTo(BeEmpty())
		})
	})
})
