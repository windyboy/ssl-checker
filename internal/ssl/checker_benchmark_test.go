package ssl_test

import (
	"crypto/tls"
	"testing"
	"time"

	"ssl-checker/internal/ssl"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gmeasure"
)

var _ = Describe("SSL Checker Benchmarks", func() {
	var (
		checker    *ssl.Checker
		experiment *gmeasure.Experiment
	)

	BeforeEach(func() {
		checker = ssl.NewChecker(10 * time.Second)
		experiment = gmeasure.NewExperiment("SSL Checker Benchmarks")
	})

	It("should measure performance of CheckSSL", func() {
		experiment.Sample(func(idx int) {
			start := time.Now()
			_, err := checker.CheckSSL("github.com", "443")
			Expect(err).NotTo(HaveOccurred())
			experiment.RecordDuration("CheckSSL", time.Since(start))
		}, gmeasure.SamplingConfig{N: 10})

		stats := experiment.GetStats("CheckSSL")
		Expect(stats.DurationFor(gmeasure.StatMean)).To(BeNumerically("<", 2*time.Second))
	})

	It("should measure performance of CheckSSLWithChain", func() {
		experiment.Sample(func(idx int) {
			start := time.Now()
			_, err := checker.CheckSSLWithChain("github.com", "443")
			Expect(err).NotTo(HaveOccurred())
			experiment.RecordDuration("CheckSSLWithChain", time.Since(start))
		}, gmeasure.SamplingConfig{N: 10})

		stats := experiment.GetStats("CheckSSLWithChain")
		Expect(stats.DurationFor(gmeasure.StatMean)).To(BeNumerically("<", 2*time.Second))
	})

	It("should measure performance of CheckMultipleSSL", func() {
		domains := []string{
			"github.com",
			"microsoft.com",
			"apple.com",
		}

		experiment.Sample(func(idx int) {
			start := time.Now()
			results := checker.CheckMultipleSSL(domains, "443", 3)
			Expect(results).To(HaveLen(len(domains)))
			experiment.RecordDuration("CheckMultipleSSL", time.Since(start))
		}, gmeasure.SamplingConfig{N: 10})

		stats := experiment.GetStats("CheckMultipleSSL")
		Expect(stats.DurationFor(gmeasure.StatMean)).To(BeNumerically("<", 3*time.Second))
	})

	It("should measure performance of ValidateHostname", func() {
		conn, err := tls.Dial("tcp", "github.com:443", &tls.Config{
			ServerName: "github.com",
		})
		Expect(err).NotTo(HaveOccurred())
		defer conn.Close()

		cert := conn.ConnectionState().PeerCertificates[0]

		experiment.Sample(func(idx int) {
			start := time.Now()
			err := checker.ValidateHostname(cert, "github.com")
			Expect(err).NotTo(HaveOccurred())
			experiment.RecordDuration("ValidateHostname", time.Since(start))
		}, gmeasure.SamplingConfig{N: 10})

		stats := experiment.GetStats("ValidateHostname")
		Expect(stats.DurationFor(gmeasure.StatMean)).To(BeNumerically("<", 100*time.Millisecond))
	})

	It("should measure performance of GetCertificateFingerprint", func() {
		conn, err := tls.Dial("tcp", "github.com:443", &tls.Config{
			ServerName: "github.com",
		})
		Expect(err).NotTo(HaveOccurred())
		defer conn.Close()

		cert := conn.ConnectionState().PeerCertificates[0]

		experiment.Sample(func(idx int) {
			start := time.Now()
			fingerprint := checker.GetCertificateFingerprint(cert)
			Expect(fingerprint).NotTo(BeEmpty())
			experiment.RecordDuration("GetCertificateFingerprint", time.Since(start))
		}, gmeasure.SamplingConfig{N: 10})

		stats := experiment.GetStats("GetCertificateFingerprint")
		Expect(stats.DurationFor(gmeasure.StatMean)).To(BeNumerically("<", 100*time.Millisecond))
	})
})

func BenchmarkSSL(b *testing.B) {
	checker := ssl.NewChecker(10 * time.Second)
	b.Run("CheckSSL", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := checker.CheckSSL("github.com", "443")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("CheckSSLWithChain", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := checker.CheckSSLWithChain("github.com", "443")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("CheckMultipleSSL", func(b *testing.B) {
		domains := []string{
			"github.com",
			"microsoft.com",
			"apple.com",
		}
		for i := 0; i < b.N; i++ {
			results := checker.CheckMultipleSSL(domains, "443", 3)
			if len(results) != len(domains) {
				b.Fatal("unexpected number of results")
			}
		}
	})
}
