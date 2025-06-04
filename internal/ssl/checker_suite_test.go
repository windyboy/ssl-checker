package ssl_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSSL(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SSL Suite")
}
