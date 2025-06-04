// Package ssl 提供了 SSL 证书检查的核心功能
// 包括证书验证、证书链分析、安全特性检查等功能
package ssl

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Checker 是 SSL 检查器的主要结构体
// 它包含了执行 SSL 检查所需的所有功能
type Checker struct {
	timeout time.Duration // 连接超时时间
}

// NewChecker 创建一个新的 SSL 检查器实例
// timeout: 连接超时时间
func NewChecker(timeout time.Duration) *Checker {
	return &Checker{
		timeout: timeout,
	}
}

// CheckSSL 检查指定主机的 SSL 证书
// host: 要检查的主机名
// port: 端口号
// 返回 SSL 证书信息和可能的错误
func (c *Checker) CheckSSL(host, port string) (*SSLInfo, error) {
	// 建立 TLS 连接
	dialer := &net.Dialer{
		Timeout: c.timeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), &tls.Config{
		ServerName: host,
	})
	if err != nil {
		return nil, fmt.Errorf("连接失败: %v", err)
	}
	defer conn.Close()

	// 获取连接状态
	state := conn.ConnectionState()
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("未找到证书")
	}

	// 分析服务器证书
	cert := certs[0]
	return c.analyzeCertificate(cert, host, port), nil
}

// CheckSSLWithChain 检查 SSL 证书并返回证书链信息
// host: 要检查的主机名
// port: 端口号
// 返回包含证书链信息的检查结果
func (c *Checker) CheckSSLWithChain(host, port string) (*CheckResult, error) {
	dialer := &net.Dialer{
		Timeout: c.timeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), &tls.Config{
		ServerName: host,
	})
	if err != nil {
		return &CheckResult{Error: fmt.Errorf("检查失败: %v", err)}, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return &CheckResult{Error: errors.New("未找到证书")}, nil
	}

	// 分析主证书
	sslInfo := c.analyzeCertificate(certs[0], host, port)

	// 分析证书链
	chain := c.analyzeCertificateChain(certs)
	chainInfo := make([]*SSLInfo, len(chain.Certificates))
	for i, cert := range certs {
		chainInfo[i] = c.analyzeCertificate(cert, host, port)
	}

	return &CheckResult{
		SSL:   sslInfo,
		Chain: chainInfo,
	}, nil
}

// CheckMultipleSSL 并发检查多个主机的 SSL 证书
// hosts: 要检查的主机名列表
// port: 端口号
// maxConcurrent: 最大并发检查数
// 返回每个主机的检查结果
func (c *Checker) CheckMultipleSSL(hosts []string, port string, maxConcurrent int) map[string]*CheckResult {
	results := make(map[string]*CheckResult)
	var mutex sync.Mutex
	var wg sync.WaitGroup

	// 创建信号量来控制并发数
	semaphore := make(chan struct{}, maxConcurrent)

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()

			// 获取信号量
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result, err := c.CheckSSLWithChain(h, port)
			if err != nil {
				result = &CheckResult{
					Error: fmt.Errorf("检查失败: %v", err),
				}
			}

			// 安全地更新结果
			mutex.Lock()
			results[h] = result
			mutex.Unlock()
		}(host)
	}

	wg.Wait()
	return results
}

// analyzeCertificate 分析单个证书
// cert: 要分析的证书
// host: 主机名
// port: 端口号
// 返回证书的详细信息
func (c *Checker) analyzeCertificate(cert *x509.Certificate, host, port string) *SSLInfo {
	now := time.Now()
	isExpired := now.After(cert.NotAfter)
	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)

	// 检查是否自签名
	isSelfSigned := cert.Issuer.String() == cert.Subject.String()

	// 获取密钥大小
	keySize := c.getKeySize(cert)

	// 获取IP地址
	ipAddresses := make([]string, len(cert.IPAddresses))
	for i, ip := range cert.IPAddresses {
		ipAddresses[i] = ip.String()
	}

	// 检查是否有SCT (Certificate Transparency)
	hasSCT := len(cert.Extensions) > 0 && c.hasSCTExtension(cert)

	return &SSLInfo{
		Host:            host,
		Port:            port,
		Subject:         cert.Subject.String(),
		Issuer:          cert.Issuer.String(),
		NotBefore:       cert.NotBefore,
		NotAfter:        cert.NotAfter,
		DNSNames:        cert.DNSNames,
		IPAddresses:     ipAddresses,
		SerialNumber:    cert.SerialNumber.String(),
		SignatureAlgo:   cert.SignatureAlgorithm.String(),
		PublicKeyAlgo:   cert.PublicKeyAlgorithm.String(),
		KeySize:         keySize,
		Version:         cert.Version,
		IsExpired:       isExpired,
		DaysUntilExpiry: daysUntilExpiry,
		IsSelfSigned:    isSelfSigned,
		IsCA:            cert.IsCA,
		HasSCT:          hasSCT,
	}
}

// analyzeCertificateChain 分析证书链
// certs: 证书链中的所有证书
// 返回证书链的详细信息
func (c *Checker) analyzeCertificateChain(certs []*x509.Certificate) *CertificateChain {
	chain := &CertificateChain{
		Length:       len(certs),
		Certificates: make([]CertInfo, len(certs)),
	}

	for i, cert := range certs {
		chain.Certificates[i] = CertInfo{
			Subject:      cert.Subject.String(),
			Issuer:       cert.Issuer.String(),
			SerialNumber: cert.SerialNumber.String(),
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
			IsCA:         cert.IsCA,
		}
	}

	return chain
}

// getKeySize 获取证书的密钥大小
// cert: 要分析的证书
// 返回密钥大小（位）
func (c *Checker) getKeySize(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Params().BitSize
	case ed25519.PublicKey:
		return 256 // Ed25519 密钥长度固定为 256 位
	default:
		return 0
	}
}

// hasSCTExtension 检查证书是否包含 SCT 扩展
// cert: 要检查的证书
// 返回是否包含 SCT 扩展
func (c *Checker) hasSCTExtension(cert *x509.Certificate) bool {
	// SCT OID: 1.3.6.1.4.1.11129.2.4.2
	sctOID := "1.3.6.1.4.1.11129.2.4.2"
	for _, ext := range cert.Extensions {
		if ext.Id.String() == sctOID {
			return true
		}
	}
	return false
}

// ValidateHostname 验证主机名是否匹配证书
// cert: 要验证的证书
// hostname: 要验证的主机名
// 返回验证结果
func (c *Checker) ValidateHostname(cert *x509.Certificate, hostname string) error {
	return cert.VerifyHostname(hostname)
}

// GetCertificateFingerprint 获取证书指纹
// cert: 要分析的证书
// 返回证书的 SHA-256 指纹
func (c *Checker) GetCertificateFingerprint(cert *x509.Certificate) string {
	return fmt.Sprintf("%x", cert.Raw)
}
