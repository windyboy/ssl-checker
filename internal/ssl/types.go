// Package ssl 提供了 SSL 证书检查的核心功能
// 包括证书验证、证书链分析、安全特性检查等功能
package ssl

import "time"

// SSLInfo 包含 SSL 证书的所有信息
// 用于存储和分析单个 SSL 证书的详细信息
type SSLInfo struct {
	Host            string    `json:"host"`                 // 主机名
	Port            string    `json:"port"`                 // 端口号
	Subject         string    `json:"subject"`              // 证书主题
	Issuer          string    `json:"issuer"`               // 证书颁发者
	NotBefore       time.Time `json:"not_before"`           // 证书开始时间
	NotAfter        time.Time `json:"not_after"`            // 证书结束时间
	DNSNames        []string  `json:"dns_names"`            // DNS 名称列表
	IPAddresses     []string  `json:"ip_addresses"`         // IP 地址列表
	SerialNumber    string    `json:"serial_number"`        // 证书序列号
	SignatureAlgo   string    `json:"signature_algorithm"`  // 签名算法
	PublicKeyAlgo   string    `json:"public_key_algorithm"` // 公钥算法
	KeySize         int       `json:"key_size"`             // 密钥大小（位）
	Version         int       `json:"version"`              // 证书版本
	IsExpired       bool      `json:"is_expired"`           // 是否已过期
	DaysUntilExpiry int       `json:"days_until_expiry"`    // 距离过期的天数
	IsSelfSigned    bool      `json:"is_self_signed"`       // 是否自签名
	IsCA            bool      `json:"is_ca"`                // 是否是 CA 证书
	HasSCT          bool      `json:"has_sct"`              // 是否支持证书透明度
}

// CertificateChain 表示证书链信息
// 包含证书链中的所有证书及其关系
type CertificateChain struct {
	Length       int        `json:"length"`       // 证书链长度
	Certificates []CertInfo `json:"certificates"` // 证书列表
}

// CertInfo 包含单个证书的基本信息
// 用于证书链中的每个证书
type CertInfo struct {
	Subject      string    `json:"subject"`       // 证书主题
	Issuer       string    `json:"issuer"`        // 证书颁发者
	SerialNumber string    `json:"serial_number"` // 证书序列号
	NotBefore    time.Time `json:"not_before"`    // 证书开始时间
	NotAfter     time.Time `json:"not_after"`     // 证书结束时间
	IsCA         bool      `json:"is_ca"`         // 是否是 CA 证书
}

// CheckResult 包含 SSL 检查的结果
// 可以包含单个证书信息、证书链信息或错误信息
type CheckResult struct {
	SSL             *SSLInfo                // 主证书信息
	Chain           []*SSLInfo              // 证书链信息
	Error           error                   // 错误信息
	MultipleResults map[string]*CheckResult // 多个主机的检查结果
}
