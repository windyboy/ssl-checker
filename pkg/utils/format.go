// Package utils 提供了 SSL Checker 的辅助功能
// 包括格式化输出、JSON 处理等功能
package utils

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"ssl-checker/internal/ssl"
)

// PrintFormatted 格式化输出 SSL 信息
// result: 要输出的检查结果
// verbose: 是否显示详细信息
func PrintFormatted(result *ssl.CheckResult, verbose bool) {
	if result.SSL == nil {
		fmt.Println("❌ 未找到SSL信息")
		return
	}

	info := result.SSL
	fmt.Printf("🔒 SSL证书信息 - %s:%s\n", info.Host, info.Port)
	fmt.Println(strings.Repeat("=", 60))

	// 基本信息
	fmt.Printf("📋 主题: %s\n", formatSubject(info.Subject))
	fmt.Printf("🏢 颁发者: %s\n", formatIssuer(info.Issuer))
	fmt.Printf("📅 有效期: %s 至 %s\n",
		info.NotBefore.Format("2006-01-02 15:04:05"),
		info.NotAfter.Format("2006-01-02 15:04:05"))

	// 过期状态
	printExpiryStatus(info)

	// DNS名称和IP地址
	if len(info.DNSNames) > 0 {
		fmt.Printf("🌐 DNS名称: %s\n", strings.Join(info.DNSNames, ", "))
	}
	if len(info.IPAddresses) > 0 {
		fmt.Printf("🌍 IP地址: %s\n", strings.Join(info.IPAddresses, ", "))
	}

	// 安全特性
	printSecurityFeatures(info)

	// 详细信息
	if verbose {
		printVerboseInfo(info)
	}

	// 打印证书链信息
	if len(result.Chain) > 0 {
		fmt.Printf("🔗 证书链信息 (共 %d 个证书)\n", len(result.Chain))
		fmt.Println(strings.Repeat("=", 60))
		for i, cert := range result.Chain {
			fmt.Printf("📜 证书 %d:\n", i+1)
			fmt.Printf("   主题: %s\n", formatSubject(cert.Subject))
			fmt.Printf("   颁发者: %s\n", formatIssuer(cert.Issuer))
			fmt.Printf("   有效期: %s 至 %s\n",
				cert.NotBefore.Format("2006-01-02"),
				cert.NotAfter.Format("2006-01-02"))
			if cert.IsCA {
				fmt.Printf("   🔸 CA证书\n")
			}
			fmt.Println()
		}
	}

	if result.Error != nil {
		fmt.Printf("\n❌ 错误: %s\n", result.Error.Error())
	}

	fmt.Println()
}

// PrintJSON 以 JSON 格式输出检查结果
// result: 要输出的检查结果
func PrintJSON(result *ssl.CheckResult) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Printf("JSON序列化错误: %v\n", err)
		return
	}
	fmt.Println(string(data))
}

// printExpiryStatus 打印证书过期状态
// info: SSL 证书信息
func printExpiryStatus(info *ssl.SSLInfo) {
	if info.IsExpired {
		fmt.Printf("❌ 状态: 已过期 (%d 天前)\n", -info.DaysUntilExpiry)
	} else if info.DaysUntilExpiry <= 7 {
		fmt.Printf("🚨 状态: 紧急续期 (%d 天后过期)\n", info.DaysUntilExpiry)
	} else if info.DaysUntilExpiry <= 30 {
		fmt.Printf("⚠️  状态: 即将过期 (%d 天后)\n", info.DaysUntilExpiry)
	} else {
		fmt.Printf("✅ 状态: 有效 (%d 天后过期)\n", info.DaysUntilExpiry)
	}
}

// printSecurityFeatures 打印证书安全特性
// info: SSL 证书信息
func printSecurityFeatures(info *ssl.SSLInfo) {
	fmt.Printf("🔐 签名算法: %s\n", info.SignatureAlgo)
	fmt.Printf("🗝️  公钥算法: %s", info.PublicKeyAlgo)
	if info.KeySize > 0 {
		fmt.Printf(" (%d 位)", info.KeySize)
	}
	fmt.Println()

	// 安全标志
	var flags []string
	if info.IsSelfSigned {
		flags = append(flags, "🔸 自签名")
	}
	if info.IsCA {
		flags = append(flags, "🔸 CA证书")
	}
	if info.HasSCT {
		flags = append(flags, "🔸 证书透明度")
	}
	if len(flags) > 0 {
		fmt.Printf("🛡️  安全特性: %s\n", strings.Join(flags, " "))
	}
}

// printVerboseInfo 打印证书详细信息
// info: SSL 证书信息
func printVerboseInfo(info *ssl.SSLInfo) {
	fmt.Println(strings.Repeat("-", 60))
	fmt.Println("📊 详细信息:")
	fmt.Printf("   🔢 序列号: %s\n", info.SerialNumber)
	fmt.Printf("   📊 版本: %d\n", info.Version)

	// 时间信息
	now := time.Now()
	validDays := int(info.NotAfter.Sub(info.NotBefore).Hours() / 24)
	usedDays := int(now.Sub(info.NotBefore).Hours() / 24)
	fmt.Printf("   ⏰ 证书总有效期: %d 天\n", validDays)
	if usedDays > 0 {
		fmt.Printf("   ⏱️  已使用时间: %d 天\n", usedDays)
	}
}

// formatSubject 格式化证书主题信息
// subject: 证书主题字符串
// 返回格式化后的主题信息
func formatSubject(subject string) string {
	// 提取CN (Common Name)
	parts := strings.Split(subject, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}
	return subject
}

// formatIssuer 格式化证书颁发者信息
// issuer: 证书颁发者字符串
// 返回格式化后的颁发者信息
func formatIssuer(issuer string) string {
	// 提取O (Organization)
	parts := strings.Split(issuer, ",")
	var org, cn string

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "O=") {
			org = strings.TrimPrefix(part, "O=")
		} else if strings.HasPrefix(part, "CN=") {
			cn = strings.TrimPrefix(part, "CN=")
		}
	}

	if org != "" {
		return org
	} else if cn != "" {
		return cn
	}
	return issuer
}

// PrintCertificateChain 打印证书链信息
// chain: 证书链信息
func PrintCertificateChain(chain *ssl.CertificateChain) {
	fmt.Printf("🔗 证书链信息 (共 %d 个证书)\n", chain.Length)
	fmt.Println(strings.Repeat("=", 60))

	for i, cert := range chain.Certificates {
		fmt.Printf("📜 证书 %d:\n", i+1)
		fmt.Printf("   主题: %s\n", formatSubject(cert.Subject))
		fmt.Printf("   颁发者: %s\n", formatIssuer(cert.Issuer))
		fmt.Printf("   有效期: %s 至 %s\n",
			cert.NotBefore.Format("2006-01-02"),
			cert.NotAfter.Format("2006-01-02"))
		if cert.IsCA {
			fmt.Printf("   🔸 CA证书\n")
		}
		fmt.Println()
	}
}
