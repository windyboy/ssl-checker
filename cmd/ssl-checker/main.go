// Package main 是 SSL Checker 的入口点
// 该工具用于检查和分析网站的 SSL/TLS 证书信息
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"ssl-checker/config"
	"ssl-checker/internal/ssl"
	"ssl-checker/pkg/utils"
)

// main 是程序的入口点
// 它处理命令行参数，加载配置，并执行 SSL 检查
func main() {
	// 定义命令行参数
	var (
		host          = flag.String("host", "", "要检查的主机名 (必需，除非使用 -file)")
		port          = flag.String("port", "", "端口号")
		timeout       = flag.Duration("timeout", 0, "连接超时时间")
		verbose       = flag.Bool("verbose", false, "显示详细信息")
		json          = flag.Bool("json", false, "以JSON格式输出")
		configFile    = flag.String("config", "", "配置文件路径")
		help          = flag.Bool("help", false, "显示帮助信息")
		file          = flag.String("file", "", "包含要检查的主机名列表的文件")
		maxConcurrent = flag.Int("concurrent", 10, "最大并发检查数")
	)
	flag.Parse()

	// 显示帮助信息或检查必需参数
	if *help || (*host == "" && *file == "") {
		showUsage()
		if *host == "" && *file == "" {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// 加载配置
	cfg := loadConfig(*configFile)

	// 命令行参数优先级高于配置文件
	if *port != "" {
		cfg.DefaultPort = *port
	}
	if *timeout != 0 {
		cfg.DefaultTimeout = *timeout
	}
	if *verbose {
		cfg.Verbose = true
	}
	if *json {
		cfg.JSONOutput = true
	}

	// 创建检查器
	checker := ssl.NewChecker(cfg.DefaultTimeout)

	// 执行检查
	if *file != "" {
		// 从文件读取主机列表
		hosts, err := readHostsFromFile(*file)
		if err != nil {
			log.Fatalf("读取文件失败: %v", err)
		}

		// 并发检查所有主机
		results := checker.CheckMultipleSSL(hosts, cfg.DefaultPort, *maxConcurrent)

		// 输出结果
		if cfg.JSONOutput {
			utils.PrintJSON(&ssl.CheckResult{
				MultipleResults: results,
			})
		} else {
			for host, result := range results {
				fmt.Printf("\n检查主机: %s\n", host)
				utils.PrintFormatted(result, cfg.Verbose)
			}
		}
	} else {
		// 检查单个主机
		var result *ssl.CheckResult
		var err error

		if cfg.CheckChain {
			result, err = checker.CheckSSLWithChain(*host, cfg.DefaultPort)
		} else {
			sslInfo, err2 := checker.CheckSSL(*host, cfg.DefaultPort)
			if err2 != nil {
				log.Fatalf("❌ 检查失败: %v", err2)
			}
			result = &ssl.CheckResult{SSL: sslInfo}
		}

		if err != nil {
			log.Fatalf("❌ 检查失败: %v", err)
		}

		// 输出结果
		if cfg.JSONOutput {
			utils.PrintJSON(result)
		} else {
			utils.PrintFormatted(result, cfg.Verbose)
		}
	}
}

// readHostsFromFile 从文件中读取主机列表
// 每行一个主机名，忽略空行和以 # 开头的注释行
func readHostsFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hosts []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		host := strings.TrimSpace(scanner.Text())
		if host != "" && !strings.HasPrefix(host, "#") {
			hosts = append(hosts, host)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return hosts, nil
}

// loadConfig 加载配置
// 按以下优先级加载配置：
// 1. 环境变量
// 2. 指定的配置文件
// 3. 默认配置文件 (~/.ssl-checker.json)
func loadConfig(configPath string) *config.Config {
	// 首先尝试从环境变量加载
	cfg := config.LoadFromEnv()

	// 如果指定了配置文件，尝试从文件加载
	if configPath != "" {
		if fileCfg, err := config.LoadFromFile(configPath); err == nil {
			cfg = fileCfg
		} else {
			log.Printf("警告: 无法加载配置文件 %s: %v", configPath, err)
		}
	} else {
		// 尝试加载默认配置文件
		defaultConfigPath := filepath.Join(os.Getenv("HOME"), ".ssl-checker.json")
		if fileCfg, err := config.LoadFromFile(defaultConfigPath); err == nil {
			cfg = fileCfg
		}
	}

	return cfg
}

// showUsage 显示使用帮助信息
func showUsage() {
	fmt.Println("🔒 SSL证书检查工具")
	fmt.Println("==================")
	fmt.Println()
	fmt.Println("使用方法:")
	fmt.Println("  ssl-checker -host example.com")
	fmt.Println("  ssl-checker -host example.com -port 8443")
	fmt.Println("  ssl-checker -host example.com -verbose")
	fmt.Println("  ssl-checker -host example.com -json")
	fmt.Println("  ssl-checker -host example.com -timeout 30s")
	fmt.Println("  ssl-checker -host example.com -config /path/to/config.json")
	fmt.Println("  ssl-checker -file hosts.txt")
	fmt.Println("  ssl-checker -file hosts.txt -concurrent 20")
	fmt.Println()
	fmt.Println("参数:")
	flag.PrintDefaults()
	fmt.Println()
	fmt.Println("环境变量:")
	fmt.Println("  SSL_CHECKER_TIMEOUT        默认超时时间")
	fmt.Println("  SSL_CHECKER_PORT          默认端口")
	fmt.Println("  SSL_CHECKER_VERBOSE       是否显示详细信息")
	fmt.Println("  SSL_CHECKER_JSON          是否使用JSON输出")
	fmt.Println("  SSL_CHECKER_CHAIN         是否检查证书链")
	fmt.Println("  SSL_CHECKER_VALIDATE_HOSTNAME  是否验证主机名")
	fmt.Println("  SSL_CHECKER_SCT           是否检查证书透明度")
	fmt.Println()
	fmt.Println("示例:")
	fmt.Println("  ssl-checker -host github.com")
	fmt.Println("  ssl-checker -host badssl.com -port 443 -json")
	fmt.Println("  ssl-checker -file domains.txt -concurrent 50")
}
