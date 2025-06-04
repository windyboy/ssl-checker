package config

import (
	"encoding/json"
	"os"
	"time"
)

// Config 应用程序配置
type Config struct {
	// 默认超时时间
	DefaultTimeout time.Duration `json:"default_timeout"`
	// 默认端口
	DefaultPort string `json:"default_port"`
	// 是否启用详细输出
	Verbose bool `json:"verbose"`
	// 是否使用JSON输出
	JSONOutput bool `json:"json_output"`
	// 是否检查证书链
	CheckChain bool `json:"check_chain"`
	// 是否验证主机名
	ValidateHostname bool `json:"validate_hostname"`
	// 是否检查证书透明度
	CheckSCT bool `json:"check_sct"`
}

// DefaultConfig 返回默认配置
func DefaultConfig() *Config {
	return &Config{
		DefaultTimeout:   10 * time.Second,
		DefaultPort:      "443",
		Verbose:          false,
		JSONOutput:       false,
		CheckChain:       true,
		ValidateHostname: true,
		CheckSCT:         true,
	}
}

// LoadFromFile 从文件加载配置
func LoadFromFile(path string) (*Config, error) {
	config := DefaultConfig()

	file, err := os.Open(path)
	if err != nil {
		return config, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(config); err != nil {
		return config, err
	}

	return config, nil
}

// LoadFromEnv 从环境变量加载配置
func LoadFromEnv() *Config {
	config := DefaultConfig()

	if timeout := os.Getenv("SSL_CHECKER_TIMEOUT"); timeout != "" {
		if duration, err := time.ParseDuration(timeout); err == nil {
			config.DefaultTimeout = duration
		}
	}

	if port := os.Getenv("SSL_CHECKER_PORT"); port != "" {
		config.DefaultPort = port
	}

	if verbose := os.Getenv("SSL_CHECKER_VERBOSE"); verbose != "" {
		config.Verbose = verbose == "true"
	}

	if json := os.Getenv("SSL_CHECKER_JSON"); json != "" {
		config.JSONOutput = json == "true"
	}

	if chain := os.Getenv("SSL_CHECKER_CHAIN"); chain != "" {
		config.CheckChain = chain == "true"
	}

	if hostname := os.Getenv("SSL_CHECKER_VALIDATE_HOSTNAME"); hostname != "" {
		config.ValidateHostname = hostname == "true"
	}

	if sct := os.Getenv("SSL_CHECKER_SCT"); sct != "" {
		config.CheckSCT = sct == "true"
	}

	return config
}

// SaveToFile 保存配置到文件
func (c *Config) SaveToFile(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(c)
}
