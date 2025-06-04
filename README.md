# SSL Checker

一个用 Go 语言编写的 SSL 证书检查工具，用于检查和分析网站的 SSL/TLS 证书信息。

## 功能特点

- 检查 SSL 证书的有效期
- 分析证书链
- 验证主机名匹配
- 检查证书透明度 (SCT)
- 支持自定义超时
- 支持 JSON 输出格式
- 支持详细模式输出
- 支持并发检查多个主机
- 支持从文件批量检查
- 支持自定义端口
- 支持证书链验证
- 支持安全特性检测

## 安装

### 从源码安装

```bash
git clone https://github.com/yourusername/ssl-checker.git
cd ssl-checker
go install ./cmd/ssl-checker
```

### 使用 Go 安装

```bash
go install github.com/yourusername/ssl-checker/cmd/ssl-checker@latest
```

## 使用方法

### 基本用法

检查单个主机：
```bash
ssl-checker -host example.com
```

检查特定端口：
```bash
ssl-checker -host example.com -port 8443
```

显示详细信息：
```bash
ssl-checker -host example.com -verbose
```

JSON 格式输出：
```bash
ssl-checker -host example.com -json
```

自定义超时时间：
```bash
ssl-checker -host example.com -timeout 30s
```

从文件批量检查：
```bash
ssl-checker -file hosts.txt
```

设置最大并发数：
```bash
ssl-checker -file hosts.txt -concurrent 20
```

### 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-host` | 要检查的主机名 | (必需) |
| `-port` | 端口号 | 443 |
| `-timeout` | 连接超时时间 | 10s |
| `-verbose` | 显示详细信息 | false |
| `-json` | 以 JSON 格式输出 | false |
| `-file` | 包含要检查的主机名列表的文件 | |
| `-concurrent` | 最大并发检查数 | 10 |
| `-config` | 配置文件路径 | |
| `-help` | 显示帮助信息 | |

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `SSL_CHECKER_TIMEOUT` | 默认超时时间 | 10s |
| `SSL_CHECKER_PORT` | 默认端口 | 443 |
| `SSL_CHECKER_VERBOSE` | 是否显示详细信息 | false |
| `SSL_CHECKER_JSON` | 是否使用 JSON 输出 | false |
| `SSL_CHECKER_CHAIN` | 是否检查证书链 | false |
| `SSL_CHECKER_VALIDATE_HOSTNAME` | 是否验证主机名 | true |
| `SSL_CHECKER_SCT` | 是否检查证书透明度 | true |

### 配置文件

支持 JSON 格式的配置文件，默认位置：`~/.ssl-checker.json`

示例配置：
```json
{
  "default_port": "443",
  "default_timeout": "10s",
  "verbose": false,
  "json_output": false,
  "check_chain": true,
  "validate_hostname": true,
  "check_sct": true
}
```

## 输出示例

### 标准输出

```
🔒 SSL证书信息 - example.com:443
============================================================
📋 主题: example.com
🏢 颁发者: Let's Encrypt
📅 有效期: 2024-01-01 00:00:00 至 2024-04-01 00:00:00
✅ 状态: 有效 (30 天后过期)
🌐 DNS名称: example.com, www.example.com
🔐 签名算法: SHA256-RSA
🗝️  公钥算法: RSA (2048 位)
🛡️  安全特性: 🔸 证书透明度
```

### JSON 输出

```json
{
  "host": "example.com",
  "port": "443",
  "subject": "CN=example.com",
  "issuer": "C=US, O=Let's Encrypt, CN=R3",
  "not_before": "2024-01-01T00:00:00Z",
  "not_after": "2024-04-01T00:00:00Z",
  "dns_names": ["example.com", "www.example.com"],
  "key_size": 2048,
  "is_expired": false,
  "days_until_expiry": 30
}
```

## 开发指南

### 项目结构

```
ssl-checker/
├── cmd/
│   └── ssl-checker/
│       └── main.go
├── internal/
│   └── ssl/
│       ├── checker.go
│       └── types.go
├── pkg/
│   └── utils/
│       └── format.go
├── Taskfile.yml
└── README.md
```

### 开发任务

使用 Taskfile 进行开发：

1. 编译应用程序：
```bash
task build
```

2. 开发模式运行：
```bash
task dev
```

3. 运行测试：
```bash
task test
```

4. 格式化代码：
```bash
task fmt
```

5. 运行所有检查：
```bash
task check
```

6. 多平台编译：
```bash
task build-all
```

### 测试

1. 运行单元测试：
```bash
task test:unit
```

2. 运行基准测试：
```bash
task test:bench
```

## 安全考虑

### 证书验证
- 主机名验证
- 证书链验证
- 证书透明度检查
- 密钥大小验证
- 签名算法验证

### 安全特性检查
- 证书过期检查
- 自签名证书检查
- CA 证书检查
- 证书透明度 (SCT) 检查
- 密钥大小检查
- 签名算法检查

### 最佳实践
1. 始终验证证书链
2. 检查证书透明度
3. 验证主机名
4. 使用适当的密钥大小
5. 监控证书过期
6. 定期安全审计

## 故障排除

### 常见问题

1. 连接超时
   - 检查网络连接
   - 验证主机是否可达
   - 必要时增加超时值

2. 证书链问题
   - 验证中间证书
   - 检查证书顺序
   - 确保所有证书有效

3. 主机名验证失败
   - 验证 DNS 配置
   - 检查证书的 DNS 名称
   - 确保检查正确的主机名

### 错误消息

1. "连接失败: connection refused"
   - 主机不可达
   - 端口未开放
   - 防火墙阻止连接

2. "未找到证书"
   - 指定端口没有 SSL/TLS
   - 连接在证书交换前失败

3. "证书链验证失败"
   - 缺少中间证书
   - 证书链无效
   - 证书链中有过期证书

## 贡献

1. Fork 仓库
2. 创建特性分支
3. 提交更改
4. 运行测试
5. 提交 Pull Request

## 许可证

MIT License 