# Sentinel -- 轻量级网络漏洞扫描器

纯 Python 标准库实现的网络资产发现与漏洞评估工具。TCP Connect 端口扫描 -> 协议探测 -> 服务指纹识别 -> CVE 匹配 -> 单文件 HTML 报告，一条命令完成全流程。

## 特点

- **零系统依赖** -- 不依赖 nmap、openssl 等外部工具，TLS 握手通过 `ssl` 标准库完成
- **不需要 root 权限** -- 使用 TCP Connect 扫描而非 SYN 半开扫描
- **单文件报告** -- CSS 内联的暗色主题 HTML，可直接用浏览器打开
- **asyncio 并发** -- 所有 I/O 操作（端口扫描、协议探测）基于 asyncio 协程，Semaphore 控制并发上限
- **扩展 CVE 库** -- 内置常见漏洞条目，支持通过 CSV 文件导入自定义 CVE 数据
- **纯 Python** -- 除 Jinja2 外不引入任何第三方依赖

## 扫描流水线

```
 目标 IP/CIDR
      │
      ▼
┌─────────────────┐
│ 1. 端口扫描       │  TCP Connect（asyncio）
│   port_scanner   │  四状态分类: open / closed / filtered / error
└────────┬────────┘
         │ OPEN 端口
         ▼
┌─────────────────┐
│ 2. 协议探测       │  443/8443 → TLS + HTTPS GET（SNI，不验证证书）
│   probe_sender   │  80/8080  → HTTP/1.0 GET
│                  │  其他端口 → 被动 banner 抓取 + \r\n 触发
└────────┬────────┘
         │ ProbeResult（banner + headers + tls_info）
         ▼
┌─────────────────┐
│ 3. 指纹识别       │  正则规则匹配 Header / Banner / TLS Subject CN
│   fingerprinter  │  每条结果带置信度 (0.0–1.0)
└────────┬────────┘
         │ ServiceInfo（vendor, product, version）
         ▼
┌─────────────────┐
│ 4. CVE 匹配      │  vendor + product 精确匹配 → version_range 区间比较
│   cve_matcher    │  支持 <=, <, >=, >, ==, != 及组合条件
└────────┬────────┘
         │ Vulnerability（CVE ID, severity, CVSS）
         ▼
┌─────────────────┐
│ 5. HTML 报告     │  Jinja2 渲染 → output/report_<时间戳>.html
│   html_reporter  │  总览卡片 + 主机折叠面板 + 漏洞详情表
└─────────────────┘
```

## 快速开始

### 环境

- Python 3.10+
- pip

### 安装

```bash
git clone <repo-url>
cd sentinel
pip install jinja2
```

### 基本用法

```bash
# 扫描单 IP 的常用端口
python sentinel.py -t 192.168.1.1

# 指定端口
python sentinel.py -t 192.168.1.1 -p 22,80,443

# 扫描整个 C 段，端口 1–1000
python sentinel.py -t 192.168.1.0/24 -p 1-1000

# 从文件读取目标列表（每行一个 IP 或 CIDR）
python sentinel.py -t targets.txt -p top100

# 指定报告输出路径
python sentinel.py -t 192.168.1.1 -p 22,443 -o my_report.html

# 调整并发数与超时
python sentinel.py -t 192.168.1.0/24 -p 1-1024 --concurrency 200 --timeout 1.5
```
<img width="661" height="142" alt="image" src="https://github.com/user-attachments/assets/6e5820dd-30ef-455c-86d7-d815565960a7" />



## 命令行参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `-t, --target` | (必填) | 目标 IP、CIDR 网段（如 `192.168.1.0/24`）或 IP 列表文件路径 |
| `-p, --ports` | `top100` | 端口列表：`22,80,443`、`1-1000`、`top100` 或混合格式 |
| `-o, --output` | `output/report_<时间戳>.html` | 报告输出路径 |
| `--concurrency` | `100` | 最大并发 TCP 连接数 |
| `--timeout` | `2.0` | 单连接超时秒数 |
| `--retries` | `1` | FILTERED / ERROR 状态的重试次数 |

## 端口状态分类

| 状态 | 含义 | 判定依据 |
|---|---|---|
| `open` | 端口开放，TCP 连接成功 | 三次握手完成，记录 RTT |
| `closed` | 端口关闭 | 收到 RST（ConnectionRefusedError） |
| `filtered` | 被防火墙/ACL 过滤 | 超时无响应（TimeoutError） |
| `error` | 网络不可达或其他错误 | OSError |

`filtered` 和 `error` 状态会按 `--retries` 次数自动重试（`open` / `closed` 为确定性结果，不重试）。

## 探测策略

根据端口号自动选择探测方式：

| 端口 | 探测方式 | 说明 |
|---|---|---|
| 443, 8443 | TLS + HTTPS GET | `ssl.create_default_context()` 创建 TLS 通道，SNI 指定主机名，不验证证书。失败时回退到 HTTP GET |
| 80, 8080, 8000, 8888 | HTTP/1.0 GET | 发 `GET / HTTP/1.0`，解析响应头中的 `Server` / `X-Powered-By` 等字段 |
| 其他端口 | Generic Banner Grab | 先被动读取欢迎信息，无输出则发 `\r\n` 触发响应 |

TLS 探测额外提取证书的 Subject / Issuer / notAfter 字段，用于指纹辅助判断。

## 指纹识别

指纹规则定义在 `data/service_probes.json`，按 `probe_type` 分组（`generic_banner` / `http_get` / `tls_https_get`）。

匹配策略：
- **HTTP 响应** -- 优先匹配 `Server`、`X-Powered-By` 等特定响应头
- **TLS 证书** -- 匹配证书 Subject CN
- **Banner 文本** -- 匹配原始响应文本（SSH、FTP、SMTP 等协议）
- **TLS + HTTPS** -- 先匹配 TLS 规则组，无命中则回退到 HTTP 规则组
- 取置信度最高的规则作为识别结果；无命中则生成低保真度 fallback

目前支持识别 50+ 种服务/产品，包括 OpenSSH、Apache httpd、nginx、Tomcat、MySQL、PostgreSQL、Redis、MongoDB、ProFTPD、Postfix 等。

## CVE 匹配

### 内置 CVE 库

`data/cve_db.json` 包含常见高危漏洞条目（Apache httpd、OpenSSH、Tomcat、Struts 等），每条记录包含 CVE ID、严重等级、CVSS 评分、版本区间、描述和参考链接。

### 自定义 CVE 导入

在 `data/cve/custom/` 目录下放置 CSV 文件即可自动导入，支持以下列名（不区分大小写）：

| 列名别名 | 说明 |
|---|---|
| `vendor` | 厂商名（必填） |
| `product` | 产品名（必填） |
| `cve_id` / `cve` / `name` | CVE 编号（必填） |
| `version_range` / `affected_version` / `version` | 版本区间（可选，空或 `*` 表示全版本） |
| `severity` / `risk` / `level` | 严重等级 |
| `cvss_score` / `cvss` / `score` | CVSS 评分 |
| `description` / `summary` / `title` | 描述 |
| `references` / `reference` / `url` | 参考链接 |

### 版本区间格式

| 表达式 | 含义 |
|---|---|
| `*` 或空 | 所有版本 |
| `<=2.4.48` | 小于等于 2.4.48 |
| `<2.4.48` | 严格小于 |
| `>=8.5p1,<=9.3p2` | 闭区间，多个条件 AND 组合 |
| `!=1.2.3` | 排除指定版本 |

匹配逻辑：`vendor` + `product` 精确匹配（忽略大小写）-> `version_range` 区间比较。有精确版本时置信度 0.9，无版本时置信度 0.5。

## HTML 报告

生成的报告为单个独立 HTML 文件，无需外部 CSS/JS 资源。包含：

- **总览卡片** -- 目标数、开放端口数、识别服务数、CVE 命中数、UP/DOWN 主机比
- **主机汇总表** -- 所有目标的概览，点击跳转到详情
- **主机详情面板** -- 可折叠，默认展开有发现的主机
  - 端口与服务表（含状态、RTT、置信度）
  - 漏洞详情表（CVE ID、严重等级标签、CVSS、匹配依据、描述）
- 低置信度（< 30%）的服务在表格中弱化显示
  <img width="1061" height="1156" alt="image" src="https://github.com/user-attachments/assets/981bd72e-cd3d-40d3-be9d-15b242cead67" />


## 项目结构

```
sentinel/
├── sentinel.py                  # CLI 入口, 参数解析, 流水线编排
├── scanner/
│   ├── port_scanner.py          # TCP Connect 扫描（asyncio + Semaphore）
│   ├── probe_sender.py          # 协议探测：HTTP/TLS+HTTPS/通用 banner
│   ├── fingerprinter.py         # 服务指纹识别（正则规则匹配）
│   └── cve_matcher.py           # CVE 匹配（版本区间比较 + CSV 导入）
├── report/
│   └── html_reporter.py         # Jinja2 HTML 报告生成
├── models/
│   └── __init__.py              # PortStatus, PortInfo, HostResult, ProbeResult,
│                                  ServiceInfo, Vulnerability, ScanReport
├── data/
│   ├── service_probes.json      # 指纹探测规则（50+ 条）
│   ├── cve_db.json              # 内置 CVE 库
│   └── cve/custom/              # 用户自定义 CVE CSV 文件目录
├── templates/
│   └── report.html              # Jinja2 报告模板（暗色主题, 内联 CSS）
├── output/                      # 报告输出目录（首次运行自动创建）
├── requirements.txt
└── README.md
```


## 项目约束

- 不依赖 nmap、openssl 等系统工具
- 不主动引入 Jinja2 之外的第三方依赖
- 端口扫描使用 TCP Connect，无需 root 权限
- 单点失败不中断整体扫描，记录原因继续
- 所有公共函数参数和返回值带 type hint

## 许可

仅供授权的安全评估使用。使用者需自行确保对目标系统的扫描权限。
