# banner-grabber
banner scan

# Banner Grabber

一个用于学习网络安全基础的 **Banner 探测工具**，通过与目标端口建立真实 TCP 连接，捕获服务主动返回的握手信息（Banner），从而识别服务类型、软件版本及操作系统特征。

Banner Grabbing 是信息收集阶段（Reconnaissance）的核心技术之一，属于主动扫描范畴。本工具仅用于授权测试与安全学习，请遵守当地法律法规。

## 工作原理

Banner Grabbing 的本质是**利用协议的握手机制**。不同服务在 TCP 连接建立后行为不同：

## 快速开始

```bash
git clone https://github.com/security-toolkit/banner-grabber
cd banner-grabber

# 基础用法
python banner_grabber.py --host 192.168.1.1 --port 3306

# 多端口扫描
python banner_grabber.py --host 192.168.1.1 --ports 21,22,80,443,3306

# 带超时设置 + 输出到文件
python banner_grabber.py --host 192.168.1.1 --ports 22 --timeout 5 --output result.json
```

**README 标签**：项目概述、服务行为对比卡片（MySQL/FTP/SSH/HTTP 的推送差异）、TCP 流程图、快速开始命令。

**源代码标签**：完整的生产级 `banner_grabber.py`，相比原始代码做了以下升级：

- 用 `@dataclass` 封装结果，结构清晰可序列化
- `SERVICE_PROBES` 字典按端口选择探测载荷，主动/被动服务分离处理
- `ThreadPoolExecutor` 实现多端口并发扫描
- 完整异常处理：超时、拒绝连接、通用异常三层捕获
- `settimeout()` 防止永久阻塞
- `argparse` CLI 支持，可直接命令行调用并输出 JSON 报告

**交互演示标签**：可选服务逐步模拟 Banner 抓取的完整过程，直观看到主动推送型（MySQL/SSH）和请求响应型（HTTP/Redis）的差异。

**API 参考标签**：完整的函数签名、参数表和作为库调用的示例代码。
