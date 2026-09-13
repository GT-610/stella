# Windows 开发环境

## 前置条件

- Windows 10 或更高版本；
- 含 Cargo 的稳定版 Rust 工具链；
- 将已签名的 TAP-Windows Adapter V9 驱动包安装到 Driver Store；
- 用于 VitePress 文档站点的 Bun；
- 建议使用已启用长路径支持的 Git。

创建 TAP 设备和配置网络通常需要提升权限的终端。纯库测试和文档构建不需要
提升权限。

运行时不会安装驱动包。它会从 Driver Store 中已有的驱动包为每个网络创建一个持久 root
TAP-Windows 设备，命名为 `Stella <网络ID>`，并在多次运行间复用；`leave` 会删除该网络的
托管设备。驱动 MTU 与持久 MAC 地址的修改仍属于外部管理员操作，且需重启微型端口后
Stella 才能打开适配器。

## 验证工作区

```powershell
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
bun run docs:build
```

已有适配器测试为可选项，因为它会暂时修改 TAP 介质状态并需要独占访问：

```powershell
$env:STELLA_TAP_WINDOWS_ADAPTER = 'Local Area Connection'
cargo test -p stella-tap --test windows_tap `
  installed_adapter_supports_lifecycle_frame_write_and_cancellation `
  -- --ignored --exact --nocapture
```

该测试会恢复介质断开状态，不会创建、移除或重命名适配器。第二个提升权限测试验证自动
配置：创建一个名称唯一的 TAP 设备，复用并打开它，最后删除；即使测试 unwind 也会尝试
清理：

```powershell
cargo test -p stella-tap --test windows_tap `
  provisioning_creates_reuses_opens_and_removes_adapter `
  -- --ignored --exact --nocapture
```

## 运行开发控制器

在源码树之外初始化一次性部署，创建一个网络和一对一次性客户端令牌，然后运行
TLS 控制器：

```powershell
$Config = Join-Path $env:TEMP 'stella-dev\server.toml'

cargo run -p stella-server -- --config $Config init `
  --listen 127.0.0.1:44900

$NetworkId = cargo run -q -p stella-server -- `
  --config $Config network create --name 'Development LAN'
$EnrollmentToken = cargo run -q -p stella-server -- `
  --config $Config enrollment-token create
$JoinToken = cargo run -q -p stella-server -- `
  --config $Config join-token create --network $NetworkId

cargo run -p stella-server -- --config $Config run
```

启动守护进程前，请记录初始化输出、网络 ID 和令牌。令牌敏感且只输出一次。
按 Ctrl+C 排空活动会话并正常关闭。

控制器和 Windows 客户端现在可以组成实验性的虚拟局域网。请为每台客户端生成独立的
注册和加入令牌，然后按 [Windows 客户端 CLI 指南](/zh/api/client-cli)初始化、加入并
运行客户端。每次加入都会创建或复用该网络独立的托管 TAP-Windows 适配器。直连 ICE
发现和配置的 Relay 承载不要求客户端端口映射；可选的显式 HTTP 代理还能承载最后一级
Secure WebSocket 兜底。加入、离开和活动客户端都应在提升权限的 PowerShell 会话中运行，
以便 Stella 管理和打开 TAP 设备。

初始客户端配置的 `advertised_endpoints` 列表为空。控制器已下发 STUN 和 Relay 服务时
应保持为空。若确实拥有固定公网映射，可以额外公布一个端口与 `udp_bind` 一致的直连
候选，例如：

```toml
[[transport.advertised_endpoints]]
address = "192.168.1.20:45100"
priority = 10
max_datagram_size = 1200
```

Stella 转发以太网帧，不会分配 IP 地址或提供 DHCP。请在 TAP 适配器上配置合适的地址，
或在虚拟局域网中提供 DHCP。若要部署持久环境，请阅读
[Windows 控制器部署指南](./server-deployment.md)。
