# Windows 开发环境

## 前置条件

- Windows 10 或更高版本；
- 含 Cargo 的稳定版 Rust 工具链；
- 为运行时和平台测试安装 TAP-Windows；
- 用于 VitePress 文档站点的 Bun；
- 建议使用已启用长路径支持的 Git。

创建 TAP 设备和配置网络通常需要提升权限的终端。纯库测试和文档构建不需要
提升权限。

运行时会打开预先安装的 TAP-Windows Adapter V9，不会安装驱动或创建适配器。
存在多个 TAP-Windows 适配器时，配置必须选择目标 Windows 连接名称或接口 GUID。
驱动 MTU 与持久 MAC 地址的修改属于管理员操作，且需重启微型端口后 Stella 才能
打开适配器。

## 验证工作区

```powershell
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
bun run docs:build
```

真实适配器测试为可选项，因为它会暂时修改 TAP 介质状态并需要独占访问：

```powershell
$env:STELLA_TAP_WINDOWS_ADAPTER = 'Local Area Connection'
cargo test -p stella-tap --test windows_tap -- --ignored --nocapture
```

该测试会恢复介质断开状态，不会安装、移除、重命名、启用或禁用适配器。

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
运行客户端。每台客户端需要一块独立、已安装的 TAP-Windows 适配器。直连 ICE 发现和
配置的 Relay 承载不要求客户端端口映射；可选的显式 HTTP 代理还能承载最后一级 Secure
WebSocket 兜底。活动客户端应在提升权限的 PowerShell 会话中运行，以便打开 TAP 适配器。

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
