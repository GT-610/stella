# Windows 开发环境

## 前置条件

- Windows 10 或更高版本；
- 含 Cargo 的稳定版 Rust 工具链；
- 为后续平台测试安装 TAP-Windows；
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

控制器控制平面已经可用。`stella-client` 尚不能组成可用的虚拟局域网；其
Windows 控制平面和数据平面集成是下一项实现里程碑。若要部署持久环境，请阅读
[Windows 控制器部署指南](./server-deployment.md)。
