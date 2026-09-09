# 在 Windows 上部署控制器

本指南在 Windows 上创建一个自托管 Stella 控制器部署。它与已配置的 Windows 客户端
共同组成实验性的二层虚拟局域网，但尚不是生产网络发布。

## 构建服务器

在仓库根目录执行：

```powershell
cargo build --release -p stella-server
New-Item -ItemType Directory -Force C:\Stella | Out-Null
Copy-Item .\target\release\stella-server.exe C:\Stella\
```

其余命令应由将来运行服务的账户执行。`init` 会为该 Windows 账户和
LocalSystem 保护生成的私钥；其他账户不能加载这些私钥。

## 初始化部署

列出客户端将用于连接控制器的每个 DNS 名称或 IP 地址。证书除这些值外，
始终包含 `localhost`、`127.0.0.1` 和 `::1`。

```powershell
C:\Stella\stella-server.exe --config C:\Stella\server.toml init `
  --listen 0.0.0.0:44900 `
  --tls-name controller.example.net `
  --tls-name 192.0.2.10
```

该命令拒绝覆盖已有部署。通过可信渠道记录输出的 `controller_id` 和
`tls_spki_pin`，客户端用两者验证控制器身份。不要将 `C:\Stella\secrets`
中的文件传给客户端。

继续前检查 `C:\Stella\server.toml`。相对数据库、证书和密钥路径都以配置
文件所在目录为基准。请在主机及上游防火墙中放行 TCP 44900 端口，或 `listen`
指定的自定义端口。

## 配置连接服务

可选的 0.2 `[connectivity]` 配置让控制器下发 STUN、Relay 位置、TLS 信任材料和绑定节点
的短期 Relay 凭据。内置服务端可以运行 TURN UDP、TURN TCP、TURN TLS 和 Secure
WebSocket；STUN 仍需单独部署。

先创建共享凭据签发密钥：

```powershell
& C:\Stella\stella-server.exe relay-key create `
  --output C:\Stella\secrets\relay-credential.key
```

然后添加配置修订、至少一个 STUN 和 Relay：

```toml
[connectivity]
revision = 1
credential_key = "secrets/relay-credential.key"
credential_lifetime_seconds = 300
stun_servers = ["192.0.2.20:3478"]

[[connectivity.relays]]
id = "01010101010101010101010101010101"
priority = 0
region = "primary"
hostname = "relay.example.net"
tls_server_name = "relay.example.net"
require_web_pki = true
turn_udp = 3478
turn_tcp = 3479
turn_tls = 5349
secure_websocket = 443
addresses = ["192.0.2.30", "2001:db8::30"]
```

非零端口启用对应承载。私有 TLS 证书可省略 `require_web_pki`，改为配置一个或多个规范
`sha256/<standard-base64>` SPKI 固定值。服务定义变化后必须递增 `revision`。凭据密钥只应
由控制器和 Relay 进程读取；客户端只接收绑定其节点身份与 Relay ID 的短期凭据。

分别启动四个承载。以下示例把公网 TCP 443 留给 Secure WebSocket，使允许直接出站
HTTPS/WSS 的网络仍有最终兜底路径：

```powershell
$Server = 'C:\Stella\stella-server.exe'
$Config = 'C:\Stella\server.toml'

& $Server --config $Config relay run `
  --id 01010101010101010101010101010101 `
  --carrier udp `
  --listen 0.0.0.0:3478 `
  --advertise 192.0.2.30

& $Server --config $Config relay run `
  --id 01010101010101010101010101010101 `
  --carrier tcp `
  --listen 0.0.0.0:3479 `
  --advertise 192.0.2.30

& $Server --config $Config relay run `
  --id 01010101010101010101010101010101 `
  --carrier tls `
  --listen 0.0.0.0:5349 `
  --advertise 192.0.2.30

& $Server --config $Config relay run `
  --id 01010101010101010101010101010101 `
  --carrier websocket `
  --listen 0.0.0.0:443 `
  --advertise 192.0.2.30
```

在主机与上游防火墙中放行 UDP 3478、TCP 3479、5349 和 443。四个承载都会为每个分配
创建动态 UDP socket，这些端口同样必须可用；Relay 位于 NAT 后时还需转发 Windows UDP
动态端口范围，直接使用公网 IP 更合适。TLS 与 Secure WebSocket 进程复用 `[tls]` 的
证书与私钥，证书必须覆盖 `tls_server_name`。每个进程都会拒绝与 `turn_udp`、
`turn_tcp`、`turn_tls` 或 `secure_websocket` 不一致的监听端口，并在 Ctrl+C 后有序退出。

WebSocket 路径固定为 `/stella/turn/v1`，子协议固定为 `stella-turn.v1`，升级前验证短期
凭据，并禁止压缩扩展。应直接监听公网 TCP 443；若同一端口还需承载网站，请使用独立 IP
或主机名配合四层 TLS/SNI 透传，普通的明文 HTTP 上游并不是该监听器。Windows 客户端按
UDP → TCP → TLS → Secure WebSocket 的顺序自动尝试，无需客户端端口映射。只能通过
代理出站的网络可设置客户端数值 `transport.https_proxy`；客户端先用它隧道化控制器
TLS，取得 Relay 授权后再用同一代理建立 Secure WebSocket Relay 兜底。控制器和 Relay
的 TLS 认证在各自 CONNECT 隧道内保持端到端。首个方案暂不支持代理认证。

## 创建网络和邀请

```powershell
$Server = 'C:\Stella\stella-server.exe'
$Config = 'C:\Stella\server.toml'

$NetworkId = & $Server --config $Config network create --name 'Game LAN'
$NetworkId

& $Server --config $Config invite create `
  --network $NetworkId `
  --controller 203.0.113.10:44900 `
  --tls-name controller.example.net
```

把 `--controller` 替换成客户端实际能够访问的数值地址；`--tls-name` 必须包含在初始化
生成的证书中。邀请以 `stella1:` 开头，封装控制器信任、网络 ID、注册和加入令牌，默认
一小时后过期且只输出一次。请通过可信私密渠道发送，为每个节点生成不同邀请，不要写入
日志、工单或源代码管理系统。客户端可按[快速开始](./quick-start)用一条 `join` 命令完成
首次配置和加入。

需要分别管理令牌时，仍可使用 `enrollment-token create` 和 `join-token create`；详见
[服务器 CLI 参考](/zh/api/server-cli)。

## 验证并运行

```powershell
& $Server --config $Config state verify
& $Server --config $Config run
```

`state verify` 必须输出 `ok`。守护进程会再次验证部署状态，绑定配置的 TCP
地址，并将运行日志写入 stderr。按 Ctrl+C 可有序关闭；离线管理命令正在使用
同一数据库时，请勿终止该进程。

## 备份授权状态

使用协调备份命令，不要直接复制正在使用的 redb 文件：

```powershell
New-Item -ItemType Directory -Force C:\Stella\backups | Out-Null
& $Server --config $Config state backup `
  --output C:\Stella\backups\controller-2026-08-31.redb
```

目标文件不得已存在。请将经过验证的数据库备份与受保护的控制器和 TLS 身份
副本一同保存；仅有数据库无法重建同一控制器信任身份。

所有管理命令和策略默认值请参阅[服务器 CLI 参考](/zh/api/server-cli)。
