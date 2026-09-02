# 服务器管理 CLI

`stella-server` 初始化控制器部署、运行 TLS 控制平面和 TURN UDP/TCP/TLS/Secure WebSocket 服务，
创建受保护的 Relay 凭据密钥，并提供授权管理命令。每个
命令都会加载 `--config` 指定的严格 TOML 配置（默认为 `server.toml`）。访问授权状态
的命令会从受保护的控制器身份推导控制器 ID，打开配置的 redb 数据库，并在串行化授权
线程上执行数据库工作。

## 通用语法

```powershell
stella-server --config C:\Stella\server.toml <command>
```

网络 ID 和节点 ID 都是标准的 16 字节标识符，以恰好 32 个十六进制数字表示。输入
十六进制不区分大小写，输出为小写。成功的变更命令只输出脚本所需结果；错误和诊断
上下文写入 stderr，并以非零退出码结束。

## 初始化部署

```powershell
stella-server --config C:\Stella\server.toml init `
  --listen 0.0.0.0:44900 `
  --tls-name controller.example.net
```

`init` 创建配置、`state` 和 `secrets` 目录、受保护的控制器和 TLS 私钥、自签名的
Ed25519 TLS 证书，以及绑定控制器的 redb 数据库。它不会覆盖已有目标。初始化失败时
只删除本次调用创建的文件和空目录。

证书始终包含 `localhost`、`127.0.0.1` 和 `::1`。重复 `--tls-name` 可添加 DNS 名称
或 IP 地址。`--tls-validity-days` 默认 825，可取 1 至 3650。成功输出包含：

```text
controller_id=<32 lowercase hexadecimal digits>
tls_spki_pin=sha256/<standard padded base64>
tls_not_after=<Unix timestamp>
config=<configuration path>
```

请通过可信渠道将控制器 ID 和 SPKI 固定值交给客户端。私钥从不输出，`run` 也不会
重新生成缺失文件。

## 创建 Relay 凭据密钥

```powershell
stella-server relay-key create `
  --output C:\Stella\secrets\relay-credential.key
```

该命令从操作系统取得非零随机 256 位密钥，使用与控制器身份相同的原生受保护文件策略
创建并同步目标，只输出 `key=<path>`。它不会覆盖已有文件，也不会输出密钥字节。该文件
只应由控制器和验证短期凭据的 Relay 进程读取，绝不能复制给客户端。

## 运行 TURN Relay

```powershell
stella-server --config C:\Stella\server.toml relay run `
  --id 01010101010101010101010101010101 `
  --carrier udp `
  --listen 0.0.0.0:3478 `
  --advertise 192.0.2.30
```

`relay run` 从 `[connectivity]` 按 ID 选择 Relay，加载受保护的凭据密钥，并运行
`--carrier udp|tcp|tls|websocket` 指定的承载直到 Ctrl+C；默认仍为 UDP。监听端口必须
等于配置中的 `turn_udp`、`turn_tcp`、`turn_tls` 或 `secure_websocket`。`--advertise` 是返回给远端节点的可达
中继地址；本地分配 socket 需要绑定其他 IP 时使用 `--allocation-bind`。

TCP、TLS 和 Secure WebSocket 应各自在独立进程中运行：

```powershell
stella-server --config C:\Stella\server.toml relay run `
  --id 01010101010101010101010101010101 `
  --carrier tcp `
  --listen 0.0.0.0:3479 `
  --advertise 192.0.2.30

stella-server --config C:\Stella\server.toml relay run `
  --id 01010101010101010101010101010101 `
  --carrier tls `
  --listen 0.0.0.0:5349 `
  --advertise 192.0.2.30

stella-server --config C:\Stella\server.toml relay run `
  --id 01010101010101010101010101010101 `
  --carrier websocket `
  --listen 0.0.0.0:443 `
  --advertise 192.0.2.30
```

TLS 和 Secure WebSocket 复用顶层 `[tls]` 中的证书和受保护 PKCS#8 私钥，只允许 TLS
1.3、禁用 early data，并使用 `limits.tls_handshake_timeout_seconds` 限制握手。证书必须
覆盖控制器下发的 Relay TLS 名称，并满足相应 Web PKI、SPKI 固定或两者同时校验。

Secure WebSocket 只接受 `GET /stella/turn/v1`、子协议 `stella-turn.v1`、唯一且规范的
`Authorization: Stella ...` 凭据，并拒绝 WebSocket 扩展。HTTP 升级前先完成认证，升级后
仍执行完整 TURN challenge 和消息完整性校验；每个二进制消息恰好包含一个有界 TURN
record。该进程自行终止 TLS；若 TCP 443 还需承载网站，应使用独立 IP 或主机名配合四层
TLS/SNI 透传。

默认全局最多 1024 个分配、每节点 4 个，每个分配最多 128 个权限和 Channel。四个承载
都创建 UDP 中继分配；TCP、TLS 和 Secure WebSocket 只改变客户端到 Relay 的控制与数据
承载。Windows 客户端按 UDP → TCP → TLS → Secure WebSocket 自动回退。每个分配当前使用
操作系统选择的动态 UDP 端口，因此主机防火墙必须允许这些 socket；有界分配端口池仍待
后续实现。

## 运行控制器

```powershell
stella-server --config C:\Stella\server.toml run
```

`run` 会在绑定配置的 TCP 地址前验证完整配置、受保护的控制器身份、TLS 证书和私钥、
绑定控制器的数据库及持久化不变量。之后它通过 TLS 1.3 提供注册、认证、网络成员关系、
端点发布、快照、心跳和主动成员授权刷新控制会话。

`[logging].filter` 使用 `tracing-subscriber` 的过滤器语法。生成的值
`info,stella_server=info` 会将可读的运行日志写入 stderr，且不暴露 Bearer 令牌或
私钥。无效过滤器会在监听器启动前被拒绝。

按一次 Ctrl+C 可停止接受新连接。守护进程请求活动会话关闭，最多等待
`limits.shutdown_timeout_seconds`，中止其余会话任务，在已接纳命令之后有序关闭授权
状态，并等待授权线程结束。正常关闭以代码 0 退出。配置、身份、TLS、持久化、绑定、
会话运行时或关闭故障均会写入 stderr，并以非零代码退出。

`run` 不会创建或修复缺失的部署文件。请仅执行一次 `init`，确保 `secrets` 中两个文件
只允许控制器账户读取，并使用下方状态维护命令进行验证和备份。

## 网络管理

创建网络并让操作系统生成其 ID：

```powershell
stella-server --config C:\Stella\server.toml network create --name "Game LAN"
```

该命令输出新网络 ID。`--id` 接受显式的非零网络 ID，用于确定性部署和测试。默认策略：

| 选项 | 默认值 |
| --- | ---: |
| `--confidentiality` | `encrypt` |
| `--max-frame-size` | 1514 字节 |
| `--max-flood-peers` | 32 |
| `--flood-rate` | 1000 帧/秒 |
| `--flood-burst` | 2000 帧 |
| `--mac-age-seconds` | 300 |
| `--heartbeat-seconds` | 10 |
| `--peer-lease-seconds` | 30 |
| `--session-lifetime-seconds` | 900 |
| `--reassembly-timeout-ms` | 3000 |

`--confidentiality authenticate-only` 保持以太网负载字节可见，但仍要求数据包经过认证。
策略值在提交网络前由规范协议编解码器验证。

```powershell
stella-server --config C:\Stella\server.toml network list
stella-server --config C:\Stella\server.toml network show --network <network-id>
stella-server --config C:\Stella\server.toml network delete --network <network-id>
```

删除是幂等的。它会原子移除网络、成员关系、端点和未使用的加入令牌，并输出 `deleted`
或 `absent`。

## 一次性令牌

```powershell
stella-server --config C:\Stella\server.toml enrollment-token create
stella-server --config C:\Stella\server.toml join-token create --network <network-id>
```

两个命令都接受 `--ttl-seconds`；默认 3600 秒，零值被拒绝。成功命令恰好一次向 stdout
写入一个未填充的 base64url Bearer 令牌和一个换行。如果必须以编程方式传递令牌，请将
stdout 重定向到受保护的位置。数据库仅存储经域分隔的摘要，每个令牌会随注册或加入操作
原子消耗。

## 节点和成员关系

```powershell
stella-server --config C:\Stella\server.toml node list
stella-server --config C:\Stella\server.toml node disable --node <node-id>
stella-server --config C:\Stella\server.toml node enable --node <node-id>

stella-server --config C:\Stella\server.toml member add --network <network-id> --node <node-id>
stella-server --config C:\Stella\server.toml member suspend --network <network-id> --node <node-id>
stella-server --config C:\Stella\server.toml member resume --network <network-id> --node <node-id>
stella-server --config C:\Stella\server.toml member remove --network <network-id> --node <node-id>
```

有效授权变更会在同一事务中轮换受影响授权的序列号，并推进网络 epoch 和对等快照修订号。
重复执行已满足的操作是安全的。禁用节点会立即使其所有网络授权失效。

## 状态维护

```powershell
stella-server --config C:\Stella\server.toml state verify
stella-server --config C:\Stella\server.toml state backup --output C:\Stella\backups\controller.redb
```

`state verify` 遍历全部授权记录，只有每个模式和跨记录不变量都成立时才输出 `ok`。
`state backup` 通过授权线程创建时间点副本，将其同步、独立打开，并在报告字节数前运行
同一验证器。输出路径不得存在；不得直接复制正在使用的数据库文件。
