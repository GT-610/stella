# 客户端 CLI

`stella-client` 管理一个受保护的节点身份、严格的控制器信任、持久化的目标网络
列表，以及 Windows 或 macOS 原生 TAP/数据平面运行时。除非另行指定路径，命令都使用
`--config client.toml`。

## 前置条件与可达性

Windows 每个已配置网络需要一个预安装 TAP-Windows Adapter V9，并从提升权限的 PowerShell
运行。macOS 每个网络需要两个未占用的数值型 feth 名称，当前必须以 root 运行；Stella 会
创建或复用 pair，不安装驱动或 helper。

控制器必须能通过配置的
TLS/TCP 地址直接访问，或能通过可选的显式 HTTPS 代理访问。运行时会收集直连 UDP 候选，
并使用控制器下发的 STUN 和 Relay。
客户端端口映射是可选的：直连 ICE 检查失败后，客户端依次尝试 TURN UDP、TCP、TLS 和
Secure WebSocket；至少一种直连或 Relay 路径必须成功。

Stella 是二层覆盖网络：它不分配 IP 地址，也不提供 DHCP。请自行在 TAP 适配器上配置
地址，或在虚拟局域网内提供 DHCP。

## 初始化

```powershell
stella-client --config C:\Stella\client.toml init `
  --controller 203.0.113.10:44900 `
  --tls-name controller.example.net `
  --controller-id 0123456789abcdef0123456789abcdef `
  --spki-pin sha256/BASE64_SHA256_SPKI_DIGEST= `
  --display-name "Gaming PC" `
  --udp-bind 0.0.0.0:45100 `
  --https-proxy 192.0.2.40:8080
```

允许直接连接控制器 TCP 的网络请省略 `--https-proxy`。

`init` 以仅创建语义生成配置和 `secrets/node.pk8`。Windows 会禁用身份文件继承，只允许
当前账户和 `LocalSystem` 访问；macOS 要求无额外 hard link 的普通文件、精确 `0600`
权限，并拒绝 symlink。已有目标不会被替换；初始化失败时只删除本次调用创建的目标。

成功输出包含小写节点 ID 和配置路径。初始配置没有网络条目，且
`transport.advertised_endpoints` 列表为空。当控制器下发了可用的 STUN 或 Relay 服务时，
可以保持为空。只有部署确实拥有一个外部可达、且端口与 `udp_bind` 一致的固定映射时，
才需要添加端点：

```toml
[[transport.advertised_endpoints]]
address = "192.0.2.20:45100"
priority = 10
max_datagram_size = 1200
```

静态端点可以改善直连发现，但不能把不可路由的私网地址变成公网候选。配置
`transport.https_proxy` 后，控制器引导会先连接该数值代理地址，向控制器 TLS 名称和端口
发送有界 HTTP CONNECT。认证完成后，同一代理还用于最后一级 Secure WebSocket Relay
兜底：

```toml
[transport]
udp_bind = "0.0.0.0:45100"
https_proxy = "192.0.2.40:8080"
```

TLS 1.3、服务器名与 SPKI 验证、Stella 控制器认证以及 Relay TLS/WSS 认证都保持端到端，
在各自隧道内完成。代理不影响直连 UDP、TURN UDP、TURN TCP 或直连 TURN TLS，它们仍按
原顺序先行尝试。首个方案支持无需认证的代理；`407` 会失败关闭，明文 CONNECT 绝不
携带注册、加入、控制器或 Relay 凭据。

`init` 不接受注册或加入令牌，也不会将令牌写入磁盘。

## 加入网络

Windows 选择准确的预安装适配器：

```powershell
stella-client --config C:\Stella\client.toml join `
  --network <id> `
  --token <unpadded-base64url-token> `
  --tap-adapter "Stella LAN"
```

macOS 必须选择 feth pair 两端。第一项是宿主可见端，第二项只供 Stella 报文 I/O：

```sh
stella-client --config /etc/stella/client.toml join \
  --network <id> \
  --token <unpadded-base64url-token> \
  --tap-adapter feth100 \
  --tap-peer feth101
```

节点尚未向控制器注册时，加入一次性
`--enrollment-token <unpadded-base64url-token>`。两类令牌都必须解码为恰好 32 字节。
它们只存在于进程内，会从调试输出中脱敏，也不会写入配置。

`join` 先验证本地 TAP 选择，再认证并等待完整、已验证的控制器快照，然后原子持久化
网络 ID 与选择。重复已接受的加入可省略 `--token`；相同 Windows 适配器或完整相同的
macOS pair 是幂等的，冲突的 adapter 或 peer 会在连接控制器前被拒绝。

macOS 条目继续使用配置版本 1：

```toml
[[networks]]
id = "fedcba9876543210fedcba9876543210"
tap_adapter = "feth100"
tap_peer = "feth101"
```

## 状态

```powershell
stella-client --config C:\Stella\client.toml status
```

`status` 是离线命令。它会验证配置和受保护身份，然后输出派生的节点 ID、控制器
地址、名称和 ID、可选 HTTPS 代理、UDP 绑定地址，以及每个目标网络及其 TAP 选择。macOS
条目同时输出 `tap_adapter` 和 `tap_peer`。
它绝不输出 SPKI 固定值、凭据、私钥材料或私钥路径。

## 离开网络

```powershell
stella-client --config C:\Stella\client.toml leave --network <id>
```

`leave` 需要已有的目标网络条目。它从无活动转发状态开始，在不接受令牌材料的前提下
认证，验证控制器权威的 `LEAVE_RESULT`，然后才从本地配置中原子移除网络。失败或结果
不明确的请求不会启用转发，并会保留持久意图以便恢复或重试。

## 运行

Windows：

```powershell
stella-client --config C:\Stella\client.toml run
```

macOS：

```sh
sudo stella-client --config /etc/stella/client.toml run
```

`run` 验证配置和受保护身份，初始化配置的 tracing 过滤器，认证后按稳定 ID 顺序重新
加入目标网络（不保存令牌），并发布完整的已配置端点集合。之后它管理活动控制器状态，
应用快照、对等节点增量、授权刷新和心跳协调。

控制器暂时故障时，本地数据运行时会在既有 grant、epoch 和会话寿命内继续处理有效转发，
同时按 250 ms 到 30 秒的完整抖动退避重连。只有连续三个策略心跳周期未收到确认，心跳
才视为丢失。Ctrl+C 会中断控制循环，并等待 TAP、UDP 和 Relay 有序关闭。

Windows 会打开准确的 TAP-Windows，并在关闭时设置 media-disconnected。macOS 会创建或
复用准确 feth pair，通过 BPF 收包、AF_NDRV 发包，并在关闭时把宿主可见端置 down 而不
删除 pair。无效对等数据报会被丢弃且不重连控制器；TAP、UDP 或 worker 故障会关闭数据
运行时并进入正常的失败关闭重连路径。
