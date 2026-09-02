# Windows 客户端 CLI

`stella-client` 管理一个受保护的节点身份、严格的控制器信任、持久化的目标网络
列表，以及 Windows TAP/数据平面运行时。除非另行指定路径，命令都使用
`--config client.toml`。

## 前置条件与可达性

每台客户端都需要自己预先安装的 TAP-Windows Adapter V9。控制器必须能通过配置的
TLS/TCP 地址直接访问，或能通过可选的显式 HTTPS 代理访问。运行时会收集直连 UDP 候选，
并使用控制器下发的 STUN 和 Relay。
客户端端口映射是可选的：直连 ICE 检查失败后，客户端依次尝试 TURN UDP、TCP、TLS 和
Secure WebSocket；至少一种直连或 Relay 路径必须成功。请在提升权限的 PowerShell 会话
中运行 `run`，以便进程打开 TAP 适配器。

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

`init` 以仅创建语义生成配置和 `secrets/node.pk8`。在 Windows 上，它会禁用身份
文件的继承权限，只允许当前账户和 `LocalSystem` 访问。已有目标不会被替换；初始化
失败时只会删除本次调用创建的目标。

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

```powershell
stella-client --config C:\Stella\client.toml join `
  --network <id> `
  --token <unpadded-base64url-token> `
  --tap-adapter "Stella LAN"
```

节点尚未向控制器注册时，加入一次性
`--enrollment-token <unpadded-base64url-token>`。两类令牌都必须解码为恰好 32 字节。
它们只存在于进程内，会从调试输出中脱敏，也不会写入配置。

`join` 会先认证并等待完整且通过验证的控制器快照，再原子持久化网络 ID 和 TAP
适配器。重复已接受的加入可省略 `--token`；使用相同 TAP 适配器重复执行是幂等的，
冲突的适配器会在连接控制器前被拒绝。

## 状态

```powershell
stella-client --config C:\Stella\client.toml status
```

`status` 是离线命令。它会验证配置和受保护身份，然后输出派生的节点 ID、控制器
地址、名称和 ID、可选 HTTPS 代理、UDP 绑定地址，以及每个目标网络及其 TAP 适配器。
它绝不输出 SPKI 固定值、凭据、私钥材料或私钥路径。

## 离开网络

```powershell
stella-client --config C:\Stella\client.toml leave --network <id>
```

`leave` 需要已有的目标网络条目。它从无活动转发状态开始，在不接受令牌材料的前提下
认证，验证控制器权威的 `LEAVE_RESULT`，然后才从本地配置中原子移除网络。失败或结果
不明确的请求不会启用转发，并会保留持久意图以便恢复或重试。

## 运行

```powershell
stella-client --config C:\Stella\client.toml run
```

`run` 验证配置和受保护身份，初始化配置的 tracing 过滤器，认证后按稳定 ID 顺序重新
加入目标网络（不保存令牌），并发布完整的已配置端点集合。之后它管理活动控制器状态，
应用快照、对等节点增量、授权刷新和心跳协调。

控制器故障会在完整抖动重连延迟前撤回全部内存中的转发授权。退避从 250 ms 开始，
上限为 30 秒。只有连续三个策略心跳周期未收到确认，心跳才视为丢失。Ctrl+C 会取消
会话，并在进程退出前清除所有活动状态。在 Windows 上，活动拥有者会绑定配置的 UDP
套接字，打开每个精确指定的 TAP 适配器，完成对等握手，并转发已认证的二层帧。无效
对等数据报会被丢弃而不会重连控制器；TAP、UDP 或工作线程故障会结束活动会话，并走
正常的失败关闭重连路径。
