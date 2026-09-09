# 快速开始

本页介绍 Stella 参考程序当前最短的入网路径。Stella 仍是实验性软件；目前需要从源码
构建，Windows 和 macOS 客户端还需要准备原生二层接口。邀请机制会减少需要人工搬运的
控制器身份、证书固定值和令牌，但不会削弱这些校验。

## 加入已有网络

请先从管理员处取得：

- `stella-client`，以及 macOS 所需的 `stella-tap-helper`；
- 一个以 `stella1:` 开头的一次性邀请；
- Windows TAP-Windows 适配器名称，或两个未占用的 macOS feth 名称；
- 管理员为该二层网络安排的 IP 地址和子网掩码。

邀请包含一次性 Bearer 凭据，默认一小时后过期。请使用可信私密渠道传递，不要发布到
聊天群、日志、工单或源代码仓库。

Windows 在提升权限的 PowerShell 中执行：

```powershell
$Invitation = Read-Host 'Stella invitation'
$Invitation | C:\Stella\stella-client.exe --config C:\Stella\client.toml join `
  --invite-file - `
  --display-name $env:COMPUTERNAME `
  --tap-adapter 'Stella LAN'
$Invitation = $null
```

macOS 执行：

```sh
printf 'Stella invitation: ' >&2
IFS= read -r -s invitation
printf '\n' >&2
printf '%s\n' "$invitation" | stella-client --config /etc/stella/client.toml join \
  --invite-file - \
  --display-name "$(scutil --get ComputerName)" \
  --tap-adapter feth100 \
  --tap-peer feth101
unset invitation
```

`--invite-file -` 从标准输入读取邀请，因此邀请不会出现在进程参数列表或 shell 历史中；
也可以改为提供一个权限受保护的邀请文件路径。

当配置不存在时，`join` 会从邀请创建受保护的节点身份和严格的控制器信任配置，然后
注册节点并加入网络。配置已经存在时，它要求邀请中的控制器地址、TLS 名称、Controller
ID 和 SPKI pin 与现有信任完全匹配。成功后可查看本地配置状态：

```powershell
C:\Stella\stella-client.exe --config C:\Stella\client.toml status
```

## 配置二层接口

Stella 透明传输以太网帧，不分配 IP，也不提供 DHCP。请按管理员安排，在 Windows 的
`Stella LAN` 或 macOS 的宿主可见端 `feth100` 上配置地址。不同节点必须位于同一虚拟
子网且地址不能冲突。

macOS 还需要先在一个终端启动特权范围受限的 helper：

```sh
sudo stella-tap-helper --allow-uid "$(id -u)"
```

## 运行客户端

Windows：

```powershell
C:\Stella\stella-client.exe --config C:\Stella\client.toml run
```

macOS 在另一个终端运行：

```sh
stella-client --config /etc/stella/client.toml run
```

## 创建网络和邀请

以下命令假定控制器已经按[服务器部署指南](./server-deployment)完成初始化和连接服务
配置。先创建网络：

```powershell
$NetworkId = & C:\Stella\stella-server.exe --config C:\Stella\server.toml `
  network create --name 'Game LAN'
```

为每台客户端分别生成邀请。`--controller` 必须是该客户端实际能够访问的数值地址，
`--tls-name` 必须包含在控制器证书中：

```powershell
& C:\Stella\stella-server.exe --config C:\Stella\server.toml invite create `
  --network $NetworkId `
  --controller 203.0.113.10:44900 `
  --tls-name controller.example.net
```

命令只输出一次邀请。每个邀请只能供一个新节点使用；不要在多台设备之间复用。控制器
运行后，客户端即可按本页第一节加入。

需要分别管理注册令牌、加入令牌或多个 SPKI pin 时，仍可使用[客户端 CLI](../api/client-cli)
和[服务器 CLI](../api/server-cli)中的精细命令。
