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

## 创建网络和注册材料

```powershell
$Server = 'C:\Stella\stella-server.exe'
$Config = 'C:\Stella\server.toml'

$NetworkId = & $Server --config $Config network create --name 'Game LAN'
$EnrollmentToken = & $Server --config $Config enrollment-token create
$JoinToken = & $Server --config $Config join-token create --network $NetworkId

$NetworkId
$EnrollmentToken
$JoinToken
```

注册令牌和加入令牌都是 Bearer 凭据，默认一小时后过期，只输出一次，并在首次
成功使用时消耗。不要将它们写入 shell 历史、日志或源代码管理系统。请为每个
节点生成不同的令牌，不要在客户端之间共享。

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
