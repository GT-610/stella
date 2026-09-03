# macOS 开发环境

## 前置条件

- 带内置 feth、BPF 与 AF_NDRV 支持的当前 macOS；
- 仓库默认 stable Rust 与 Cargo；
- 用于 VitePress 的 Bun；
- 用于真实双节点 verifier、带 `pip` 的 Python 3；
- 运行活动 TAP 客户端和真实 feth 测试所需的 root 权限。

纯 Rust 测试、配置解析、文档和 release 构建不需要 root；活动 macOS 数据平面需要。本里程碑
刻意不安装 kext、DriverKit 扩展、特权 helper 或 daemon。

## 验证工作区

开发时使用默认 stable。工作区保留 `rust-version = "1.85"` 作为声明的最低版本，但正常
开发不要求另外安装 1.85 toolchain。

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
bun run docs:build
```

## 选择 feth pair

每个 Stella 网络分配两个未使用、彼此不同的数值型 feth 名称。例如节点 A 使用 `feth100`
作为宿主可见端，使用 `feth101` 作为 Stella 报文 I/O peer。不要使用物理接口、不要在 peer
上配置 IP，也不要与另一个运行中的 Stella 实例共享任一名称。

活动客户端首次打开时创建 pair。正常关闭会把 visible 端置 down，但保留两个接口。下次
启动会复用它们，因此 visible 端的 IP 可以跨客户端重启保留，直到机器重启或管理员删除
接口。

## 初始化并加入客户端

按服务器和客户端 CLI 指南初始化控制器与客户端。macOS 的 join 必须增加 peer 名称：

```sh
target/debug/stella-client --config /path/to/client.toml join \
  --network <id> \
  --token <unpadded-base64url-token> \
  --enrollment-token <unpadded-base64url-token> \
  --tap-adapter feth100 \
  --tap-peer feth101
```

以 root 运行活动客户端：

```sh
sudo target/debug/stella-client --config /path/to/client.toml run
```

日志出现 `macOS data plane is active` 后，只在 visible 端配置地址或运行 DHCP：

```sh
sudo ifconfig feth100 inet 10.77.0.1 netmask 255.255.255.0 up
```

Stella 只传输以太网帧，不分配 IP，也不提供 DHCP。同一虚拟网络中的主机需要兼容的地址
规划。

## 真实设备验证

先以普通用户编译被忽略的平台测试，再以 root 运行生成的二进制，避免 Cargo 产物归 root
所有：

```sh
cargo test -p stella-tap --test macos_tap --no-run
sudo "$(find target/debug/deps -type f -name 'macos_tap-*' -perm -111 -print -quit)" \
  --ignored --nocapture
```

使用四个未占用名称运行真实控制器、真实客户端场景：

```sh
cargo build --release -p stella-server -p stella-client
sudo ./tests/two-node-lan/run-macos.sh \
  --skip-build \
  --python /opt/homebrew/bin/python3
```

脚本会拒绝已有的所选名称，验证首轮和同配置重启，把报告与进程日志写入仅创建的 artifact
目录，并且只删除它确认可由本次运行创建的四个接口。

手工管理 pair 时，删除前必须停止所有 owner。删除任一端属于管理员操作，会丢弃持久接口
以及本次开机期间保留的 IP 配置：

```sh
sudo ifconfig feth101 destroy
sudo ifconfig feth100 destroy
```
