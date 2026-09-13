# Windows TAP 实现

`stella-tap` 将 TAP-Windows Adapter V9 表示为安全、同步、完整帧的以太网设备。它应在专用
阻塞工作线程上运行，异步客户端运行时不得在 Tokio 工作线程上执行帧 I/O。

库要求 Windows Driver Store 中已经存在已签名的 TAP-Windows Adapter V9 驱动包。它不会
安装或移除驱动包、持久化 MAC 地址、编辑驱动 MTU 或重启微型端口；这些操作可能影响
其他 VPN 软件，仍由安装程序或管理员负责。

Stella 会管理自己命名的 root 设备生命周期。`ensure_adapter` 会复用匹配适配器，或通过
SetupAPI 以硬件 ID `tap0901` 创建设备，让 `DiInstallDevice` 从 Driver Store 选择已有签名
驱动包，等待 `NetCfgInstanceId` 出现，再设置 Windows 连接名称；注册后的任一步失败都会
删除半成品。`remove_adapter` 通过 SetupAPI 删除匹配设备；若 Windows 不要求重启，还会
等待接口消失。

客户端将每个网络映射为 `Stella <32位网络ID>`。`join` 在使用凭据前确保该持久适配器，
`run` 会补建丢失设备，普通关闭只把它置为 media-disconnected 以便复用，`leave` 才删除。
这些设备管理操作需要提升权限。一个打开的 `WindowsTapDevice` 独占一个设备句柄；
`destroy` 或 `Drop` 都会先请求介质断开状态。

后端通过 Windows IP Helper API 枚举适配器。`TapConfig::name` 可指定连接友好名称或接口
GUID（可带或不带花括号），匹配不区分大小写。友好名称不存在时会自动配置；GUID 不存在
仍返回未找到。未指定选择器时，只有刚好存在一个 TAP-Windows 候选项才会成功。打开设备
路径后，Stella 查询驱动版本、当前 MAC 和驱动 MTU，不支持 TAP 控制接口的路径会被拒绝。

`TapConfig` 分别定义 Windows 三层 MTU 和完整以太网帧最大值。读写使用重叠
`ReadFile`、`WriteFile` 和 `DeviceIoControl`；调用拥有自己的事件和 `OVERLAPPED` 存储直到
完成。写入先验证最小 14 字节和配置上限，短成功写入是内部不变量错误，不会再次提交余下
帧。错误或调试输出不包含原始以太网字节。

另一个线程可通过取消句柄调用 `CancelIoEx`。关闭顺序为停止提交新帧、取消待处理 I/O、
等待阻塞工作线程、调用 `destroy` 使介质断开并关闭设备。取消具有幂等性。

Windows 单元测试还覆盖托管名称边界和硬件 ID 编码。一个可选平台测试打开已有真实适配器
并验证完整帧与取消；另一个提升权限测试创建、复用、打开并删除名称唯一的适配器。两个
测试都会清理各自拥有的状态。
