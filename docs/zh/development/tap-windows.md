# Windows TAP 实现

`stella-tap` 将 TAP-Windows Adapter V9 表示为安全、同步、完整帧的以太网设备。它应在专用
阻塞工作线程上运行，异步客户端运行时不得在 Tokio 工作线程上执行帧 I/O。

库只打开预先安装的适配器，不会安装或移除驱动、创建或删除适配器、重命名 Windows
连接、持久化 MAC 地址或重启微型端口。这些操作会影响不相关的 VPN 软件，属于安装或
管理员工具的职责。一个打开的 `WindowsTapDevice` 独占一个设备句柄；`destroy` 或 `Drop`
都会先请求介质断开状态。

后端通过 Windows IP Helper API 枚举适配器。`TapConfig::name` 可指定连接友好名称或接口
GUID（可带或不带花括号），匹配不区分大小写。未指定选择器时，只有刚好存在一个
TAP-Windows 候选项才会成功。打开设备路径后，Stella 查询驱动版本、当前 MAC 和驱动 MTU，
不支持 TAP 控制接口的路径会被拒绝。

`TapConfig` 分别定义 Windows 三层 MTU 和完整以太网帧最大值。读写使用重叠
`ReadFile`、`WriteFile` 和 `DeviceIoControl`；调用拥有自己的事件和 `OVERLAPPED` 存储直到
完成。写入先验证最小 14 字节和配置上限，短成功写入是内部不变量错误，不会再次提交余下
帧。错误或调试输出不包含原始以太网字节。

另一个线程可通过取消句柄调用 `CancelIoEx`。关闭顺序为停止提交新帧、取消待处理 I/O、
等待阻塞工作线程、调用 `destroy` 使介质断开并关闭设备。取消具有幂等性。
