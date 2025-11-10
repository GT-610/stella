# Stella 测试计划

## 第一阶段：交换机核心逻辑测试

### 1. 交换机结构测试
- [x] 测试交换机结构体的初始化 (TestSwitcherCreation)
- [x] 测试交换机状态转换 (TestSwitcherStartStop)
- [x] 测试交换机生命周期管理 (TestSwitcherStartStop)

### 2. 端口管理测试
- [x] 测试端口创建和配置 (TestPortManagement)
- [x] 测试端口状态管理（基本功能）
- [x] 测试端口删除和资源释放 (TestPortManagement)

## 第二阶段：MAC地址表管理测试

### 1. MAC地址学习测试
- [x] 测试从数据包中学习源MAC地址 (TestMACTableLearning)
- [x] 测试MAC地址与端口的绑定 (TestMACTableLearning)
- [x] 测试MAC地址表容量限制处理 (TestMACTableCapacityHandling)

### 2. MAC地址老化测试
- [ ] 测试MAC地址超时老化机制
- [x] 测试活跃MAC地址的刷新 (TestMACTableLearning)
- [ ] 测试老化时间配置

### 3. MAC地址表查找测试
- [ ] 测试单条MAC地址查询
- [ ] 测试批量MAC地址查询
- [ ] 测试不存在的MAC地址处理
- [ ] 测试MAC地址表性能优化

## 第三阶段：数据包转发测试

### 1. 单播数据包转发
- [ ] 测试已知MAC地址的数据包转发
- [x] 测试未知MAC地址的泛洪转发（基础框架）
- [ ] 测试自环数据包处理

### 2. 广播数据包转发
- [x] 测试广播数据包的正确泛洪（基础框架）
- [ ] 测试广播抑制功能（如果实现）

### 3. 数据包过滤测试
- [x] 测试基于端口的过滤（基本功能）
- [ ] 测试基于MAC地址的过滤
- [ ] 测试特殊帧处理（如PAUSE帧）

## 第四阶段：VLAN支持测试

### 1. VLAN配置测试
- [x] 测试VLAN创建和删除（在vlan_test.go中实现）
- [x] 测试端口VLAN配置（Access、Trunk模式）（在vlan_integration_test.go中实现）
- [x] 测试Native VLAN配置（在vlan_test.go中实现）

### 2. VLAN数据包处理
- [x] 测试Access端口的VLAN标记/去标记（在vlan_test.go中实现）
- [x] 测试Trunk端口的多VLAN转发（在vlan_integration_test.go中实现）
- [x] 测试VLAN间隔离功能（在vlan_integration_test.go中实现）

### 3. VLAN过滤测试
- [x] 测试VLAN过滤规则应用（在switcher.go中实现并在集成测试中验证）
- [x] 测试未标记帧处理（在HandlePacket方法中实现）

## 第五阶段：多播支持测试

### 1. IGMP监听测试 - 已在 `test/switcher/igmp_test.go` 实现
- [x] 测试IGMP报文解析
- [x] 测试IGMP Join/Leave消息处理
- [x] 测试多播组成员管理

### 2. 多播转发测试 - 已在 `test/switcher/multicast_integration_test.go` 实现
- [x] 测试多播数据转发到组成员
- [x] 测试多播数据过滤
- [x] 测试IGMP查询功能

### 3. 多播组管理 - 已在 `test/switcher/multicast_test.go` 实现
- [x] 测试多播组创建和删除
- [x] 测试组成员添加和删除
- [x] 测试组成员超时管理

## 第六阶段：集成测试

### 1. 交换机与传输层集成测试
- [ ] 测试交换机与UDP传输层的集成
- [ ] 测试数据包加密/解密与转发的配合
- [ ] 测试连接管理与端口状态的同步

### 2. 节点与交换机集成测试
- [ ] 测试节点启动时交换机的初始化
- [ ] 测试节点状态变化时交换机的响应
- [ ] 测试节点关闭时资源清理

### 3. 基本功能集成测试
- [x] 测试交换机基本功能组合 (TestPacketHandlingBasic)

## 第七阶段：系统测试（使用Incus容器）

### 1. 网络连通性测试
- [ ] 使用Incus创建多个容器，模拟不同节点
- [ ] 验证节点间的网络连通性
- [ ] 测试跨容器的TCP/UDP通信

### 2. 广播/多播测试
- [ ] 测试广播消息的正确传播
- [ ] 测试多播应用（如mDNS、IGMP）
- [ ] 测试组播流量复制

### 3. VLAN隔离测试
- [ ] 在不同VLAN中创建容器
- [ ] 验证VLAN间隔离
- [ ] 测试跨VLAN通信（如果支持）

### 4. 链路故障恢复测试
- [ ] 模拟链路断开和恢复
- [ ] 测试MAC地址表更新
- [ ] 测试连接重建

## 第八阶段：性能测试

### 1. 吞吐量测试
- [ ] 测试不同数据包大小下的吞吐量
- [ ] 测试单端口和多端口吞吐量
- [ ] 测试VLAN和非VLAN配置下的性能差异

### 2. 延迟测试
- [ ] 测试数据包转发延迟
- [ ] 测试MAC地址学习延迟
- [ ] 测试不同负载下的延迟变化

### 3. 并发连接测试
- [ ] 测试同时处理的最大连接数
- [ ] 测试大量MAC地址的学习和查找性能
- [ ] 测试高负载下的稳定性

## 测试工具和环境准备

### 1. 单元测试和集成测试工具
- [x] Go标准测试框架
- [x] testify断言库

### 2. 系统测试环境
- [x] Incus容器环境配置
- [ ] 网络测试工具安装（ping, iperf, mz）
- [ ] 流量分析工具配置（Wireshark/tcpdump）

### 3. 性能测试工具
- [x] Go的基准测试功能
- [ ] iperf3安装和配置
- [ ] 自定义延迟测量工具开发