# 开发初始化说明（mihomo + minivpn submodule）

本仓库是 `mihomo` 的 fork，并在 outbound 中集成了 OpenVPN（基于 `github.com/ooni/minivpn`）。为保证可复现构建与便于协作，`minivpn` 以 Git submodule 形式固定在 `third_party/minivpn`，`go.mod` 通过 `replace` 指向该子模块。

## 1. 初始化

推荐直接递归拉取子模块：

```bash
git clone --recurse-submodules https://github.com/6ccg/mihomo.git
```

如果已经 clone：

```bash
git submodule update --init --recursive
```

## 2. 项目结构速览

- `adapter/outbound/openvpn.go`：OpenVPN outbound 入口（适配 mihomo 的 `C.ProxyAdapter`），负责：
  - 解析 `.ovpn`（minivpn config）
  - 首次流量触发时建立隧道 `minivpn/pkg/tunnel.Start`
  - 根据隧道实际单栈/双栈自动收敛 `ip-version`（降低不必要的 unreachable 噪音；若用户强制不可用栈则可能无法联网）
- `adapter/outbound/openvpn_stack_gvisor.go`：`with_gvisor` 下的桥接实现：
  - 使用 gVisor netstack 在进程内提供 TCP/UDP（L4）
  - 将 netstack 的 IP 包写入 minivpn 的 `TUN`（OpenVPN data channel）
- `adapter/outbound/openvpn_stack_stub.go`：未开启 `with_gvisor` 时的 stub（提示缺少 tag）
- `docs/openvpn.md`：OpenVPN outbound 的使用/调试说明
- `third_party/minivpn`：`github.com/6ccg/minivpn` 子模块（你的 minivpn fork）

## 3. OpenVPN 集成的“兼容接口”与数据流

### 3.1 mihomo 侧接口（outbound 层）

OpenVPN outbound 内部通过一个很小的设备接口与具体实现解耦：

```go
type openvpnDevice interface {
    DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
    ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error)
    Start() error
    Close() error
}
```

`OpenVPN`（见 `adapter/outbound/openvpn.go`）负责生命周期与配置；实际“拨号/收包”由 `openvpnDevice` 完成（当前是 gVisor netstack 版本）。

### 3.2 minivpn 侧接口（TUN 语义）

`minivpn/pkg/tunnel.Start` 返回 `*tunnel.TUN`（类型别名到 `internal/tun.TUN`），其核心语义是：

- `Read([]byte)`：读出 **IP 包**（从 OpenVPN 隧道上来）
- `Write([]byte)`：写入 **IP 包**（下发到 OpenVPN 隧道）
- `LocalAddr()/RemoteAddr()/NetMask()/MTU()`：隧道分配信息（用于在 gVisor 侧配置地址/路由）

### 3.3 数据流（从浏览器到 OpenVPN）

1) 应用 -> mihomo（HTTP/SOCKS 入站）  
2) 规则选择到 `type: openvpn` outbound  
3) outbound 将目标 `tcp/udp` 连接交给 gVisor netstack（在进程内生成/处理 IP 包）  
4) netstack 产出的 IP 包 -> 写入 minivpn `TUN.Write` -> OpenVPN 隧道  
5) 反方向：OpenVPN 隧道的 IP 包 -> `TUN.Read` -> 投递给 netstack -> 回到应用连接

### 3.4 控制通道 TLS 保护（minivpn）

minivpn 已支持 OpenVPN 控制通道的 `tls-auth` / `tls-crypt` / `tls-crypt-v2`：

- `.ovpn` 中只应启用一种（互斥）。
- 支持文件路径或内联块（`<tls-auth>` / `<tls-crypt>` / `<tls-crypt-v2>`）；若使用路径，按 `.ovpn` 所在目录相对解析，并需位于该目录下（与 `ca/cert/key` 规则一致）。
- `tls-crypt-v2` 需提供 client key（`-----BEGIN OpenVPN tls-crypt-v2 client key-----`）。

### 3.5 NCP / data channel cipher 协商（重要）

OpenVPN 2.5+ 可能会在 `PUSH_REPLY` 中推送 `cipher ...`（NCP / data-ciphers 的协商结果），其值可能与 `.ovpn` 里的 `cipher ...` 不同。
例如：配置里是 `AES-256-CBC`，但服务端 push 为 `AES-256-GCM`。

如果客户端仍按 `.ovpn` 的 `cipher` 初始化 data channel，就会出现典型症状：

- TLS 握手成功、拿到 Tunnel IP/GW，但 TCP/UDP 业务流量全部超时
- 日志出现 `error decrypting: cannot decrypt: cannot decode: too short (...)`（常见原因是把 AEAD(GCM) 数据包按 CBC+HMAC 去解析）

当前实现：minivpn 收到 `PUSH_REPLY` 后会优先采用服务端推送的 `cipher`（若在 `SupportedCiphers` 内），并在首把 data key 到达后再初始化 data channel，确保加解密路径与服务端一致。
`.ovpn` 中的 `cipher` 作为 fallback（服务端不推送 cipher 或推送不支持时）。

## 4. 开发建议（推荐工作流）

### 4.1 只改 mihomo（不动 minivpn）

直接在本仓库开发、提交即可；构建时会使用 `third_party/minivpn` 的固定版本。

### 4.2 需要改 minivpn（推荐在 submodule 内开发）

```bash
cd third_party/minivpn
git checkout -b fix/xxx
# 修改、测试
git commit -m "..."
git push -u origin fix/xxx
```

然后回到 mihomo 记录 submodule 指针更新：

```bash
cd ../..
git add third_party/minivpn
git commit -m "chore: bump minivpn"
git push
```

### 4.3 同步上游

- `mihomo` 上游：`MetaCubeX/mihomo`
- `minivpn` 上游：`ooni/minivpn`

建议在两个仓库都保留 `upstream` remote，用 `fetch/merge` 或 `rebase` 按需同步；当 `minivpn` 有更新时，先在 submodule 内完成同步并推到你的 fork，再在 mihomo 里 bump submodule 指针。

## 5. 运行/调试（OpenVPN）

详见 `docs/openvpn.md`。常用调试环境变量（需 `log-level: debug`）：

- `MIHOMO_OPENVPN_LOG_ALL=1`
- `MIHOMO_OPENVPN_LOG_FIRST=200`
- `MIHOMO_OPENVPN_LOG_EVERY=100`
- `MIHOMO_OPENVPN_LOG_STATS=1`

minivpn 侧（更底层的 wire/packet/HMAC 排查）：

- `MINIVPN_DEBUG_WIRE=1`：打印收发原始包
- `MINIVPN_DEBUG_PACKET=1`：打印 packet marshal/parse 关键字段
- `MINIVPN_DEBUG_HMAC=1`：打印 tls-auth HMAC 的输入与校验结果
- `MINIVPN_DEBUG_KEY=1`：打印 tls-auth key 的分块与选取结果
- `MINIVPN_DEBUG_ALL=1`：打开所有 minivpn debug 开关
