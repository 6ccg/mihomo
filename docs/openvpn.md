# OpenVPN outbound（minivpn）集成说明

本项目将 OpenVPN 客户端能力（基于 `github.com/ooni/minivpn`）作为 mihomo 的一种 outbound 适配器接入，并使用 gVisor netstack 在进程内完成 L3 “虚拟网卡”桥接：mihomo 的 TCP/UDP 连接被转换为 IP 包，经 OpenVPN 隧道收发。

## 快速开始（Windows / PowerShell）

前置：
- 需要 `with_gvisor` 构建标签（OpenVPN outbound 依赖 gVisor netstack）。
- `config:` 路径会按 mihomo HomeDir（`-d` / `CLASH_HOME_DIR`）进行相对解析，并受 safe-path 校验影响。

验证配置（不建立 VPN 连接）：

```powershell
go run -tags with_gvisor . -t -d .. -f ..\openvpn-test.yaml
```

运行并触发 OpenVPN 连接（首次有流量时才会建隧道）：

```powershell
go run -tags with_gvisor . -d .. -f ..\openvpn-test.yaml
```

另起一个终端，通过本地 HTTP 代理发起一次请求以触发 OpenVPN：

```powershell
curl.exe -I --proxy http://127.0.0.1:7890 http://example.com
```

## 配置字段（`type: openvpn`）

示例见 `docs/config.yaml`，最小配置如下：

```yaml
proxies:
  - name: ovpn
    type: openvpn
    config: vpn.ovpn
    # username: user
    # password: pass
    # timeout: 60
    # dialer-proxy: "ss1"
    # ip-version: dual
```

字段说明：
- `config`：`.ovpn` 配置文件路径；相对路径会基于 HomeDir（`-d`）解析；必须满足 safe-path（或通过 `SAFE_PATHS`/`SKIP_SAFE_PATH_CHECK` 放行）。
- `username`/`password`：可覆盖 `.ovpn` 中的认证信息；最终需满足 minivpn 的 `HasAuthInfo()`。
- `timeout`：首次建隧道（握手）超时（秒）；默认 `60s`。
- `dialer-proxy`：用于 OpenVPN 控制通道/数据通道的“底层拨号器代理”（即 OpenVPN 先通过该 outbound 出去，再连到 VPN 服务器）。
- `ip-version`：与其他 outbound 一致，控制 DNS/拨号偏好（`dual`/`ipv4`/`ipv6`/`ipv4-prefer`/`ipv6-prefer`）。同时为了减少不必要的 `network is unreachable` 噪音，OpenVPN outbound 会在隧道明确是单栈时自动收敛到可用栈；若你显式强制了不可用的栈（例如 IPv4-only 隧道上配置 `ip-version: ipv6`），则预期会无法联网。

## IPv6 说明

如果服务端只下发了 IPv4（例如只看到 `Tunnel IP: 10.x.x.x`），则该 OpenVPN 隧道本身就是 IPv4-only：访问 IPv6 目的地址会失败并出现 `network is unreachable`，这是预期行为。

为减少双栈域名的 AAAA/IPv6 拨号噪音，OpenVPN outbound 会在隧道明确是单栈时自动收敛：

- 只分配了 IPv4（例如只看到 `Tunnel IP: 10.x.x.x`）→ 自动 IPv4 only（只查 A、只拨 IPv4）
- 只分配了 IPv6 → 自动 IPv6 only（只查 AAAA、只拨 IPv6）
- 同时分配了 v4/v6 → 维持 dual-stack

因此在 IPv4-only 的 OpenVPN 隧道下，访问 IPv6-only 目的地址仍会失败（可能出现 `network is unreachable`），这是预期行为。

如需全局禁用 IPv6（阻断所有 IPv6 连接并屏蔽 DNS AAAA），可在主配置中设置 `ipv6: false`。

## 调试

gVisor/OpenVPN 方向包日志（仅 `log-level: debug` 生效）：

- `MIHOMO_OPENVPN_LOG_ALL=1`：打印所有包
- `MIHOMO_OPENVPN_LOG_FIRST=200`：只打印前 N 个包（默认 5）
- `MIHOMO_OPENVPN_LOG_EVERY=100`：之后每隔 N 个包打印一次（默认 100；设为 0 表示不再间隔打印）
- `MIHOMO_OPENVPN_LOG_STATS=1`：随包打印 gVisor TCP/IP 统计计数（用于定位丢包/握手问题）

## 注意事项

- **必须使用 `with_gvisor`**：否则 OpenVPN outbound 会报错（配置校验/运行期均会提示）。
- **minivpn 只支持 OpenVPN 子集**：`.ovpn` 中不支持的指令会以 `unsupported key` 形式告警，但不一定影响建立隧道。
- **DNS 与 OpenVPN push**：minivpn 会解析并打印服务端 `PUSH_REPLY`（如 `dhcp-option DNS ...`），但当前实现只映射 `IP/Netmask/MTU` 到 gVisor；是否采用 push DNS 取决于 mihomo 的 DNS 配置。
