# cythsec 开发 / 运行 / 部署手册

> 面向已搭好的最小纵向切片：**packet-engine(C++) → traffic-engine(Rust) → routerd(Go) → console(React)**。
> 本文档把「构建 → 测试 → 运行」的完整命令固化，覆盖两套环境：
> - **本机**（开发者 Windows/Mac，含 CLion/WebStorm 用法）
> - **openEuler 2403 sp4**（生产/联调目标，`192.168.159.128`）

---

## 0. 仓库布局速览

```
cythsec/
├── dataplane/
│   ├── packet-engine/      # C++17 高速收包（当前为 lib+CLI+CTest 最小工程）
│   └── traffic-engine/     # Rust 流量分析（Packet -> Flow -> Session）
├── services/routerd/       # Go 控制面服务：网络信息 HTTP API
├── web/console/            # React 前端，消费 routerd /api/v1
├── ml/                     # (空骨架)
├── platform/ storage/ ...  # (空骨架)
├── CMakeLists.txt          # 根 CMake（含 packet-engine）
├── Cargo.toml              # 根 Rust workspace（含 traffic-engine）
└── go.work                 # Go 多模块（routerd/policyd/dnsd/telemetryd）
```

---

## 1. packet-engine（C++）

### 本机构建 + 测试
```bash
cd dataplane/packet-engine
cmake -S . -B build && cmake --build build
ctest --test-dir build --output-on-failure   # 跑 packet_engine_unit
./build/hello_packet                          # 运行（打印 hello packet）
```

### 从仓库根构建（CLion 打开根目录会走这条）
```bash
cd cythsec
cmake -S . -B build && cmake --build build    # 产出 hello_packet / packet_engine / test_packet
ctest --test-dir build
```
> 根 `CMakeLists.txt` 已 `add_subdirectory(dataplane/packet-engine)`，并 `include(CTest)`，
> 因此无论独立目录还是从根 configure，`test_packet` 目标都可用。

### openEuler 上构建为 Linux ELF
```bash
# 在 openEuler（cmake 3.31 / g++ 12.3.1 已具备）
cmake -S packet-engine -B packet-engine/build -DCMAKE_BUILD_TYPE=Release
cmake --build packet-engine/build
file packet-engine/build/hello_packet   # ELF 64-bit LSB executable, x86-64
ctest --test-dir packet-engine/build
./packet-engine/build/hello_packet
```

---

## 2. traffic-engine（Rust）

### 本机构建 + 测试
```bash
cd dataplane/traffic-engine
cargo build --offline      # 零依赖，离线即可；产物 target/debug/traffic-engine
cargo test --offline       # 7 个单测
./target/debug/traffic-engine   # 运行演示 Packet->Flow->Session
```
> 提示：本工程零第三方依赖，`--offline` 可避免 cargo 联网更新索引而卡住。
> `target/` 与根目录 `Cargo.lock` 已被 .gitignore 忽略，不入库。

### openEuler 上构建
```bash
# cargo/rustc 1.96 已具备
cd /root/cythsec/dataplane/traffic-engine
cargo build --release
cargo test
file target/release/traffic-engine       # ELF 64-bit LSB pie executable
```

---

## 3. routerd（Go 控制面）

### 本机构建 / 运行 / 测试
```bash
cd services/routerd
export GOWORK=off GOPROXY=off GOTOOLCHAIN=local   # Windows 沙箱离线用
go build ./...
go test ./...
go run ./cmd/routerd -addr :8080
```

### openEuler 构建 + 运行
```bash
go build -o /usr/local/bin/routerd ./services/routerd/cmd/routerd
/usr/local/bin/routerd -addr 0.0.0.0:8080 &   # 或 systemd
curl http://127.0.0.1:8080/api/v1/routes      # 返回真实路由
```

### HTTP API
| 端点 | 说明 |
|---|---|
| `GET /healthz` | 健康检查 |
| `GET /api/v1/system` | hostname/os/arch/go/pid |
| `GET /api/v1/interfaces` | 网卡、IP、up/running 状态 |
| `GET /api/v1/routes` | IPv4 路由（Linux 读 /proc/net/route）|

---

## 4. console（React Web 控制面）

### 安装依赖
```bash
cd web/console
npm install        # 或 npm ci（有 package-lock.json）
```

### 开发运行（需 routerd 在 :8080 或指向它）
```bash
# 默认 vite proxy 指向 http://localhost:8080；如 routerd 在别处：
#   VITE_ROUTERD_TARGET=http://192.168.159.128:8080 npm run dev
npm run dev        # http://localhost:5173
```
> vite dev proxy 已把 `/api` 与 `/healthz` 转发到 routerd，前端无需 CORS 配置。

### 类型校验 + 生产构建
```bash
npx tsc --noEmit    # 类型把关（strict）
npm run build       # 产出 dist/
npm run preview     # 本地预览 dist
```

---

## 5. 纵向切片联调（本机）
在一个终端起后端、另一个起前端：
```bash
# 终端 A：routerd
cd services/routerd && go run ./cmd/routerd -addr :8080

# 终端 B：console
cd web/console && npm run dev   # 打开 http://localhost:5173
```
预期：侧栏 System/接口/路由 三页能渲染；顶栏显示 "routerd online"。
> Windows 上 `/routes` 为空（无 /proc/net/route）属正常，真实路由需 openEuler 上的 routerd。

---

## 6. openEuler 真实数据联调
openEuler 的 routerd 返回真实路由。若你的开发机能访问其 8080 端口，直接把 console 指向它即可看到真实数据。若网络隔离（如本沙箱），可用 SSH 隧道转发：
```bash
# 本地 8080 -> openEuler 的 routerd:8080
ssh -N -L 8080:127.0.0.1:8080 root@192.168.159.128
# 然后本机 console 正常 npm run dev（proxy 到 localhost:8080 即隧道终点）
```

---

## 7. 环境速查
| 环境 | 工具链 | 产物类型 |
|---|---|---|
| 本机 Windows | MinGW g++ 8.1 / go 1.22 / node 22 / cargo 1.91 | Windows PE / exe |
| openEuler 2403 sp4 | g++ 12.3 / go 1.25 / cmake 3.31 / cargo 1.96 | Linux ELF |
> 生产部署以 openEuler 构建的 ELF 为准；本机仅作语法冒烟与前端开发。

---

## 8. 常用排查
- **本机 go 在 workspace 下卡死**：加 `GOWORK=off GOPROXY=off GOTOOLCHAIN=local`。
- **cargo/npm 联网卡住**：零依赖工程用 `--offline`；npm 走 `registry.npmjs.org`（可达）。
- **CMake 从根 configure 失败**：确认 `ml/inference` 空源时用 INTERFACE 占位（已修复）。
- **vite 预览打不开**：vite 默认监听 IPv6 `[::1]`，用 `localhost` 而非 `127.0.0.1` 访问；沙箱对 127.0.0.1 有透明代理劫持。
