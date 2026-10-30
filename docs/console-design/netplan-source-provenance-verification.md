# NC-02B3B4A验收记录

日期：2026-10-29。证据目录：build/netplan-source-provenance。

| 检查 | 结果 |
| --- | --- |
| Go定向/race | 已退出0；来源遮蔽与跨目录文件名顺序、标量/序列、false/空值、嵌套bool/int区别、伪元数据原子拒绝 |
| YAML读取专项 | PyYAML6.0.3隔离测试环境；7个读取子场景及被遮蔽非法YAML测试通过，退出0；yaml-reader.log |
| 完整lint | 退出0，lint.log；包含新增Python支持代码的Ruff/Black检查及仓库其他检查 |
| 默认完整测试 | CYTHSEC_LIVE_SUDO=0、CYTHSEC_LIVE_IFACE=en0，无分组裁剪，退出0；test.log；前端25文件93项维持通过 |
| Go构建 | build-all.sh --go退出0，四个服务二进制均生成；build.log；本轮未修改前端，不重复前端生产构建 |
| Linux交叉编译 | amd64/arm64/loong64/mipsle均退出0；crosscompile.log；不代表运行认证 |
| 开发机采集回归 | 普通用户en0采集7027帧，7025解析成功/2不支持/0错误，15项断言通过；无注入目标，ICMP可见项不适用 |

默认Go测试的纯来源算法检查只用Python标准库；YAML读取专项独立显式运行：

```bash
CYTHSEC_NETPLAN_TEST_PYTHON=/path/to/python-with-pyyaml \
  go test -tags netplan_yaml ./internal/networkcfg \
  -run 'TestNetplanBoundedYAMLSourceReader|TestNetplanShadowedInvalidYAMLIsNotParsed' -v
```

该命令在services/routerd执行；tag专项不是默认CI隐含通过项。本轮使用build目录隔离环境，未修改系统Python或项目依赖锁。
Docker daemon未运行，未启动容器或修改主机网络；实际Linux Netplan命令、发行版矩阵和整体来源/设备归属仍未核验。
按用户要求不做macOS网关兼容适配、unsupported HTTP或界面复验。本轮后端变更不要求浏览器布局验证。
既有tshark DPI14、重组2、FlowRecord8裁判例外继续未核验；不合main、不推送、不执行sudo。

本地evidence-manifest.json绑定本轮提交、改动文件及已完成的测试日志/编译产物SHA-256；仅用于检测相对该清单的变化，
不是签名或可信时间证明。活动服务日志、隔离环境目录和会被后续覆盖的原始抓包不纳入固定清单。
