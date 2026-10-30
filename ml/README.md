# ml/ — AI / ML

> 当前已有数据面/训练侧的特征契约与训练特征产物实现；训练、评估、模型注册与推理仍待开发。全量验收与合并状态见 `docs/planning/BACKLOG.md` M7。

| 子模块 | 语言 | 状态 |
| --- | --- | --- |
| `training/` | Python | ◐ 属性字典、21 维特征绑定与独立提取器；训练特征 CSV/清单构建与校验（CYS-MLT-006）已实现 |
| `inference/` | C++ | 纯构建骨架，无推理源码 |
| `model-registry/` | — | 仅 `.gitkeep` |

## training/

- `features/attributes_gen.py`：属性字典生成绑定。
- `features/schema_gen.py`：由 `configs/registry/features.json` 生成的特征版本、下标、名字、单位、定义与阈值；不得手抄布局。
- `features/extractor.py`：标准库独立 Python 提取器，对齐 Rust 的同一 21 维特征契约。
- `features/dataset.py`：从包观测 JSONL 提取，或从 FlowRecord v2 投影，产出严格定序的 CSV 与来源/版本/完整性清单；外部标签显式连接，无标签时明确标记，支持发布前/读取前校验。
- 输入契约、命令、示例和限制见 [features/README.md](training/features/README.md)。
- `training/pyproject.toml` / `.python-version` / `uv.lock`：Python 3.11.15 与 uv 0.12.1 钉扎，可安装包 `cythsec-training` 与命令 `cythsec-features`。构建工具有精确版本与锁文件摘要，wheel 无第三方运行时依赖；安装说明见 [training/README.md](training/README.md)。
- Python 工程门禁：`bash scripts/verify/check-training-project.sh`，默认全量测试和独立 CI Python job 也调用；远端 CI 尚未触发。
- Python 质量门禁：`bash scripts/verify/check-python-quality.sh`，Ruff/Black 检查 8 个手写文件，strict mypy 检查完整训练包 6 个文件；已挂 lint、默认测试与 CI，含实际工具反向注入。工具由独立 quality 分组锁定。
- 统一多格式加载器、切分、预处理、训练与评估尚未实现，分别按 MLT-003/004/005/008/010 推进。

验收：`bash scripts/test/test-all.sh --rust`（含既有特征 parity 与训练产物测试）；单独运行：`python3 -m unittest discover -s tests/ml -p 'test_feature_dataset.py' -v`。

## inference/

- 无源码时 CMake 落为 INTERFACE 占位库，`ENABLE_ONNXRUNTIME` 默认 OFF。
- ONNX Runtime、特征张量转换、推理 API 与热更新尚未实现。

## 数据链当前边界

```text
Rust 特征 / Python 包观测提取 → CSV + manifest（本批）
                              → 切分/预处理 → 训练/评估 → ONNX/推理（后续）
```

仓库示例与分组标签是合成测试数据，不代表真实标注数据集或模型效果。
