# ml/ — AI / ML

> 模型训练（Python）与生产推理（C++）闭环。**当前处于早期：大部分是占位骨架**（规划见 `docs/planning/BACKLOG.md` M7，37 任务）。

| 子模块 | 语言 | 状态 |
| --- | --- | --- |
| `training/` | Python | 🚧 仅属性字典绑定；其余目录占位 |
| `inference/` | C++ | 🚧 纯构建骨架，无源码 |
| `model-registry/` | — | 🚧 空 |

---

## training/（Python）

- **唯一实质文件**：`features/attributes_gen.py`（1051 行，codegen 生成）
  - 属性字典 Python 绑定，头注释要求：**训练侧必须从本模块导入常量，不得写字面量**
- 占位目录：`datasets/` `preprocessing/` `models/` `experiments/` `evaluation/` `scripts/`
- ⚠️ 暂无 `pyproject.toml` / `requirements.txt`，依赖管理待补

## inference/（C++）

- `CMakeLists.txt` 用 `file(GLOB_RECURSE src/*.cpp)`：无源码时自动落 **INTERFACE 占位库**，保证根 CMake 聚合不断链
- CMake 选项 `ENABLE_ONNXRUNTIME` 默认 **OFF**，ONNX Runtime 尚未实际接入
- 占位目录：`include/` `src/` `onnx/` `runtime/`

## model-registry/

- 仅 `.gitkeep`。规划承载：模型版本、指标、来源元数据。

## 数据流（规划态）

```
traffic-engine 特征提取 ──► datasets/features ──► training 训练 ──► model-registry 登记
                                                                      │
                                                  inference (ONNX Runtime) ◄──┘
```

## 相关

- 属性字典真源：`configs/README.md`（98 条属性定义训练/推理侧共同词汇）
- 绑定再生成：`tools/codegen/gen-attributes.py` → `python3 ml/training/features/attributes_gen.py` 所依赖的真源
