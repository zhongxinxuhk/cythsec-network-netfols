# cythsec 统一构建入口。
# 所有目标转发到 scripts/ 下的脚本，避免在多处重复构建逻辑（见 CYS-INF-007）。
# 脚本用法：bash scripts/<x>/<x>-all.sh --help

.PHONY: build test lint fmt clean ci hooks check-hooks

# hooks：安装本仓库的 git 钩子（分支纪律 + 密钥兜底扫描）。
# core.hooksPath 是**本地配置、不随克隆走** —— 每个新克隆/新机器都要跑一次这一条，
# 忘了就等于没有钩子（make check-hooks 会把这种状态显式报出来）。
hooks:
	git config core.hooksPath scripts/hooks
	chmod +x scripts/hooks/pre-commit scripts/hooks/guard-agent-git.sh
	@echo "已安装：core.hooksPath = scripts/hooks（负责验证：make check-hooks）"

check-hooks:
	@bash scripts/verify/check-branch-policy.sh


build:
	bash scripts/build/build-all.sh

test:
	bash scripts/test/test-all.sh

lint:
	bash scripts/lint/lint-all.sh

fmt:
	bash scripts/fmt/fmt-all.sh

clean:
	rm -rf build/
	rm -rf target/
	@echo "已清理构建产物（build/ 与 target/）"

# ci：本地复现 CI 全流程（lint -> build -> test）。
ci: lint build test
	@echo "CI 全流程通过"
