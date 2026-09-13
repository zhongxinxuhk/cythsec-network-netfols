# cythsec 统一构建入口。
# 所有目标转发到 scripts/ 下的脚本，避免在多处重复构建逻辑（见 CYS-INF-007）。
# 脚本用法：bash scripts/<x>/<x>-all.sh --help

.PHONY: build test lint fmt clean ci

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
