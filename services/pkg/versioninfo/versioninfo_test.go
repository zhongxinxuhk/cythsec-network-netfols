package versioninfo

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultsWhenNotInjected(t *testing.T) {
	// 单元测试环境下未经 -ldflags 注入，应保留占位值而非空串。
	i := Get()
	if i.Version == "" {
		t.Error("Version 不应为空串")
	}
	if i.Commit == "" {
		t.Error("Commit 不应为空串")
	}
	if i.BuildTime == "" {
		t.Error("BuildTime 不应为空串")
	}
	if i.OS != runtime.GOOS {
		t.Errorf("OS 期望 %q，实际 %q", runtime.GOOS, i.OS)
	}
	if i.Arch != runtime.GOARCH {
		t.Errorf("Arch 期望 %q，实际 %q", runtime.GOARCH, i.Arch)
	}
	if !strings.HasPrefix(i.GoVersion, "go") {
		t.Errorf("GoVersion 期望以 go 开头，实际 %q", i.GoVersion)
	}
}

// 模拟 -ldflags 注入后的取值（直接改写包级变量，等价于链接期注入的效果）。
func TestInjectedValues(t *testing.T) {
	origV, origC, origB := Version, Commit, BuildTime
	defer func() { Version, Commit, BuildTime = origV, origC, origB }()

	Version = "1.2.3"
	Commit = "abc1234"
	BuildTime = "2026-09-14T02:00:00Z"

	i := Get()
	if i.Version != "1.2.3" || i.Commit != "abc1234" || i.BuildTime != "2026-09-14T02:00:00Z" {
		t.Fatalf("注入值未生效: %+v", i)
	}

	s := String()
	for _, want := range []string{"1.2.3", "commit abc1234", "built 2026-09-14T02:00:00Z", runtime.GOOS + "/" + runtime.GOARCH} {
		if !strings.Contains(s, want) {
			t.Errorf("String() 缺少 %q: %s", want, s)
		}
	}
}

// 空串注入应回退为占位值（避免 /api/v1/version 返回空字段）。
func TestEmptyInjectionFallsBack(t *testing.T) {
	origV, origC, origB := Version, Commit, BuildTime
	defer func() { Version, Commit, BuildTime = origV, origC, origB }()

	Version, Commit, BuildTime = "", "", ""
	i := Get()
	if i.Version != "dev" || i.Commit != "unknown" || i.BuildTime != "unknown" {
		t.Fatalf("空串应回退占位值: %+v", i)
	}
}

func TestJSONFieldNames(t *testing.T) {
	// /api/v1/version 直接序列化本结构，字段名属对外契约，须固定。
	b, err := json.Marshal(Info{})
	if err != nil {
		t.Fatalf("意外错误: %v", err)
	}
	for _, key := range []string{`"version"`, `"commit"`, `"build_time"`, `"go_version"`, `"os"`, `"arch"`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("JSON 缺少字段 %s: %s", key, b)
		}
	}
}
