package netinfo

import (
	"runtime"
	"testing"
)

// TestGetSystem 校验系统信息采集的基本字段。
func TestGetSystem(t *testing.T) {
	s := GetSystem()
	if s.Hostname == "" {
		t.Error("hostname 不应为空")
	}
	if s.OS == "" || s.Arch == "" {
		t.Error("os/arch 不应为空")
	}
	if s.PID <= 0 {
		t.Errorf("pid 应 > 0, got %d", s.PID)
	}
}

// TestListInterfaces 校验能枚举出接口且结构可序列化（回环接口通常恒存在）。
func TestListInterfaces(t *testing.T) {
	ifaces, err := ListInterfaces()
	if err != nil {
		t.Fatalf("ListInterfaces: %v", err)
	}
	if runtime.GOOS == "linux" && len(ifaces) == 0 {
		t.Fatal("Linux 上不应枚举出 0 张网卡")
	}
	for _, ifc := range ifaces {
		if ifc.Name == "" {
			t.Error("网卡名不应为空")
		}
		if ifc.MTU < 0 {
			t.Errorf("%s: mtu 非法 %d", ifc.Name, ifc.MTU)
		}
	}
}

// TestListRoutes 校验 Linux 上路由表可解析（默认路由/直连路由通常存在）。
func TestListRoutes(t *testing.T) {
	routes, err := ListRoutes()
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}
	if runtime.GOOS != "linux" {
		return
	}
	// 不强制断言条数（容器可能为空表），只校验字段格式合法。
	for _, r := range routes {
		if r.Interface == "" {
			t.Error("路由出接口不应为空")
		}
	}
}
