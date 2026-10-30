package networkcfg

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// NativeValidation is a parser result for this digest, never an apply permit.
type NativeValidation struct {
	DraftDigest string        `json:"draft_digest"`
	Backend     string        `json:"backend"`
	Platform    string        `json:"platform"`
	CheckedAt   time.Time     `json:"checked_at"`
	Status      string        `json:"status"`
	Scope       string        `json:"scope"`
	ToolVersion string        `json:"tool_version"`
	CanApply    bool          `json:"can_apply"`
	Checks      []NativeCheck `json:"checks"`
}
type NativeCheck struct {
	Artifact string `json:"artifact"`
	State    string `json:"state"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}
type NativeValidator struct {
	platform string
	euid     func() int
	find     func(string) (string, error)
	run      func(context.Context, string, []string, string, string) ([]byte, error)
	gate     chan struct{}
}

func NewNativeValidator() *NativeValidator {
	return &NativeValidator{runtime.GOOS, os.Geteuid, findNetworkTool, captureProbeCommand, make(chan struct{}, 1)}
}

func findNetworkTool(tool string) (string, error) {
	for _, dir := range []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"} {
		path := filepath.Join(dir, tool)
		if st, err := os.Stat(path); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0111 != 0 {
			return path, nil
		}
	}
	return "", os.ErrNotExist
}

func (v *NativeValidator) Validate(ctx context.Context, c Config) (NativeValidation, error) {
	p, err := Compile(c)
	if err != nil {
		return NativeValidation{}, err
	}
	select {
	case v.gate <- struct{}{}:
		defer func() { <-v.gate }()
	default:
		return NativeValidation{}, ErrObservationBusy
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	result := NativeValidation{DraftDigest: p.Digest, Backend: c.Backend, Platform: v.platform, Status: "unavailable", Scope: "parser", Checks: []NativeCheck{}}
	for _, a := range p.Artifacts {
		result.Checks = append(result.Checks, NativeCheck{a.Name, "unavailable", "not_checked", "尚未完成原生校验"})
	}
	finish := func(state, code, message string) (NativeValidation, error) {
		result.Status, result.CheckedAt = state, time.Now().UTC()
		for i := range result.Checks {
			result.Checks[i].State, result.Checks[i].Code, result.Checks[i].Message = state, code, message
		}
		return result, nil
	}
	if v.platform != "linux" {
		return finish("unsupported", "unsupported_platform", "当前平台不支持目标原生工具")
	}
	// Run parsers as the ordinary service account; never start a privileged helper.
	if v.euid() == 0 {
		return finish("unavailable", "unprivileged_worker_required", "原生校验需要非特权服务进程")
	}
	tool := map[string]string{"networkmanager": "nmcli", "netplan": "netplan", "openwrt": "uci"}[c.Backend]
	path, err := v.find(tool)
	if err != nil {
		return finish("unavailable", "tool_unavailable", "未找到目标原生工具")
	}
	dir, err := os.MkdirTemp("", "cythsec-native-*")
	if err != nil {
		return finish("unavailable", "workspace_unavailable", "无法创建私有校验目录")
	}
	defer os.RemoveAll(dir)
	dir, err = filepath.Abs(dir)
	if err != nil {
		return finish("unavailable", "workspace_unavailable", "无法定位私有校验目录")
	}
	if c.Backend == "networkmanager" {
		result.Scope = "offline_profile"
		raw, e := v.run(ctx, path, []string{"--version"}, "", dir)
		if e != nil {
			return finish("unavailable", "version_unavailable", "无法核对 nmcli 版本")
		}
		result.ToolVersion = readVersion(raw, "nmcli")
		parts := strings.Split(result.ToolVersion, ".")
		if len(parts) < 2 {
			return finish("unsupported", "offline_unavailable", "无法确认 nmcli 离线模式支持")
		}
		major, _ := strconv.Atoi(parts[0])
		minor, _ := strconv.Atoi(parts[1])
		if major < 1 || (major == 1 && minor < 40) {
			return finish("unsupported", "offline_unavailable", "nmcli 离线校验需要 1.40 或更高版本")
		}
	}
	if c.Backend == "netplan" {
		// Netplan can start units during early boot. Refuse unless systemd is settled;
		// --mapping parses without generating backend files, always in a private root.
		stateTool, e := v.find("systemctl")
		if e != nil {
			return finish("unavailable", "boot_state_unavailable", "无法核对系统启动阶段")
		}
		raw, e := v.run(ctx, stateTool, []string{"is-system-running"}, "", dir)
		state := strings.TrimSpace(string(raw))
		var exited *exec.ExitError
		if (e != nil && !errors.As(e, &exited)) || (state != "running" && state != "degraded") {
			return finish("unavailable", "boot_state_unavailable", "系统启动阶段不满足独立校验条件")
		}
		help, e := v.run(ctx, path, []string{"generate", "--help"}, "", dir)
		if e != nil || !bytes.Contains(help, []byte("--root-dir")) || !bytes.Contains(help, []byte("--mapping")) {
			return finish("unsupported", "isolated_parser_unavailable", "当前 Netplan 不支持隔离解析参数")
		}
		if e = os.MkdirAll(filepath.Join(dir, "etc", "netplan"), 0700); e != nil {
			return finish("unavailable", "workspace_unavailable", "无法创建私有配置目录")
		}
	}
	if c.Backend == "openwrt" {
		// UCI absolute-path export loads a package with has_delta=false: no host
		// /etc/config override or /tmp/.uci/network staging is merged into this check.
		if e := os.Mkdir(filepath.Join(dir, "delta"), 0700); e != nil {
			return finish("unavailable", "workspace_unavailable", "无法创建私有暂存目录")
		}
	}
	result.Status = "passed"
	for i, a := range p.Artifacts {
		var args []string
		input := ""
		switch c.Backend {
		case "networkmanager":
			args, input = []string{"--offline", "connection", "modify", "connection.autoconnect", "yes"}, a.Content
		case "netplan":
			if err = os.WriteFile(filepath.Join(dir, "etc", "netplan", a.Name), []byte(a.Content), 0600); err == nil {
				args = []string{"generate", "--root-dir", dir, "--mapping", c.Interfaces[0].Device}
			}
		case "openwrt":
			file := filepath.Join(dir, "network")
			if err = os.WriteFile(file, []byte(a.Content), 0600); err == nil {
				args = []string{"-c", dir, "-P", filepath.Join(dir, "delta"), "-s", "export", file}
			}
		}
		check := &result.Checks[i]
		if err != nil {
			check.Code, check.Message = "workspace_unavailable", "无法写入私有校验文件"
		} else {
			raw, runErr := v.run(ctx, path, args, input, dir)
			if runErr == nil && len(bytes.TrimSpace(raw)) > 0 {
				check.State, check.Code, check.Message = "passed", "parser_accepted", "原生解析校验通过"
			} else {
				check.Code, check.Message = "execution_incomplete", "原生工具未完成校验"
				var exited *exec.ExitError
				if errors.As(runErr, &exited) && exited.ExitCode() > 0 {
					check.State, check.Code, check.Message = "rejected", "parser_rejected", "原生工具拒绝配置，请核对目标版本与配置字段"
				}
			}
		}
		if check.State == "unavailable" {
			result.Status = "unavailable"
		} else if check.State == "rejected" && result.Status == "passed" {
			result.Status = "rejected"
		}
	}
	result.CheckedAt = time.Now().UTC()
	return result, nil
}
