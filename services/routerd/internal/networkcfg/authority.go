package networkcfg

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type SourceSafety struct {
	UID    *uint32  `json:"uid"`
	GID    *uint32  `json:"gid"`
	Mode   string   `json:"mode"`
	Stable *bool    `json:"stable"`
	Status string   `json:"status"`
	Codes  []string `json:"codes"`
}
type ManagerReferences struct {
	State      string    `json:"state"`
	Scope      string    `json:"scope"`
	ObservedAt time.Time `json:"observed_at"`
	Diagnostic string    `json:"diagnostic"`
}
type AuthorityIssue struct {
	SourceID  string `json:"source_id"`
	Reference string `json:"reference"`
	Severity  string `json:"severity"`
	Code      string `json:"code"`
	Message   string `json:"message"`
}
type AuthorityReport struct {
	Status   string           `json:"status"`
	CanAdopt bool             `json:"can_adopt"`
	Issues   []AuthorityIssue `json:"issues"`
}

func sourceSafety(info os.FileInfo, backend string) *SourceSafety {
	s := &SourceSafety{Status: "unknown", Codes: []string{}}
	if info == nil {
		return s
	}
	s.Mode = fmt.Sprintf("%04o", info.Mode().Perm())
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		uid, gid := st.Uid, st.Gid
		s.UID, s.GID = &uid, &gid
	}
	if s.UID == nil {
		return s
	}
	s.Status = "meets_baseline"
	if !info.Mode().IsRegular() {
		s.Codes = append(s.Codes, "not_regular_file")
		s.Status = "blocked"
	}
	if *s.UID != 0 {
		s.Codes = append(s.Codes, "owner_not_root")
		s.Status = "blocked"
	}
	if info.Mode().Perm()&0022 != 0 {
		s.Codes = append(s.Codes, "group_or_other_writable")
		s.Status = "blocked"
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		s.Codes = append(s.Codes, "special_permission_bits")
		s.Status = "blocked"
	}
	if backend == "networkmanager" && info.Mode().Perm()&0077 != 0 {
		s.Codes = append(s.Codes, "nm_keyfile_not_private")
		s.Status = "blocked"
	} else if info.Mode().Perm()&0044 != 0 {
		s.Codes = append(s.Codes, "group_or_other_readable")
		if s.Status == "meets_baseline" {
			s.Status = "review"
		}
	}
	return s
}
func stableSource(before, after, current os.FileInfo) bool {
	if before == nil || after == nil || current == nil || !current.Mode().IsRegular() || !os.SameFile(before, after) || !os.SameFile(after, current) {
		return false
	}
	if before.Size() != after.Size() || after.Size() != current.Size() || before.Mode() != after.Mode() || after.Mode() != current.Mode() || !before.ModTime().Equal(after.ModTime()) || !after.ModTime().Equal(current.ModTime()) {
		return false
	}
	a, aok := before.Sys().(*syscall.Stat_t)
	b, bok := after.Sys().(*syscall.Stat_t)
	c, cok := current.Sys().(*syscall.Stat_t)
	return aok && bok && cok && a.Uid == b.Uid && b.Uid == c.Uid && a.Gid == b.Gid && b.Gid == c.Gid
}

func (p *PersistentReader) correlateManager(ctx context.Context, r *PersistentInspection) {
	e := &ManagerReferences{State: "not_checked", Scope: "visible_profile_references", ObservedAt: time.Now().UTC(), Diagnostic: "backend_not_supported"}
	r.Manager = e
	for i := range r.Profiles {
		r.Profiles[i].LoadReference = "unknown"
	}
	if p.platform != "linux" {
		e.State = "unsupported"
		e.Diagnostic = "unsupported_platform"
		return
	}
	if r.Backend != "networkmanager" {
		return
	}
	e.State = "unavailable"
	e.Diagnostic = "service_state_unavailable"
	state, err := p.execute(ctx, "systemctl", []string{"--no-pager", "is-active", "NetworkManager"}, "", "")
	if strings.TrimSpace(string(state)) == "inactive" {
		e.State = "inactive"
		e.Diagnostic = "service_inactive"
		return
	}
	if err != nil || strings.TrimSpace(string(state)) != "active" {
		return
	}
	e.Diagnostic = "profile_references_unavailable"
	raw, err := p.execute(ctx, "nmcli", []string{"-t", "-f", "UUID,FILENAME", "connection", "show"}, "", "")
	if err != nil {
		return
	}
	refs, err := parseManagerReferences(raw)
	if err != nil {
		e.Diagnostic = "reference_schema_unsupported"
		return
	}
	e.State = "observed"
	e.Diagnostic = "contents_and_activation_not_verified"
	e.ObservedAt = time.Now().UTC()
	for i := range r.Profiles {
		profile := &r.Profiles[i]
		uuid := strings.TrimPrefix(profile.Reference, "nm:")
		if !strings.HasPrefix(profile.Reference, "nm:") || !profileUUID.MatchString(uuid) || len(profile.SourceIDs) != 1 {
			continue
		}
		var path string
		for _, s := range r.Sources {
			if s.ID == profile.SourceIDs[0] {
				path = s.Path
				break
			}
		}
		paths := refs[strings.ToLower(uuid)]
		switch {
		case len(paths) == 0:
			profile.LoadReference = "not_observed"
		case len(paths) == 1 && paths[0] == "":
			profile.LoadReference = "unknown"
		case len(paths) == 1 && paths[0] != "" && filepath.Clean(paths[0]) == filepath.Clean(path):
			profile.LoadReference = "matched"
		default:
			profile.LoadReference = "conflicting"
		}
	}
}
func parseManagerReferences(raw []byte) (map[string][]string, error) {
	refs := map[string][]string{}
	lines := strings.Split(string(raw), "\n")
	if len(lines) > 1025 {
		return nil, errNativeSchema
	}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		uuid, filename, ok := strings.Cut(line, ":")
		if !ok || !profileUUID.MatchString(uuid) || len(filename) > 4096 {
			return nil, errNativeSchema
		}
		filename, err := nmUnescape(filename)
		if err != nil {
			return nil, err
		}
		if filename == "--" {
			filename = ""
		}
		if filename != "" && !filepath.IsAbs(filename) {
			return nil, errNativeSchema
		}
		uuid = strings.ToLower(uuid)
		refs[uuid] = append(refs[uuid], filename)
	}
	return refs, nil
}

func assessAuthority(r PersistentInspection) *AuthorityReport {
	a := &AuthorityReport{Status: "review_required", Issues: []AuthorityIssue{}}
	add := func(source, ref, severity, code, message string) {
		a.Issues = append(a.Issues, AuthorityIssue{source, ref, severity, code, message})
		if severity == "blocker" {
			a.Status = "blocked"
		}
	}
	add("", "", "review", "adoption_unconfirmed", "尚未完成明确接管确认")
	add("", "", "review", "management_and_rollback_unverified", "管理链路与独立回滚尚未核验")
	add("", "", "review", "runtime_contents_unverified", "加载引用不代表运行内容、激活状态或内核配置一致")
	if r.Platform != "linux" {
		add("", "", "blocker", "unsupported_platform", "当前平台不支持Linux网络接管检查")
	}
	if r.Status != "observed" {
		add("", "", "blocker", "source_inventory_incomplete", "来源清单或读取范围尚未完整核验")
	}
	if len(r.Profiles) == 0 {
		add("", "", "blocker", "profile_inventory_unavailable", "未取得可核对的接口配置声明")
	}
	for _, s := range r.Sources {
		if s.State != "read" {
			add(s.ID, "", "blocker", "source_not_read", "源文件未完整读取或格式未兼容")
		}
		if s.Safety == nil || s.Safety.Stable == nil || !*s.Safety.Stable {
			add(s.ID, "", "blocker", "source_stability_unverified", "源文件捕获窗口的一致性未核验")
			continue
		}
		switch s.Safety.Status {
		case "blocked":
			add(s.ID, "", "blocker", "source_permissions_blocked", "源文件所有者或权限不满足接管基线")
		case "review":
			add(s.ID, "", "review", "source_permissions_review", "源文件可被组或其他账号读取，需复核访问范围")
		case "meets_baseline":
		default:
			add(s.ID, "", "blocker", "source_permissions_unknown", "源文件权限信息未知")
		}
		if s.Storage != "persistent" {
			add(s.ID, "", "review", "non_persistent_source", "来源属于临时或厂商层，需确认写入与覆盖范围")
		}
	}
	for _, profile := range r.Profiles {
		sourceID := ""
		if len(profile.SourceIDs) == 1 {
			sourceID = profile.SourceIDs[0]
		}
		if !profile.OriginVerified {
			add(sourceID, profile.Reference, "blocker", "field_origin_unverified", "合并字段尚未归因到明确源文件")
		}
		if profile.Binding != "declared" {
			add(sourceID, profile.Reference, "blocker", "device_binding_unresolved", "设备匹配或重命名规则尚未解析")
		}
		for _, state := range profile.FieldStates {
			if state == "unsupported" {
				add(sourceID, profile.Reference, "blocker", "unsupported_network_fields", "配置包含未解析网络字段")
				break
			}
		}
		if profile.LoadReference != "matched" {
			severity := "review"
			if profile.LoadReference == "conflicting" {
				severity = "blocker"
			}
			add(sourceID, profile.Reference, severity, "loaded_reference_"+profile.LoadReference, "管理器加载引用尚未匹配当前源文件")
		}
	}
	return a
}
