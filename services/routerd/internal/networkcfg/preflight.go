package networkcfg

import (
	"fmt"
	"net/netip"
	"reflect"
)

type CheckIssue struct {
	Severity string `json:"severity"`
	Device   string `json:"device"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}
type FieldDifference struct {
	Device  string `json:"device"`
	Field   string `json:"field"`
	Current any    `json:"current"`
	Desired any    `json:"desired"`
	State   string `json:"state"`
	Source  string `json:"source"`
}
type Preflight struct {
	DraftDigest string            `json:"draft_digest"`
	Observation Observation       `json:"observation"`
	Status      string            `json:"status"`
	CanApply    bool              `json:"can_apply"`
	Issues      []CheckIssue      `json:"issues"`
	Differences []FieldDifference `json:"differences"`
}

func Compare(c Config, o Observation) (Preflight, error) {
	if err := Validate(c); err != nil {
		return Preflight{}, err
	}
	p := Preflight{DraftDigest: Digest(c), Observation: o, Status: "review_required", Issues: []CheckIssue{}, Differences: []FieldDifference{}}
	add := func(level, device, code, message string) {
		p.Issues = append(p.Issues, CheckIssue{level, device, code, message})
		if level == "blocker" {
			p.Status = "blocked"
		}
	}
	if o.Platform != "linux" {
		add("blocker", "", "unsupported_platform", "当前主机不支持Linux原生网络接管检查")
	}
	if !o.InventoryAvailable {
		add("blocker", "", "inventory_unavailable", "接口快照不可用，不能判断接口是否存在")
	}
	add("review", "", "persistent_state_not_read", "本报告未关联持久配置来源快照，DHCP/RA与现有配置归属仍须核对")
	add("review", "", "native_validation_pending", "本报告未关联原生工具校验结果，请单独校验配置")
	add("review", "", "management_path_unverified", "管理连接路径及断线恢复尚未核验")
	for _, desired := range c.Interfaces {
		var actual *ObservedInterface
		for i := range o.Interfaces {
			if o.Interfaces[i].Device == desired.Device {
				actual = &o.Interfaces[i]
				break
			}
		}
		if actual == nil {
			if o.InventoryAvailable {
				add("blocker", desired.Device, "device_missing", "目标接口未出现在本次内核快照中")
			}
		}
		if actual != nil {
			if len(actual.Restrictions) > 0 {
				add("blocker", desired.Device, "layered_device_relation", "逻辑接口与目标物理设备存在间接三层关联，需专门接管模型")
			}
			if actual.Kind != "physical_ethernet" {
				add("blocker", desired.Device, "interface_kind_unsupported", "接口不是已核对的物理以太网口，需专门接管模型")
			}
			switch len(actual.Owners) {
			case 0:
				add("blocker", desired.Device, "owner_unknown", "未取得接口管理器归属证据")
			case 1:
				if actual.Owners[0].Backend != c.Backend && !(c.Backend == "netplan" && actual.Owners[0].Backend == "networkd") {
					add("blocker", desired.Device, "backend_mismatch", "草稿管理器与接口运行归属不一致")
				}
				if c.Backend == "netplan" {
					add("review", desired.Device, "configuration_origin_unverified", "Netplan合并配置来源尚未核验，不能按文件名确认接管")
				}
				add("review", desired.Device, "adoption_required", "现有profile尚未完成显式接管确认")
			default:
				add("blocker", desired.Device, "multiple_owners", "同接口存在多个管理归属声明，不能直接覆盖")
			}
			if !actual.Up {
				add("review", desired.Device, "interface_down", "接口当前未启用，需核对管理与业务角色")
			}
		}
		canonicalAddresses := func(values []string) []string {
			out := []string{}
			for _, v := range values {
				if prefix, e := netip.ParsePrefix(v); e == nil {
					out = append(out, prefix.String())
				}
			}
			return stringSet(out)
		}
		desiredDNS, _ := observedDNS(desired.DNS)
		desiredSearch, _ := observedSearch(desired.Search)
		desiredValues := map[string]any{"mtu": desired.MTU, "addresses": canonicalAddresses(desired.Addresses), "dns": desiredDNS, "search": desiredSearch, "routes": routeStrings(desired.Routes)}
		for _, field := range []string{"mtu", "addresses", "dns", "search", "routes"} {
			d := FieldDifference{Device: desired.Device, Field: field, Desired: desiredValues[field], State: "unknown", Source: "unavailable"}
			if actual != nil && actual.Known[field] {
				d.Source = actual.Sources[field]
				switch field {
				case "mtu":
					if actual.MTU != nil {
						d.Current = *actual.MTU
					}
				case "addresses":
					d.Current = canonicalAddresses(actual.Addresses)
				case "dns":
					d.Current = stringSet(actual.DNS)
				case "search":
					d.Current = stringSet(actual.Search)
				case "routes":
					d.Current = routeStrings(actual.Routes)
				}
				if d.Current != nil {
					d.State = "different"
					if reflect.DeepEqual(d.Current, d.Desired) {
						d.State = "same"
					}
				}
			}
			p.Differences = append(p.Differences, d)
		}
	}
	if len(p.Differences) != 5*len(c.Interfaces) {
		return Preflight{}, fmt.Errorf("incomplete preflight comparison")
	}
	return p, nil
}
