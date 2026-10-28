package networkcfg

import (
	"context"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

const routingFields = "connection.uuid,connection.type,ipv4.gateway,ipv4.routes,ipv4.route-metric,ipv4.route-table,ipv4.never-default,ipv4.ignore-auto-routes,ipv4.routing-rules,ipv6.gateway,ipv6.routes,ipv6.route-metric,ipv6.route-table,ipv6.never-default,ipv6.ignore-auto-routes,ipv6.routing-rules"

type RoutingComparison struct {
	State      string    `json:"state"`
	Scope      string    `json:"scope"`
	ObservedAt time.Time `json:"observed_at"`
	Reason     string    `json:"reason"`
	Source     []string  `json:"source"`
	Loaded     []string  `json:"loaded"`
}

func routeMultiset(routes []ConfiguredRoute) []string {
	values := make([]string, 0, len(routes))
	for _, route := range routes {
		metric := "default"
		if route.Metric != nil {
			metric = strconv.FormatUint(uint64(*route.Metric), 10)
		}
		values = append(values, route.Destination+" via "+route.Gateway+" metric "+metric)
	}
	sort.Strings(values) // Preserve duplicates: set deduplication would hide drift.
	return values
}

func (p *PersistentReader) compareRouting(ctx context.Context, r *PersistentInspection) {
	args := []string{"-t", "-m", "multiline", "-f", routingFields, "connection", "show"}
	requested := map[string]bool{}
	for i := range r.Profiles {
		profile := &r.Profiles[i]
		c := &RoutingComparison{State: "not_checked", Scope: "nm_declared_route_multiset", ObservedAt: time.Now().UTC(), Reason: "reference_not_matched"}
		profile.Routing = c
		if profile.FieldStates["routes"] == "configured" {
			c.Source = routeMultiset(profile.Routes)
		}
		if p.platform != "linux" {
			c.State, c.Reason = "unsupported", "unsupported_platform"
		} else if r.Backend != "networkmanager" {
			c.Reason = "backend_not_supported"
		} else if uuid, ok := strings.CutPrefix(profile.Reference, "nm:"); ok && profileUUID.MatchString(uuid) && profile.LoadReference == "matched" {
			c.State, c.Reason = "unavailable", "routing_query_unavailable"
			uuid = strings.ToLower(uuid)
			if !requested[uuid] {
				requested[uuid] = true
				args = append(args, "uuid", uuid)
			}
		}
	}
	if len(requested) == 0 {
		return
	}
	raw, err := p.execute(ctx, "nmcli", args, "", "")
	var records map[string]map[string]string
	reason := "routing_query_unavailable"
	if err == nil {
		records, err = parseNMSettingsBatch(raw, routingFields, requested)
		reason = "routing_schema_unsupported"
	}
	for i := range r.Profiles {
		profile := &r.Profiles[i]
		c := profile.Routing
		if c.State != "unavailable" {
			continue
		}
		if err != nil {
			c.Reason = reason
			continue
		}
		fields, ok := records[strings.ToLower(strings.TrimPrefix(profile.Reference, "nm:"))]
		if !ok {
			c.Reason = "profile_not_observed"
			continue
		}
		c.ObservedAt = time.Now().UTC()
		c.State, c.Reason = "unknown", "loaded_route_semantics_unsupported"
		routes, err := projectNMRoutes(fields)
		if err != nil {
			continue
		}
		c.Loaded = routeMultiset(routes)
		if c.Source == nil {
			c.Reason = "source_unset_or_unsupported"
			continue
		}
		c.State, c.Reason = "same", "compared_partial_semantics"
		if strings.Join(c.Source, "\n") != strings.Join(c.Loaded, "\n") {
			c.State = "different"
		}
	}
}

func projectNMRoutes(fields map[string]string) ([]ConfiguredRoute, error) {
	p := newPersistentProfile("", nil)
	for _, family := range []string{"ipv4", "ipv6"} {
		if fields[family+".route-metric"] != "-1" || fields[family+".route-table"] != "0" || (fields[family+".never-default"] != "no" && fields[family+".never-default"] != "false") || (fields[family+".ignore-auto-routes"] != "no" && fields[family+".ignore-auto-routes"] != "false") || (fields[family+".routing-rules"] != "" && fields[family+".routing-rules"] != "--") {
			return nil, errNativeSchema
		}
		add := func(destination, gateway, metric string) error {
			d, de := netip.ParsePrefix(destination)
			g, ge := netip.ParseAddr(gateway)
			if de != nil || ge != nil || g.Zone() != "" || d.Addr().Is4() != (family == "ipv4") || g.Is4() != d.Addr().Is4() || g.IsMulticast() || g.IsUnspecified() {
				return errNativeSchema
			}
			persistentRoute(&p, destination, gateway, metric)
			if p.FieldStates["routes"] == "unsupported" {
				return errNativeSchema
			}
			return nil
		}
		if gateway := fields[family+".gateway"]; gateway != "" && gateway != "--" {
			destination := "::/0"
			if family == "ipv4" {
				destination = "0.0.0.0/0"
			}
			if err := add(destination, gateway, ""); err != nil {
				return nil, err
			}
		}
		if raw := fields[family+".routes"]; raw != "" && raw != "--" {
			for _, route := range strings.Split(raw, ",") {
				parts := strings.Fields(route)
				if len(parts) != 2 && len(parts) != 3 {
					return nil, errNativeSchema
				}
				metric := ""
				if len(parts) == 3 {
					metric = parts[2]
					if _, err := strconv.ParseUint(metric, 10, 32); err != nil {
						return nil, errNativeSchema
					}
				}
				if err := add(parts[0], parts[1], metric); err != nil {
					return nil, err
				}
			}
		}
	}
	if p.Routes == nil {
		return []ConfiguredRoute{}, nil
	}
	return p.Routes, nil
}
