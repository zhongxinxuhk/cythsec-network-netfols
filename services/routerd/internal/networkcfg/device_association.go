package networkcfg

import (
	"context"
	"strconv"
	"strings"
	"time"
)

type DeviceEvidence struct {
	State      string    `json:"state"`
	Scope      string    `json:"scope"`
	ObservedAt time.Time `json:"observed_at"`
	Diagnostic string    `json:"diagnostic"`
}

// Association is only NetworkManager's view, not exclusive device ownership or
// equality between daemon memory, persistent settings and kernel configuration.
type DeviceAssociation struct {
	State                string `json:"state"`
	DeviceState          *int   `json:"device_state"`
	Managed              *bool  `json:"managed"`
	ActiveProfileMatches *bool  `json:"active_profile_matches"`
}

type nmDeviceReference struct {
	state int
	uuid  string
}

func (p *PersistentReader) correlateNMDevices(ctx context.Context, r *PersistentInspection) {
	e := r.Devices
	e.Diagnostic = "device_associations_unavailable"
	raw, err := p.execute(ctx, "nmcli", []string{"-t", "-m", "multiline", "-f", "GENERAL.DEVICE,GENERAL.STATE,GENERAL.CON-UUID", "device", "show"}, "", "")
	if err != nil {
		return
	}
	devices, err := parseNMDeviceReferences(raw)
	if err != nil {
		e.Diagnostic = "device_schema_unsupported"
		return
	}
	e.State, e.Diagnostic, e.ObservedAt = "observed", "contents_and_exclusive_ownership_not_verified", time.Now().UTC()
	for i := range r.Profiles {
		profile := &r.Profiles[i]
		if profile.Binding != "declared" || !deviceName.MatchString(profile.Device) {
			continue
		}
		uuid, ok := strings.CutPrefix(profile.Reference, "nm:")
		if !ok || !profileUUID.MatchString(uuid) {
			continue
		}
		a := profile.Association
		d, ok := devices[profile.Device]
		if !ok {
			a.State = "not_observed"
			continue
		}
		a.DeviceState = &d.state
		if d.state == 0 {
			continue
		}
		managed := d.state != 10
		a.Managed = &managed
		if d.uuid != "" {
			matches := strings.EqualFold(d.uuid, uuid)
			a.ActiveProfileMatches = &matches
		}
		switch {
		case !managed:
			a.State = "unmanaged"
		case a.ActiveProfileMatches != nil && !*a.ActiveProfileMatches:
			a.State = "conflicting"
		case d.state == 100 && a.ActiveProfileMatches != nil && *a.ActiveProfileMatches:
			a.State = "active"
		case d.state == 20:
			a.State = "unavailable_device"
		case d.state == 30 || d.state == 120:
			a.State = "inactive"
		case d.state != 100:
			a.State = "transitioning"
		}
	}
}

func parseNMDeviceReferences(raw []byte) (map[string]nmDeviceReference, error) {
	devices := map[string]nmDeviceReference{}
	var fields map[string]string
	flush := func() error {
		if fields == nil {
			return nil
		}
		name := fields["GENERAL.DEVICE"]
		if !deviceName.MatchString(name) || len(fields) != 3 || len(devices) >= 512 {
			return errNativeSchema
		}
		if _, exists := devices[name]; exists {
			return errNativeSchema
		}
		parts := strings.Fields(fields["GENERAL.STATE"])
		if len(parts) == 0 {
			return errNativeSchema
		}
		state, err := strconv.Atoi(parts[0])
		if err != nil || state < 0 || state > 120 || state%10 != 0 {
			return errNativeSchema
		}
		uuid := fields["GENERAL.CON-UUID"]
		if uuid == "--" {
			uuid = ""
		}
		if uuid != "" && !profileUUID.MatchString(uuid) {
			return errNativeSchema
		}
		devices[name] = nmDeviceReference{state, uuid}
		return nil
	}
	if len(raw) > 1024*1024 {
		return nil, errNativeSchema
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || len(line) > 256 {
			return nil, errNativeSchema
		}
		if key == "GENERAL.DEVICE" {
			if err := flush(); err != nil {
				return nil, err
			}
			fields = map[string]string{}
		}
		if fields == nil || (key != "GENERAL.DEVICE" && key != "GENERAL.STATE" && key != "GENERAL.CON-UUID") {
			return nil, errNativeSchema
		}
		if _, exists := fields[key]; exists {
			return nil, errNativeSchema
		}
		value, err := nmUnescape(strings.TrimSpace(value))
		if err != nil {
			return nil, err
		}
		fields[key] = value
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return devices, nil
}
