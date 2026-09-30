package acl

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

type Peer struct {
	ID         int64   `json:"id"`
	ExternalID string  `json:"external_id"`
	PublicKey  string  `json:"public_key"`
	IP         string  `json:"ip"`
	Name       string  `json:"name"`
	Enabled    bool    `json:"enabled"`
	SyncStatus string  `json:"sync_status"`
	LastSeen   string  `json:"last_seen"`
	Groups     []int64 `json:"groups"`
}
type Group struct {
	ID      int64   `json:"id"`
	Name    string  `json:"name"`
	Members []int64 `json:"members"`
}
type Resource struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	PortStart   int    `json:"port_start"`
	PortEnd     int    `json:"port_end"`
	Enabled     bool   `json:"enabled"`
}
type Policy struct {
	ID         int64  `json:"id"`
	PeerID     int64  `json:"peer_id"`
	GroupID    int64  `json:"group_id"`
	ResourceID int64  `json:"resource_id"`
	Action     string `json:"action"`
}
type MatrixCell struct {
	PeerID     int64  `json:"peer_id"`
	ResourceID int64  `json:"resource_id"`
	Result     string `json:"result"`
	Reason     string `json:"reason"`
}
type Rule struct {
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	PortStart   int    `json:"port_start,omitempty"`
	PortEnd     int    `json:"port_end,omitempty"`
	Action      string `json:"action"`
}
type Desired struct {
	Revision  int64  `json:"revision"`
	Activated bool   `json:"activated"`
	Checksum  string `json:"checksum"`
	Rules     []Rule `json:"rules"`
}
type Status struct {
	DesiredRevision    int64  `json:"desired_revision"`
	AppliedRevision    int64  `json:"applied_revision"`
	Checksum           string `json:"checksum"`
	Chain              string `json:"chain"`
	State              string `json:"state"`
	LastAttempt        string `json:"last_attempt"`
	LastSuccess        string `json:"last_success"`
	LastError          string `json:"last_error"`
	AnchorPresent      bool   `json:"anchor_present"`
	AnchorBeforeAccept bool   `json:"anchor_before_accept"`
	Heartbeat          string `json:"heartbeat"`
}
type Snapshot struct {
	Peers     []Peer       `json:"peers"`
	Groups    []Group      `json:"groups"`
	Resources []Resource   `json:"resources"`
	Policies  []Policy     `json:"policies"`
	Matrix    []MatrixCell `json:"matrix"`
	Desired   Desired      `json:"desired"`
}

func IPv4(s string) (string, error) {
	a, e := netip.ParseAddr(s)
	if e != nil || !a.Is4() {
		return "", fmt.Errorf("invalid IPv4 address: %q", s)
	}
	return a.String(), nil
}
func CIDR(s string) (string, error) {
	p, e := netip.ParsePrefix(s)
	if e != nil || !p.Addr().Is4() || p.Masked() != p {
		return "", fmt.Errorf("invalid canonical IPv4 CIDR: %q", s)
	}
	return p.String(), nil
}
func (r Resource) Validate() error {
	if strings.TrimSpace(r.Name) == "" || len(r.Name) > 120 {
		return errors.New("resource name required (max 120 characters)")
	}
	if _, e := CIDR(r.Destination); e != nil {
		return e
	}
	if r.Destination == "0.0.0.0/0" {
		return errors.New("global destination is outside ACL resource scope")
	}
	if r.Protocol != "tcp" && r.Protocol != "udp" && r.Protocol != "icmp" && r.Protocol != "any" {
		return errors.New("protocol must be tcp, udp, icmp or any")
	}
	if r.Protocol == "tcp" || r.Protocol == "udp" {
		if r.PortStart == 0 && r.PortEnd == 0 {
			return nil
		}
		if r.PortStart < 1 || r.PortEnd < r.PortStart || r.PortEnd > 65535 {
			return errors.New("invalid port range")
		}
	} else if r.PortStart != 0 || r.PortEnd != 0 {
		return errors.New("ports require tcp or udp")
	}
	return nil
}
func ValidateResources(resources []Resource) error {
	for i, a := range resources {
		if e := a.Validate(); e != nil {
			return e
		}
		if !a.Enabled {
			continue
		}
		pa, _ := netip.ParsePrefix(a.Destination)
		for _, b := range resources[:i] {
			if !b.Enabled {
				continue
			}
			pb, _ := netip.ParsePrefix(b.Destination)
			if !(pa.Contains(pb.Addr()) || pb.Contains(pa.Addr())) {
				continue
			}
			if a.Protocol != b.Protocol && a.Protocol != "any" && b.Protocol != "any" {
				continue
			}
			if (a.Protocol == "tcp" || a.Protocol == "udp") && a.Protocol == b.Protocol && a.PortStart > 0 && b.PortStart > 0 && (a.PortEnd < b.PortStart || b.PortEnd < a.PortStart) {
				continue
			}
			return fmt.Errorf("enabled resources %q and %q overlap", a.Name, b.Name)
		}
	}
	return nil
}
func (p Policy) Validate() error {
	if p.ResourceID <= 0 || (p.PeerID <= 0) == (p.GroupID <= 0) || (p.Action != "ALLOW" && p.Action != "DENY") {
		return errors.New("invalid policy")
	}
	return nil
}
func Resolve(peers []Peer, groups []Group, resources []Resource, policies []Policy) []MatrixCell {
	groupNames := map[int64]string{}
	for _, g := range groups {
		groupNames[g.ID] = g.Name
	}
	out := make([]MatrixCell, 0, len(peers)*len(resources))
	for _, peer := range peers {
		for _, r := range resources {
			cell := MatrixCell{PeerID: peer.ID, ResourceID: r.ID, Result: "DENY", Reason: "default DENY"}
			if !r.Enabled {
				cell.Result = "UNMANAGED"
				cell.Reason = "resource disabled"
			}
			if peer.SyncStatus != "present" || !peer.Enabled {
				cell.Reason = "peer missing or disabled"
			}
			if cell.Result == "UNMANAGED" || peer.SyncStatus != "present" || !peer.Enabled {
				out = append(out, cell)
				continue
			}
			allows, denies := []string{}, []string{}
			for _, p := range policies {
				if p.ResourceID != r.ID {
					continue
				}
				source := ""
				if p.PeerID == peer.ID {
					source = "direct peer"
				} else {
					for _, gid := range peer.Groups {
						if gid == p.GroupID {
							source = "group " + groupNames[gid]
							break
						}
					}
				}
				if source == "" {
					continue
				}
				if p.Action == "DENY" {
					denies = append(denies, source)
				} else {
					allows = append(allows, source)
				}
			}
			sort.Strings(allows)
			sort.Strings(denies)
			if len(denies) > 0 {
				cell.Reason = strings.Join(denies, ", ") + " DENY"
				if len(allows) > 0 {
					cell.Reason += " overrides " + strings.Join(allows, ", ") + " ALLOW"
				}
			} else if len(allows) > 0 {
				cell.Result = "ALLOW"
				cell.Reason = strings.Join(allows, ", ") + " ALLOW"
			}
			out = append(out, cell)
		}
	}
	return out
}
func Compile(peers []Peer, resources []Resource, matrix []MatrixCell, revision int64, activated bool) (Desired, error) {
	if e := ValidateResources(resources); e != nil {
		return Desired{}, e
	}
	peerByID := map[int64]Peer{}
	for _, p := range peers {
		peerByID[p.ID] = p
	}
	resourceByID := map[int64]Resource{}
	for _, r := range resources {
		if e := r.Validate(); e != nil {
			return Desired{}, e
		}
		resourceByID[r.ID] = r
	}
	rules := []Rule{}
	for _, cell := range matrix {
		if cell.Result != "ALLOW" {
			continue
		}
		p, ok := peerByID[cell.PeerID]
		if !ok {
			return Desired{}, errors.New("unknown peer in matrix")
		}
		r, ok := resourceByID[cell.ResourceID]
		if !ok {
			return Desired{}, errors.New("unknown resource in matrix")
		}
		ip, e := IPv4(p.IP)
		if e != nil {
			return Desired{}, e
		}
		if !r.Enabled || p.SyncStatus != "present" || !p.Enabled {
			return Desired{}, errors.New("allow for inactive peer or resource")
		}
		rules = append(rules, Rule{Source: ip + "/32", Destination: r.Destination, Protocol: r.Protocol, PortStart: r.PortStart, PortEnd: r.PortEnd, Action: "ACCEPT"})
	}
	for _, r := range resources {
		if r.Enabled {
			rules = append(rules, Rule{Destination: r.Destination, Protocol: r.Protocol, PortStart: r.PortStart, PortEnd: r.PortEnd, Action: "DROP"})
		}
	}
	sort.Slice(rules, func(i, j int) bool {
		a, _ := json.Marshal(rules[i])
		b, _ := json.Marshal(rules[j])
		return string(a) < string(b)
	})
	// Allow rules must precede managed-resource drops, regardless of lexical order.
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Action == "ACCEPT" && rules[j].Action == "DROP" })
	b, _ := json.Marshal(rules)
	sum := sha256.Sum256(b)
	return Desired{Revision: revision, Activated: activated, Checksum: hex.EncodeToString(sum[:]), Rules: rules}, nil
}
func (r Rule) Args() ([]string, error) {
	if _, e := CIDR(r.Destination); e != nil {
		return nil, e
	}
	if r.Destination == "0.0.0.0/0" {
		return nil, errors.New("global destination is outside ACL resource scope")
	}
	args := []string{}
	if r.Source != "" {
		p, e := netip.ParsePrefix(r.Source)
		if e != nil || !p.Addr().Is4() || p.Bits() != 32 || p.Masked() != p {
			return nil, errors.New("invalid source /32")
		}
		args = append(args, "-s", r.Source)
	}
	args = append(args, "-d", r.Destination)
	if r.Protocol != "any" && r.Protocol != "tcp" && r.Protocol != "udp" && r.Protocol != "icmp" {
		return nil, errors.New("invalid protocol")
	}
	if r.Protocol != "any" {
		args = append(args, "-p", r.Protocol)
	}
	if r.PortStart != 0 || r.PortEnd != 0 {
		if (r.Protocol != "tcp" && r.Protocol != "udp") || r.PortStart < 1 || r.PortEnd < r.PortStart || r.PortEnd > 65535 {
			return nil, errors.New("invalid port range")
		}
		port := strconv.Itoa(r.PortStart)
		if r.PortEnd != r.PortStart {
			port += ":" + strconv.Itoa(r.PortEnd)
		}
		args = append(args, "--dport", port)
	}
	if r.Action != "ACCEPT" && r.Action != "DROP" {
		return nil, errors.New("invalid firewall action")
	}
	return append(args, "-j", r.Action), nil
}
