package acl

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func fixture() ([]Peer, []Group, []Resource) {
	peers := []Peer{{ID: 1, ExternalID: "1", IP: "10.8.0.2", Name: "Alice", Enabled: true, SyncStatus: "present", Groups: []int64{1}}, {ID: 2, ExternalID: "2", IP: "10.8.0.3", Name: "Bob", Enabled: true, SyncStatus: "present"}}
	groups := []Group{{ID: 1, Name: "analysts"}}
	resources := []Resource{{ID: 1, Name: "DWH", Destination: "172.20.57.245/32", Protocol: "tcp", PortStart: 3306, PortEnd: 3306, Enabled: true}}
	return peers, groups, resources
}
func TestPolicyResolutionAndCompilation(t *testing.T) {
	peers, groups, resources := fixture()
	cases := []struct {
		name         string
		policies     []Policy
		want, reason string
	}{
		{"default", nil, "DENY", "default DENY"},
		{"peer allow", []Policy{{PeerID: 1, ResourceID: 1, Action: "ALLOW"}}, "ALLOW", "direct peer ALLOW"},
		{"peer deny", []Policy{{PeerID: 1, ResourceID: 1, Action: "DENY"}}, "DENY", "direct peer DENY"},
		{"group allow", []Policy{{GroupID: 1, ResourceID: 1, Action: "ALLOW"}}, "ALLOW", "group analysts ALLOW"},
		{"group deny", []Policy{{GroupID: 1, ResourceID: 1, Action: "DENY"}}, "DENY", "group analysts DENY"},
		{"direct deny over group allow", []Policy{{PeerID: 1, ResourceID: 1, Action: "DENY"}, {GroupID: 1, ResourceID: 1, Action: "ALLOW"}}, "DENY", "direct peer DENY overrides group analysts ALLOW"},
		{"group deny over direct allow", []Policy{{PeerID: 1, ResourceID: 1, Action: "ALLOW"}, {GroupID: 1, ResourceID: 1, Action: "DENY"}}, "DENY", "group analysts DENY overrides direct peer ALLOW"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matrix := Resolve(peers, groups, resources, tc.policies)
			if matrix[0].Result != tc.want || matrix[0].Reason != tc.reason {
				t.Fatalf("%+v", matrix[0])
			}
			d, e := Compile(peers, resources, matrix, 1, true)
			if e != nil {
				t.Fatal(e)
			}
			if got := d.Rules[len(d.Rules)-1].Action; got != "DROP" {
				t.Fatalf("managed resource must end in DROP: %s", got)
			}
			for _, r := range d.Rules {
				if r.Destination == "0.0.0.0/0" {
					t.Fatal("global drop")
				}
			}
		})
	}
	resources[0].Enabled = false
	matrix := Resolve(peers, groups, resources, nil)
	if matrix[0].Result != "UNMANAGED" {
		t.Fatal(matrix[0])
	}
	d, e := Compile(peers, resources, matrix, 1, true)
	if e != nil || len(d.Rules) != 0 {
		t.Fatalf("disabled resource must not produce rules: %+v %v", d.Rules, e)
	}
}
func TestRulesAreDeterministicAndValidated(t *testing.T) {
	peers, groups, resources := fixture()
	policies := []Policy{{PeerID: 1, ResourceID: 1, Action: "ALLOW"}, {GroupID: 1, ResourceID: 1, Action: "ALLOW"}}
	a, e := Compile(peers, resources, Resolve(peers, groups, resources, policies), 2, true)
	if e != nil {
		t.Fatal(e)
	}
	policies[0], policies[1] = policies[1], policies[0]
	b, e := Compile(peers, resources, Resolve(peers, groups, resources, policies), 2, true)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("nondeterministic compiled policy")
	}
	bad := []Rule{{Source: "10.8.0.2; rm -rf /32", Destination: "172.20.57.245/32", Protocol: "tcp", Action: "ACCEPT"}, {Destination: "0.0.0.0/0", Protocol: "tcp;DROP", Action: "DROP"}, {Destination: "1.2.3.4/32", Protocol: "tcp", PortStart: 65536, PortEnd: 65536, Action: "DROP"}}
	for _, r := range bad {
		if _, e := r.Args(); e == nil {
			t.Fatalf("accepted unsafe rule: %+v", r)
		}
	}
	if e := (Policy{PeerID: 1, GroupID: 1, ResourceID: 1, Action: "ACCEPT"}).Validate(); e == nil {
		t.Fatal("malformed policy accepted")
	}
	resources = append(resources, Resource{ID: 2, Name: "overlap", Destination: "172.20.57.0/24", Protocol: "tcp", PortStart: 3306, PortEnd: 3306, Enabled: true})
	if _, e := Compile(peers, resources, nil, 3, true); e == nil {
		t.Fatal("overlapping resources accepted")
	}
}
func TestPeerSyncUniquenessAndTombstone(t *testing.T) {
	dir := t.TempDir()
	s, e := OpenStore(filepath.Join(dir, "acl.db"), dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	one := Peer{ExternalID: "1", PublicKey: "key1", IP: "10.8.0.2", Name: "Alice", Enabled: true}
	if e = s.SyncPeers("admin", []Peer{one}); e != nil {
		t.Fatal(e)
	}
	first, e := s.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.SyncPeers("system", []Peer{one}); e != nil {
		t.Fatal(e)
	}
	second, e := s.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	if second.Desired.Revision != first.Desired.Revision {
		t.Fatal("unchanged peer poll bumped desired revision")
	}
	if _, e = s.DB.Exec("INSERT INTO peers(external_id,public_key,ip,name,enabled,sync_status,last_seen) VALUES('other','other-key',?,'Other',1,'present','now')", one.IP); e == nil {
		t.Fatal("database accepted duplicate VPN IPv4")
	}
	if e = s.SyncPeers("admin", []Peer{one, {ExternalID: "2", PublicKey: "key2", IP: one.IP, Enabled: true}}); e == nil {
		t.Fatal("duplicate IP accepted")
	}
	if e = s.SyncPeers("admin", nil); e != nil {
		t.Fatal(e)
	}
	snap, e := s.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	if snap.Peers[0].SyncStatus != "missing" {
		t.Fatal(snap.Peers[0])
	}
	if e = s.SyncPeers("admin", []Peer{{ExternalID: "3", PublicKey: "key3", IP: one.IP, Enabled: true}}); e == nil {
		t.Fatal("reassigned IP accepted")
	}
}
func TestIdentityConflictQuarantinesOldGrant(t *testing.T) {
	dir := t.TempDir()
	s, e := OpenStore(filepath.Join(dir, "acl.db"), dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	if e = s.SyncPeers("admin", []Peer{{ExternalID: "old", PublicKey: "old-key", IP: "10.8.0.2", Enabled: true}}); e != nil {
		t.Fatal(e)
	}
	e = s.Change("admin", "setup", "resource", nil, nil, func(tx *sql.Tx) error {
		if _, e := tx.Exec("INSERT INTO resources(id,name,description,destination,protocol,port_start,port_end,enabled) VALUES(1,'DWH','','172.20.57.245/32','tcp',3306,3306,1)"); e != nil {
			return e
		}
		_, e := tx.Exec("INSERT INTO policies(peer_id,resource_id,action) VALUES(1,1,'ALLOW')")
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	before, e := s.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	if before.Matrix[0].Result != "ALLOW" {
		t.Fatal("setup grant missing")
	}
	if e = s.SyncPeers("admin", []Peer{{ExternalID: "new", PublicKey: "new-key", IP: "10.8.0.2", Enabled: true}}); e == nil {
		t.Fatal("identity conflict accepted")
	}
	after, e := s.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	if after.Peers[0].SyncStatus != "missing" || after.Matrix[0].Result != "DENY" || len(after.Desired.Rules) != 1 || after.Desired.Rules[0].Action != "DROP" {
		t.Fatalf("old grant survived conflict: %+v %+v", after.Peers, after.Desired.Rules)
	}
}
func TestMovedPeerCannotKeepGrantOnOldIPWhenNewIPConflicts(t *testing.T) {
	dir := t.TempDir()
	s, e := OpenStore(filepath.Join(dir, "acl.db"), dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	old := []Peer{{ExternalID: "a", PublicKey: "a-key", IP: "10.8.0.2", Enabled: true}, {ExternalID: "b", PublicKey: "b-key", IP: "10.8.0.3", Enabled: true}}
	if e = s.SyncPeers("admin", old); e != nil {
		t.Fatal(e)
	}
	if e = s.SyncPeers("admin", []Peer{{ExternalID: "a", PublicKey: "a-key", IP: "10.8.0.3", Enabled: true}}); e == nil {
		t.Fatal("conflicting move accepted")
	}
	v, e := s.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range v.Peers {
		if p.SyncStatus != "missing" {
			t.Fatalf("stale peer stayed active: %+v", p)
		}
	}
}

type fakeIPT struct {
	chains      map[string][][]string
	forward     [][]string
	fail        string
	creates     int
	breakVerify bool
	tamperNext  bool
}

func newFake() *fakeIPT {
	return &fakeIPT{chains: map[string][][]string{}, forward: [][]string{{"-i", "wg0", "-j", "ACCEPT"}, {"-o", "wg0", "-j", "ACCEPT"}, {"-s", "10.8.0.0/24", "-j", "ACCEPT"}}}
}
func equal(a, b []string) bool { return reflect.DeepEqual(a, b) }
func (f *fakeIPT) Run(_ string, args ...string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("empty args")
	}
	if f.fail == args[0] {
		return "", errors.New("injected failure")
	}
	switch args[0] {
	case "-S":
		if len(args) == 1 {
			var lines []string
			for name := range f.chains {
				lines = append(lines, "-N "+name)
			}
			return strings.Join(lines, "\n"), nil
		}
		name := args[1]
		var rules [][]string
		if name == "FORWARD" {
			rules = f.forward
			if f.tamperNext {
				f.tamperNext = false
				rules = [][]string{{"-i", "wg0", "-j", "ACCEPT"}}
			}
		} else {
			var ok bool
			rules, ok = f.chains[name]
			if !ok {
				return "", errors.New("missing chain")
			}
		}
		out := []string{}
		for _, r := range rules {
			out = append(out, "-A "+name+" "+strings.Join(r, " "))
		}
		return strings.Join(out, "\n"), nil
	case "-N":
		if _, ok := f.chains[args[1]]; ok {
			return "", errors.New("exists")
		}
		f.chains[args[1]] = [][]string{}
		f.creates++
		return "", nil
	case "-A":
		f.chains[args[1]] = append(f.chains[args[1]], append([]string{}, args[2:]...))
		return "", nil
	case "-I":
		n, _ := strconv.Atoi(args[2])
		i := n - 1
		f.forward = append(f.forward, nil)
		copy(f.forward[i+1:], f.forward[i:])
		f.forward[i] = append([]string{}, args[3:]...)
		return "", nil
	case "-R":
		n, _ := strconv.Atoi(args[2])
		f.forward[n-1] = append([]string{}, args[3:]...)
		if f.breakVerify && strings.HasPrefix(args[len(args)-1], "WGACL_") {
			f.tamperNext = true
			f.breakVerify = false
		}
		return "", nil
	case "-D":
		for i, r := range f.forward {
			if equal(r, args[2:]) {
				f.forward = append(f.forward[:i], f.forward[i+1:]...)
				return "", nil
			}
		}
		return "", errors.New("rule missing")
	case "-F":
		f.chains[args[1]] = [][]string{}
		return "", nil
	case "-X":
		delete(f.chains, args[1])
		return "", nil
	}
	return "", errors.New("unsupported fake command")
}
func writeDesired(t *testing.T, dir string, d Desired) {
	t.Helper()
	b, _ := json.Marshal(d)
	if e := os.WriteFile(filepath.Join(dir, "desired.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
}
func TestEnforcerLifecycle(t *testing.T) {
	dir := t.TempDir()
	peers, groups, resources := fixture()
	matrix := Resolve(peers, groups, resources, []Policy{{PeerID: 1, ResourceID: 1, Action: "ALLOW"}})
	d, e := Compile(peers, resources, matrix, 17, true)
	if e != nil {
		t.Fatal(e)
	}
	writeDesired(t, dir, d)
	fake := newFake()
	enforcer := &Enforcer{Runner: fake, Dir: dir}
	if e = enforcer.Reconcile(); e != nil {
		t.Fatal(e)
	}
	lines, broad, anchors, e := enforcer.inspect()
	if e != nil || len(anchors) != 1 || anchors[0] >= broad {
		t.Fatalf("anchor wrong: %v %d %v %v", lines, broad, anchors, e)
	}
	if !equal(fake.forward[len(fake.forward)-2], []string{"-o", "wg0", "-j", "ACCEPT"}) {
		t.Fatal("wg-easy inbound rule changed")
	}
	original := append([][]string{}, fake.forward...)
	creates := fake.creates
	if e = enforcer.Reconcile(); e != nil || fake.creates != creates || !reflect.DeepEqual(fake.forward, original) {
		t.Fatal("repeated apply changed firewall")
	}
	// Lost anchor and namespace recreation both restore desired state.
	fake.forward = fake.forward[1:]
	if e = enforcer.Reconcile(); e != nil {
		t.Fatal(e)
	}
	fake.forward = newFake().forward
	fake.chains = map[string][][]string{}
	enforcer = &Enforcer{Runner: fake, Dir: dir}
	if e = enforcer.Reconcile(); e != nil {
		t.Fatal(e)
	}
	if enforcer.Status.AppliedRevision != 17 || !enforcer.Status.AnchorBeforeAccept {
		t.Fatal(enforcer.Status)
	}
	oldApplied := enforcer.Status.AppliedRevision
	d, e = Compile(peers, resources, Resolve(peers, groups, resources, nil), 18, true)
	if e != nil {
		t.Fatal(e)
	}
	writeDesired(t, dir, d)
	fake.fail = "-N"
	if e = enforcer.Reconcile(); e == nil {
		t.Fatal("expected apply failure")
	}
	if enforcer.Status.AppliedRevision != oldApplied || enforcer.Status.State != "ERROR" {
		t.Fatal("failed apply reported active")
	}
	fake.fail = ""
	if e = enforcer.Reconcile(); e != nil {
		t.Fatal(e)
	}
	if enforcer.Status.AppliedRevision != 18 {
		t.Fatal("retry failed")
	}
	if e = enforcer.ManualBreakGlass(); e != nil {
		t.Fatal(e)
	}
	if status := StatusForDesired(d, dir); status.State != "OUT_OF_SYNC" || status.AnchorPresent {
		t.Fatalf("manual breakglass status: %+v", status)
	}
	if !reflect.DeepEqual(fake.forward, newFake().forward) {
		t.Fatalf("breakglass changed unrelated rules: %v", fake.forward)
	}
}
func TestAnchorRepairKeepsWGEasyRules(t *testing.T) {
	dir := t.TempDir()
	peers, groups, resources := fixture()
	d, e := Compile(peers, resources, Resolve(peers, groups, resources, nil), 1, true)
	if e != nil {
		t.Fatal(e)
	}
	writeDesired(t, dir, d)
	fake := newFake()
	fake.forward = append(fake.forward, []string{"-i", "wg0", "-j", "WGACL_old"})
	fake.chains["WGACL_old"] = [][]string{{"-j", "RETURN"}}
	enforcer := &Enforcer{Dir: dir, Runner: fake}
	if e = enforcer.Reconcile(); e != nil {
		t.Fatal(e)
	}
	lines, broad, anchors, e := enforcer.inspect()
	if e != nil || len(anchors) != 1 || anchors[0] >= broad {
		t.Fatalf("anchor not repaired: %v %v", lines, e)
	}
	if !equal(fake.forward[2], []string{"-o", "wg0", "-j", "ACCEPT"}) {
		t.Fatalf("unrelated rule changed: %v", fake.forward)
	}
	if _, ok := fake.chains["WGACL_old"]; ok {
		t.Fatal("old chain retained")
	}
}
func TestFailedVerificationRollsBack(t *testing.T) {
	dir := t.TempDir()
	peers, groups, resources := fixture()
	allow := Resolve(peers, groups, resources, []Policy{{PeerID: 1, ResourceID: 1, Action: "ALLOW"}})
	d, e := Compile(peers, resources, allow, 1, true)
	if e != nil {
		t.Fatal(e)
	}
	writeDesired(t, dir, d)
	fake := newFake()
	enforcer := &Enforcer{Dir: dir, Runner: fake}
	if e = enforcer.Reconcile(); e != nil {
		t.Fatal(e)
	}
	previous := enforcer.Status.Chain
	d, e = Compile(peers, resources, Resolve(peers, groups, resources, nil), 2, true)
	if e != nil {
		t.Fatal(e)
	}
	writeDesired(t, dir, d)
	fake.breakVerify = true
	if e = enforcer.Reconcile(); e == nil {
		t.Fatal("verification failure ignored")
	}
	if enforcer.Status.AppliedRevision != 1 || enforcer.Status.State != "ERROR" {
		t.Fatal(enforcer.Status)
	}
	lines, _, anchors, e := enforcer.inspect()
	if e != nil || len(anchors) != 1 || anchorChain(lines[anchors[0]-1]) != previous {
		t.Fatalf("previous policy not restored: %v %v", lines, e)
	}
}
func TestMalformedDesiredCannotDisableACL(t *testing.T) {
	dir := t.TempDir()
	peers, groups, resources := fixture()
	d, e := Compile(peers, resources, Resolve(peers, groups, resources, nil), 1, true)
	if e != nil {
		t.Fatal(e)
	}
	writeDesired(t, dir, d)
	fake := newFake()
	enforcer := &Enforcer{Dir: dir, Runner: fake}
	if e = enforcer.Reconcile(); e != nil {
		t.Fatal(e)
	}
	original := append([][]string{}, fake.forward...)
	if e = os.WriteFile(filepath.Join(dir, "desired.json"), []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = enforcer.Reconcile(); e == nil {
		t.Fatal("malformed desired accepted")
	}
	if !reflect.DeepEqual(original, fake.forward) || enforcer.Status.AppliedRevision != 1 {
		t.Fatal("malformed desired changed active ACL")
	}
}
