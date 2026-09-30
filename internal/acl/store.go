package acl

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	DB       *sql.DB
	StateDir string
}

var ErrIdentityConflict = errors.New("wg-easy peer identity conflict")

type SyncStatus struct {
	At    string `json:"at"`
	State string `json:"state"`
	Error string `json:"error,omitempty"`
}

const schema = `
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS peers (
 id INTEGER PRIMARY KEY, external_id TEXT NOT NULL UNIQUE, public_key TEXT NOT NULL DEFAULT '',
 ip TEXT NOT NULL UNIQUE, name TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL,
 sync_status TEXT NOT NULL CHECK(sync_status IN ('present','missing')),
 last_seen TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS peers_public_key ON peers(public_key) WHERE public_key<>'';
CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS memberships (
 peer_id INTEGER NOT NULL REFERENCES peers(id), group_id INTEGER NOT NULL REFERENCES groups(id),
 PRIMARY KEY(peer_id,group_id)
);
CREATE TABLE IF NOT EXISTS resources (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '',
 destination TEXT NOT NULL, protocol TEXT NOT NULL, port_start INTEGER NOT NULL,
 port_end INTEGER NOT NULL, enabled INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS policies (
 id INTEGER PRIMARY KEY, peer_id INTEGER REFERENCES peers(id), group_id INTEGER REFERENCES groups(id),
 resource_id INTEGER NOT NULL REFERENCES resources(id), action TEXT NOT NULL CHECK(action IN ('ALLOW','DENY')),
 CHECK((peer_id IS NOT NULL) != (group_id IS NOT NULL)),
 UNIQUE(peer_id,resource_id), UNIQUE(group_id,resource_id)
);
CREATE TABLE IF NOT EXISTS settings (
 id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, activated INTEGER NOT NULL
);
INSERT OR IGNORE INTO settings(id,revision,activated) VALUES(1,0,0);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
 target TEXT NOT NULL, before_json TEXT NOT NULL, after_json TEXT NOT NULL
);
`

func OpenStore(path, stateDir string) (*Store, error) {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	if e := os.MkdirAll(stateDir, 0750); e != nil {
		return nil, e
	}
	db, e := sql.Open("sqlite3", path+"?_foreign_keys=on&_busy_timeout=5000")
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	var version int
	if e = db.QueryRow("PRAGMA user_version").Scan(&version); e != nil {
		db.Close()
		return nil, e
	}
	if version > 1 {
		db.Close()
		return nil, fmt.Errorf("unsupported database schema version %d", version)
	}
	if version == 0 {
		tx, err := db.Begin()
		if err != nil {
			db.Close()
			return nil, err
		}
		if _, err = tx.Exec(schema); err == nil {
			_, err = tx.Exec("PRAGMA user_version=1")
		}
		if err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
		if err != nil {
			db.Close()
			return nil, err
		}
	}
	return &Store{DB: db, StateDir: stateDir}, nil
}
func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }
func audit(tx *sql.Tx, actor, action, target string, before, after any) error {
	b, _ := json.Marshal(before)
	a, _ := json.Marshal(after)
	_, e := tx.Exec("INSERT INTO audit(at,actor,action,target,before_json,after_json) VALUES(?,?,?,?,?,?)", now(), actor, action, target, string(b), string(a))
	return e
}
func bump(tx *sql.Tx) error {
	_, e := tx.Exec("UPDATE settings SET revision=revision+1 WHERE id=1")
	return e
}
func (s *Store) Change(actor, action, target string, before, after any, work func(*sql.Tx) error) error {
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = work(tx); e != nil {
		return e
	}
	if e = bump(tx); e != nil {
		return e
	}
	if e = audit(tx, actor, action, target, before, after); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	return s.Publish()
}
func (s *Store) Log(actor, action, target string, before, after any) error {
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = audit(tx, actor, action, target, before, after); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) Snapshot() (Snapshot, error) {
	var v Snapshot
	tx, e := s.DB.Begin()
	if e != nil {
		return v, e
	}
	defer tx.Rollback()
	rows, e := tx.Query("SELECT id,external_id,public_key,ip,name,enabled,sync_status,last_seen FROM peers ORDER BY ip")
	if e != nil {
		return v, e
	}
	for rows.Next() {
		var p Peer
		if e = rows.Scan(&p.ID, &p.ExternalID, &p.PublicKey, &p.IP, &p.Name, &p.Enabled, &p.SyncStatus, &p.LastSeen); e != nil {
			rows.Close()
			return v, e
		}
		v.Peers = append(v.Peers, p)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return v, e
	}
	rows, e = tx.Query("SELECT id,name FROM groups ORDER BY name")
	if e != nil {
		return v, e
	}
	for rows.Next() {
		var g Group
		if e = rows.Scan(&g.ID, &g.Name); e != nil {
			rows.Close()
			return v, e
		}
		v.Groups = append(v.Groups, g)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return v, e
	}
	rows, e = tx.Query("SELECT peer_id,group_id FROM memberships ORDER BY group_id,peer_id")
	if e != nil {
		return v, e
	}
	for rows.Next() {
		var pid, gid int64
		if e = rows.Scan(&pid, &gid); e != nil {
			rows.Close()
			return v, e
		}
		for i := range v.Peers {
			if v.Peers[i].ID == pid {
				v.Peers[i].Groups = append(v.Peers[i].Groups, gid)
			}
		}
		for i := range v.Groups {
			if v.Groups[i].ID == gid {
				v.Groups[i].Members = append(v.Groups[i].Members, pid)
			}
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return v, e
	}
	rows, e = tx.Query("SELECT id,name,description,destination,protocol,port_start,port_end,enabled FROM resources ORDER BY name")
	if e != nil {
		return v, e
	}
	for rows.Next() {
		var r Resource
		if e = rows.Scan(&r.ID, &r.Name, &r.Description, &r.Destination, &r.Protocol, &r.PortStart, &r.PortEnd, &r.Enabled); e != nil {
			rows.Close()
			return v, e
		}
		v.Resources = append(v.Resources, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return v, e
	}
	rows, e = tx.Query("SELECT id,COALESCE(peer_id,0),COALESCE(group_id,0),resource_id,action FROM policies ORDER BY id")
	if e != nil {
		return v, e
	}
	for rows.Next() {
		var p Policy
		if e = rows.Scan(&p.ID, &p.PeerID, &p.GroupID, &p.ResourceID, &p.Action); e != nil {
			rows.Close()
			return v, e
		}
		v.Policies = append(v.Policies, p)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return v, e
	}
	var revision int64
	var active bool
	if e = tx.QueryRow("SELECT revision,activated FROM settings WHERE id=1").Scan(&revision, &active); e != nil {
		return v, e
	}
	v.Matrix = Resolve(v.Peers, v.Groups, v.Resources, v.Policies)
	v.Desired, e = Compile(v.Peers, v.Resources, v.Matrix, revision, active)
	return v, e
}
func atomicJSON(path string, value any) error {
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".state-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Chmod(0644); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}
func (s *Store) Publish() error {
	v, e := s.Snapshot()
	if e != nil {
		return e
	}
	return atomicJSON(filepath.Join(s.StateDir, "desired.json"), v.Desired)
}
func ReadStatus(dir string) Status {
	var st Status
	b, e := os.ReadFile(filepath.Join(dir, "status.json"))
	if e != nil {
		return Status{State: "OUT_OF_SYNC", LastError: "enforcer status unavailable"}
	}
	if json.Unmarshal(b, &st) != nil {
		return Status{State: "ERROR", LastError: "invalid enforcer status"}
	}
	if t, e := time.Parse(time.RFC3339Nano, st.Heartbeat); e != nil || time.Since(t) > 20*time.Second {
		st.State = "OUT_OF_SYNC"
		st.LastError = "enforcer heartbeat stale"
	}
	return st
}
func StatusForDesired(d Desired, dir string) Status {
	st := ReadStatus(dir)
	if d.Activated {
		if st.State != "ERROR" && (st.State != "IN_SYNC" || st.AppliedRevision != d.Revision || st.Checksum != d.Checksum || !st.AnchorPresent || !st.AnchorBeforeAccept) {
			st.State = "OUT_OF_SYNC"
		}
	} else if st.State != "ERROR" && st.State != "INACTIVE" {
		st.State = "OUT_OF_SYNC"
	}
	return st
}
func (s *Store) SyncPeers(actor string, peers []Peer) error {
	ids := map[string]bool{}
	ips := map[string]bool{}
	keys := map[string]bool{}
	for i := range peers {
		p := &peers[i]
		var e error
		p.IP, e = IPv4(p.IP)
		if e != nil {
			return e
		}
		if p.ExternalID == "" || ids[p.ExternalID] || ips[p.IP] || (p.PublicKey != "" && keys[p.PublicKey]) {
			return errors.New("duplicate or missing wg-easy peer identity/IP/key")
		}
		ids[p.ExternalID] = true
		ips[p.IP] = true
		keys[p.PublicKey] = true
	}
	old, e := s.Snapshot()
	if e != nil {
		return e
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var conflicts []string
	changed := false
	markMissing := func(id int64) error {
		result, err := tx.Exec("UPDATE peers SET sync_status='missing' WHERE id=? AND sync_status='present'", id)
		if err != nil {
			return err
		}
		n, _ := result.RowsAffected()
		if n > 0 {
			changed = true
		}
		return nil
	}
	for _, p := range peers {
		var id int64
		var oldKey, oldIP, oldName, oldStatus string
		var oldEnabled bool
		e = tx.QueryRow("SELECT id,public_key,ip,name,enabled,sync_status FROM peers WHERE external_id=?", p.ExternalID).Scan(&id, &oldKey, &oldIP, &oldName, &oldEnabled, &oldStatus)
		if e != nil && e != sql.ErrNoRows {
			return e
		}
		var ownerID int64
		var owner string
		ownerErr := tx.QueryRow("SELECT id,external_id FROM peers WHERE ip=? OR (public_key<>'' AND public_key=?) ORDER BY CASE WHEN ip=? THEN 0 ELSE 1 END LIMIT 1", p.IP, p.PublicKey, p.IP).Scan(&ownerID, &owner)
		if ownerErr != nil && ownerErr != sql.ErrNoRows {
			return ownerErr
		}
		if ownerErr == nil && owner != p.ExternalID {
			if e = markMissing(ownerID); e != nil {
				return e
			}
			if id != 0 && id != ownerID {
				if e = markMissing(id); e != nil {
					return e
				}
			}
			conflicts = append(conflicts, fmt.Sprintf("IP/key for %s belongs to previous peer %s", p.ExternalID, owner))
			continue
		}
		if e == nil && oldKey != "" && p.PublicKey != "" && oldKey != p.PublicKey {
			if e = markMissing(id); e != nil {
				return e
			}
			conflicts = append(conflicts, fmt.Sprintf("peer %s changed public key", p.ExternalID))
			continue
		}
		if e == sql.ErrNoRows {
			_, e = tx.Exec("INSERT INTO peers(external_id,public_key,ip,name,enabled,sync_status,last_seen) VALUES(?,?,?,?,?,'present',?)", p.ExternalID, p.PublicKey, p.IP, p.Name, p.Enabled, now())
			if e == nil {
				changed = true
			}
		} else {
			if p.PublicKey == "" {
				p.PublicKey = oldKey
			}
			if oldKey != p.PublicKey || oldIP != p.IP || oldName != p.Name || oldEnabled != p.Enabled || oldStatus != "present" {
				changed = true
			}
			_, e = tx.Exec("UPDATE peers SET public_key=?,ip=?,name=?,enabled=?,sync_status='present',last_seen=? WHERE id=?", p.PublicKey, p.IP, p.Name, p.Enabled, now(), id)
		}
		if e != nil {
			return e
		}
	}
	marks := make([]string, 0, len(peers))
	args := make([]any, 0, len(peers))
	for _, p := range peers {
		marks = append(marks, "?")
		args = append(args, p.ExternalID)
	}
	query := "UPDATE peers SET sync_status='missing' WHERE sync_status='present'"
	if len(peers) > 0 {
		query += " AND external_id NOT IN (" + strings.Join(marks, ",") + ")"
	}
	result, e := tx.Exec(query, args...)
	if e != nil {
		return e
	}
	n, _ := result.RowsAffected()
	if n > 0 {
		changed = true
	}
	if changed {
		if e = bump(tx); e != nil {
			return e
		}
	}
	action := "peer.sync.ok"
	var before, after any
	if changed {
		action = "peer.sync"
		before = old.Peers
		after = peers
	} else {
		after = map[string]int{"count": len(peers)}
	}
	if e = audit(tx, actor, action, "wg-easy", before, after); e != nil {
		return e
	}
	if len(conflicts) > 0 {
		if e = audit(tx, actor, "peer.sync.conflict", "wg-easy", nil, conflicts); e != nil {
			return e
		}
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	if e = s.Publish(); e != nil {
		return e
	}
	if len(conflicts) > 0 {
		return fmt.Errorf("%w: %s; manual identity review required", ErrIdentityConflict, strings.Join(conflicts, "; "))
	}
	return nil
}
func (s *Store) FailPeerSync(actor string, cause error) error {
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	result, e := tx.Exec("UPDATE peers SET sync_status='missing' WHERE sync_status='present'")
	if e != nil {
		return e
	}
	changed, _ := result.RowsAffected()
	if changed > 0 {
		if e = bump(tx); e != nil {
			return e
		}
	}
	if e = audit(tx, actor, "peer.sync.failed", "wg-easy", nil, cause.Error()); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	if changed > 0 {
		return s.Publish()
	}
	return nil
}
func (s *Store) LastSync() (SyncStatus, error) {
	var out SyncStatus
	var action, after string
	e := s.DB.QueryRow("SELECT at,action,after_json FROM audit WHERE action IN ('peer.sync','peer.sync.ok','peer.sync.conflict','peer.sync.failed') ORDER BY id DESC LIMIT 1").Scan(&out.At, &action, &after)
	if e == sql.ErrNoRows {
		out.State = "NEVER"
		return out, nil
	}
	if e != nil {
		return out, e
	}
	if action == "peer.sync" || action == "peer.sync.ok" {
		out.State = "OK"
	} else {
		out.State = "ERROR"
		if json.Unmarshal([]byte(after), &out.Error) != nil {
			var messages []string
			if json.Unmarshal([]byte(after), &messages) == nil {
				out.Error = strings.Join(messages, "; ")
			}
		}
	}
	return out, nil
}
