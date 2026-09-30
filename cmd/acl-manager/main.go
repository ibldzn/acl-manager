package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ibldzn/acl-manager/internal/acl"
)

type app struct {
	store                *acl.Store
	source               acl.PeerSource
	user, password, csrf string
	// ponytail: one writer keeps validation and publication ordered; add a distributed lock only for multiple web replicas.
	mu sync.Mutex
}

func secret(name string) string {
	if path := os.Getenv(name + "_FILE"); path != "" {
		b, e := os.ReadFile(path)
		if e != nil {
			log.Fatal(e)
		}
		return strings.TrimSpace(string(b))
	}
	return os.Getenv(name)
}
func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
func main() {
	mode := "web"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	dir := env("ACL_STATE_DIR", "./state")
	if mode == "enforcer" {
		(&acl.Enforcer{Dir: dir}).Loop()
		return
	}
	if mode == "reconcile-once" {
		e := &acl.Enforcer{Dir: dir}
		if err := e.Reconcile(); err != nil {
			log.Fatal(err)
		}
		_ = json.NewEncoder(os.Stdout).Encode(e.Status)
		return
	}
	if mode == "breakglass" {
		e := &acl.Enforcer{Dir: dir, Runner: acl.ExecRunner{}}
		if err := e.ManualBreakGlass(); err != nil {
			log.Fatal(err)
		}
		fmt.Println("ACL anchors removed; wg-easy forwarding preserved")
		return
	}
	if mode != "web" {
		log.Fatal("usage: acl-manager [web|enforcer|reconcile-once|breakglass]")
	}
	store, e := acl.OpenStore(env("ACL_DB_PATH", filepath.Join(dir, "acl.db")), dir)
	if e != nil {
		log.Fatal(e)
	}
	defer store.DB.Close()
	password := secret("ACL_ADMIN_PASSWORD")
	if password == "" {
		log.Fatal("ACL_ADMIN_PASSWORD or ACL_ADMIN_PASSWORD_FILE is required")
	}
	b := make([]byte, 32)
	if _, e = rand.Read(b); e != nil {
		log.Fatal(e)
	}
	a := &app{store: store, user: env("ACL_ADMIN_USER", "admin"), password: password, csrf: hex.EncodeToString(b), source: acl.PeerSource{URL: os.Getenv("WG_EASY_URL"), Version: env("WG_EASY_API_VERSION", "15"), Username: secret("WG_EASY_USER"), Password: secret("WG_EASY_PASSWORD")}}
	if e = a.doSync(context.Background(), "system"); e != nil {
		log.Printf("initial peer sync: %v", e)
	}
	if e = store.Publish(); e != nil {
		log.Fatal(e)
	}
	go a.syncLoop()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.page)
	mux.HandleFunc("GET /api/diagnostics", a.diagnostics)
	mux.HandleFunc("GET /api/audit", a.audit)
	mux.HandleFunc("POST /sync", a.sync)
	mux.HandleFunc("POST /peers/forget", a.peerForget)
	mux.HandleFunc("POST /activate", a.activate)
	mux.HandleFunc("POST /retry", a.retry)
	mux.HandleFunc("POST /groups/save", a.groupSave)
	mux.HandleFunc("POST /groups/delete", a.groupDelete)
	mux.HandleFunc("POST /membership", a.membership)
	mux.HandleFunc("POST /resources/save", a.resourceSave)
	mux.HandleFunc("POST /resources/delete", a.resourceDelete)
	mux.HandleFunc("POST /policies/save", a.policySave)
	mux.HandleFunc("POST /policies/delete", a.policyDelete)
	server := &http.Server{Addr: env("ACL_LISTEN", "127.0.0.1:8080"), Handler: a.auth(mux), ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServe())
}
func (a *app) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(a.user)) != 1 || subtle.ConstantTimeCompare([]byte(p), []byte(a.password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="ACL Manager"`)
			http.Error(w, "admin authentication required", 401)
			return
		}
		if r.Method == "POST" {
			if e := r.ParseForm(); e != nil {
				http.Error(w, e.Error(), 400)
				return
			}
			if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(a.csrf)) != 1 {
				http.Error(w, "invalid CSRF token", 403)
				return
			}
			a.mu.Lock()
			defer a.mu.Unlock()
		}
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
func id(r *http.Request, key string) (int64, error) {
	n, e := strconv.ParseInt(r.FormValue(key), 10, 64)
	if e != nil || n < 0 {
		return 0, errors.New("invalid " + key)
	}
	return n, nil
}
func fail(w http.ResponseWriter, e error) { http.Error(w, e.Error(), 400) }
func done(w http.ResponseWriter, r *http.Request, e error) {
	if e != nil {
		fail(w, e)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (a *app) sync(w http.ResponseWriter, r *http.Request) {
	done(w, r, a.doSync(context.Background(), a.user))
}
func (a *app) doSync(ctx context.Context, actor string) error {
	peers, e := a.source.Fetch(ctx)
	if e == nil {
		e = a.store.SyncPeers(actor, peers)
	}
	if e != nil && !errors.Is(e, acl.ErrIdentityConflict) {
		if quarantineErr := a.store.FailPeerSync(actor, e); quarantineErr != nil {
			return fmt.Errorf("peer sync failed: %v; fail-closed update failed: %w", e, quarantineErr)
		}
	}
	return e
}
func (a *app) syncLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		a.mu.Lock()
		if e := a.doSync(context.Background(), "system"); e != nil {
			log.Printf("peer sync: %v", e)
		}
		a.mu.Unlock()
	}
}
func (a *app) peerForget(w http.ResponseWriter, r *http.Request) {
	pid, e := id(r, "id")
	if e != nil || pid == 0 {
		fail(w, errors.New("invalid peer"))
		return
	}
	var p acl.Peer
	e = a.store.DB.QueryRow("SELECT id,external_id,public_key,ip,name,enabled,sync_status,last_seen FROM peers WHERE id=?", pid).Scan(&p.ID, &p.ExternalID, &p.PublicKey, &p.IP, &p.Name, &p.Enabled, &p.SyncStatus, &p.LastSeen)
	if e != nil {
		fail(w, e)
		return
	}
	if r.FormValue("confirm") != p.ExternalID {
		fail(w, errors.New("type the exact wg-easy peer ID to forget this ACL record"))
		return
	}
	v, e := a.store.Snapshot()
	if e != nil {
		fail(w, e)
		return
	}
	before := struct {
		Peer     acl.Peer
		Policies []acl.Policy
	}{Peer: p}
	for _, existing := range v.Peers {
		if existing.ID == pid {
			before.Peer = existing
			break
		}
	}
	for _, policy := range v.Policies {
		if policy.PeerID == pid {
			before.Policies = append(before.Policies, policy)
		}
	}
	e = a.store.Change(a.user, "peer.forget", p.ExternalID, before, nil, func(tx *sql.Tx) error {
		if _, e := tx.Exec("DELETE FROM policies WHERE peer_id=?", pid); e != nil {
			return e
		}
		if _, e := tx.Exec("DELETE FROM memberships WHERE peer_id=?", pid); e != nil {
			return e
		}
		_, e := tx.Exec("DELETE FROM peers WHERE id=?", pid)
		return e
	})
	done(w, r, e)
}
func (a *app) activate(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("confirm") != "ACTIVATE" {
		fail(w, errors.New("type ACTIVATE to enable enforcement"))
		return
	}
	v, e := a.store.Snapshot()
	if e != nil {
		fail(w, e)
		return
	}
	st := acl.StatusForDesired(v.Desired, a.store.StateDir)
	if st.State != "INACTIVE" || st.LastError != "" {
		fail(w, errors.New("enforcer must be healthy and inactive before activation"))
		return
	}
	// Initial activation requires successful peer sync and a reviewed resource set.
	syncStatus, e := a.store.LastSync()
	if e != nil {
		fail(w, e)
		return
	}
	if syncStatus.State != "OK" || len(v.Resources) == 0 {
		fail(w, errors.New("complete a successful peer sync and create resources before activation"))
		return
	}
	e = a.store.Change(a.user, "enforcement.activate", "firewall", v.Desired, true, func(tx *sql.Tx) error { _, e := tx.Exec("UPDATE settings SET activated=1 WHERE id=1"); return e })
	done(w, r, e)
}
func (a *app) retry(w http.ResponseWriter, r *http.Request) {
	e := a.store.Publish()
	if e == nil {
		e = a.store.Log(a.user, "enforcement.retry", "firewall", nil, nil)
	}
	done(w, r, e)
}
func (a *app) groupSave(w http.ResponseWriter, r *http.Request) {
	gid, e := id(r, "id")
	if e != nil {
		fail(w, e)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" || len(name) > 120 {
		fail(w, errors.New("group name required (max 120 characters)"))
		return
	}
	var before any
	if gid > 0 {
		var old string
		e = a.store.DB.QueryRow("SELECT name FROM groups WHERE id=?", gid).Scan(&old)
		if e != nil {
			fail(w, e)
			return
		}
		before = old
	}
	e = a.store.Change(a.user, "group.save", strconv.FormatInt(gid, 10), before, name, func(tx *sql.Tx) error {
		if gid == 0 {
			_, e := tx.Exec("INSERT INTO groups(name) VALUES(?)", name)
			return e
		}
		res, e := tx.Exec("UPDATE groups SET name=? WHERE id=?", name, gid)
		if e != nil {
			return e
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return sql.ErrNoRows
		}
		return nil
	})
	done(w, r, e)
}
func (a *app) groupDelete(w http.ResponseWriter, r *http.Request) {
	gid, e := id(r, "id")
	if e != nil || gid == 0 {
		fail(w, errors.New("invalid group"))
		return
	}
	var name string
	e = a.store.DB.QueryRow("SELECT name FROM groups WHERE id=?", gid).Scan(&name)
	if e != nil {
		fail(w, e)
		return
	}
	e = a.store.Change(a.user, "group.delete", name, name, nil, func(tx *sql.Tx) error {
		if _, e := tx.Exec("DELETE FROM policies WHERE group_id=?", gid); e != nil {
			return e
		}
		if _, e := tx.Exec("DELETE FROM memberships WHERE group_id=?", gid); e != nil {
			return e
		}
		_, e := tx.Exec("DELETE FROM groups WHERE id=?", gid)
		return e
	})
	done(w, r, e)
}
func (a *app) membership(w http.ResponseWriter, r *http.Request) {
	pid, e := id(r, "peer_id")
	if e != nil {
		fail(w, e)
		return
	}
	gid, e := id(r, "group_id")
	if e != nil {
		fail(w, e)
		return
	}
	add := r.FormValue("action") == "add"
	if !add && r.FormValue("action") != "remove" {
		fail(w, errors.New("invalid action"))
		return
	}
	e = a.store.Change(a.user, "membership."+r.FormValue("action"), fmt.Sprintf("%d:%d", pid, gid), !add, add, func(tx *sql.Tx) error {
		if add {
			_, e := tx.Exec("INSERT OR IGNORE INTO memberships(peer_id,group_id) VALUES(?,?)", pid, gid)
			return e
		}
		_, e := tx.Exec("DELETE FROM memberships WHERE peer_id=? AND group_id=?", pid, gid)
		return e
	})
	done(w, r, e)
}
func parseResource(r *http.Request) (acl.Resource, error) {
	id, e := id(r, "id")
	if e != nil {
		return acl.Resource{}, e
	}
	start, end := 0, 0
	port := strings.TrimSpace(r.FormValue("port"))
	if port != "" {
		parts := strings.Split(port, "-")
		if len(parts) > 2 {
			return acl.Resource{}, errors.New("invalid port range")
		}
		start, e = strconv.Atoi(parts[0])
		if e != nil {
			return acl.Resource{}, e
		}
		end = start
		if len(parts) == 2 {
			end, e = strconv.Atoi(parts[1])
			if e != nil {
				return acl.Resource{}, e
			}
		}
	}
	res := acl.Resource{ID: id, Name: strings.TrimSpace(r.FormValue("name")), Description: strings.TrimSpace(r.FormValue("description")), Destination: strings.TrimSpace(r.FormValue("destination")), Protocol: r.FormValue("protocol"), PortStart: start, PortEnd: end, Enabled: r.FormValue("enabled") == "on"}
	if e = res.Validate(); e != nil {
		return res, e
	}
	return res, nil
}
func (a *app) resourceSave(w http.ResponseWriter, r *http.Request) {
	res, e := parseResource(r)
	if e != nil {
		fail(w, e)
		return
	}
	v, e := a.store.Snapshot()
	if e != nil {
		fail(w, e)
		return
	}
	var before any
	candidate := append([]acl.Resource{}, v.Resources...)
	found := false
	for i := range candidate {
		if candidate[i].ID == res.ID && res.ID > 0 {
			before = candidate[i]
			candidate[i] = res
			found = true
		}
	}
	if res.ID > 0 && !found {
		fail(w, sql.ErrNoRows)
		return
	}
	if !found {
		candidate = append(candidate, res)
	}
	if e = acl.ValidateResources(candidate); e != nil {
		fail(w, e)
		return
	}
	e = a.store.Change(a.user, "resource.save", res.Name, before, res, func(tx *sql.Tx) error {
		if res.ID == 0 {
			_, e := tx.Exec("INSERT INTO resources(name,description,destination,protocol,port_start,port_end,enabled) VALUES(?,?,?,?,?,?,?)", res.Name, res.Description, res.Destination, res.Protocol, res.PortStart, res.PortEnd, res.Enabled)
			return e
		}
		_, e := tx.Exec("UPDATE resources SET name=?,description=?,destination=?,protocol=?,port_start=?,port_end=?,enabled=? WHERE id=?", res.Name, res.Description, res.Destination, res.Protocol, res.PortStart, res.PortEnd, res.Enabled, res.ID)
		return e
	})
	done(w, r, e)
}
func (a *app) resourceDelete(w http.ResponseWriter, r *http.Request) {
	rid, e := id(r, "id")
	if e != nil || rid == 0 {
		fail(w, errors.New("invalid resource"))
		return
	}
	var name string
	e = a.store.DB.QueryRow("SELECT name FROM resources WHERE id=?", rid).Scan(&name)
	if e != nil {
		fail(w, e)
		return
	}
	e = a.store.Change(a.user, "resource.delete", name, name, nil, func(tx *sql.Tx) error {
		if _, e := tx.Exec("DELETE FROM policies WHERE resource_id=?", rid); e != nil {
			return e
		}
		_, e := tx.Exec("DELETE FROM resources WHERE id=?", rid)
		return e
	})
	done(w, r, e)
}
func (a *app) policySave(w http.ResponseWriter, r *http.Request) {
	pid, e := id(r, "peer_id")
	if e != nil {
		fail(w, e)
		return
	}
	gid, e := id(r, "group_id")
	if e != nil {
		fail(w, e)
		return
	}
	rid, e := id(r, "resource_id")
	if e != nil {
		fail(w, e)
		return
	}
	p := acl.Policy{PeerID: pid, GroupID: gid, ResourceID: rid, Action: r.FormValue("action")}
	if e = p.Validate(); e != nil {
		fail(w, e)
		return
	}
	var before any
	var previous string
	var lookupErr error
	if pid > 0 {
		lookupErr = a.store.DB.QueryRow("SELECT action FROM policies WHERE peer_id=? AND resource_id=?", pid, rid).Scan(&previous)
	} else {
		lookupErr = a.store.DB.QueryRow("SELECT action FROM policies WHERE group_id=? AND resource_id=?", gid, rid).Scan(&previous)
	}
	if lookupErr != nil && lookupErr != sql.ErrNoRows {
		fail(w, lookupErr)
		return
	}
	if lookupErr == nil {
		before = previous
	}
	e = a.store.Change(a.user, "policy.save", fmt.Sprintf("%d:%d:%d", pid, gid, rid), before, p, func(tx *sql.Tx) error {
		if pid > 0 {
			_, e := tx.Exec("INSERT INTO policies(peer_id,resource_id,action) VALUES(?,?,?) ON CONFLICT(peer_id,resource_id) DO UPDATE SET action=excluded.action", pid, rid, p.Action)
			return e
		}
		_, e := tx.Exec("INSERT INTO policies(group_id,resource_id,action) VALUES(?,?,?) ON CONFLICT(group_id,resource_id) DO UPDATE SET action=excluded.action", gid, rid, p.Action)
		return e
	})
	done(w, r, e)
}
func (a *app) policyDelete(w http.ResponseWriter, r *http.Request) {
	policyID, e := id(r, "id")
	if e != nil || policyID == 0 {
		fail(w, errors.New("invalid policy"))
		return
	}
	var p acl.Policy
	e = a.store.DB.QueryRow("SELECT id,COALESCE(peer_id,0),COALESCE(group_id,0),resource_id,action FROM policies WHERE id=?", policyID).Scan(&p.ID, &p.PeerID, &p.GroupID, &p.ResourceID, &p.Action)
	if e != nil {
		fail(w, e)
		return
	}
	e = a.store.Change(a.user, "policy.delete", strconv.FormatInt(policyID, 10), p, nil, func(tx *sql.Tx) error { _, e := tx.Exec("DELETE FROM policies WHERE id=?", policyID); return e })
	done(w, r, e)
}
func (a *app) diagnostics(w http.ResponseWriter, r *http.Request) {
	v, e := a.store.Snapshot()
	if e != nil {
		fail(w, e)
		return
	}
	syncStatus, e := a.store.LastSync()
	if e != nil {
		fail(w, e)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Snapshot acl.Snapshot   `json:"snapshot"`
		Status   acl.Status     `json:"status"`
		Sync     acl.SyncStatus `json:"sync"`
	}{v, acl.StatusForDesired(v.Desired, a.store.StateDir), syncStatus})
}
func (a *app) audit(w http.ResponseWriter, r *http.Request) {
	rows, e := a.store.DB.Query("SELECT at,actor,action,target,before_json,after_json FROM audit ORDER BY id DESC LIMIT 200")
	if e != nil {
		fail(w, e)
		return
	}
	defer rows.Close()
	type item struct{ At, Actor, Action, Target, Before, After string }
	out := []item{}
	for rows.Next() {
		var x item
		if e = rows.Scan(&x.At, &x.Actor, &x.Action, &x.Target, &x.Before, &x.After); e != nil {
			fail(w, e)
			return
		}
		out = append(out, x)
	}
	var enforcerEvents []json.RawMessage
	if f, readErr := os.Open(filepath.Join(a.store.StateDir, "enforcer-audit.jsonl")); readErr == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := append([]byte(nil), scanner.Bytes()...)
			if json.Valid(line) {
				enforcerEvents = append(enforcerEvents, json.RawMessage(line))
				if len(enforcerEvents) > 200 {
					enforcerEvents = enforcerEvents[1:]
				}
			}
		}
		if e = scanner.Err(); e != nil {
			fail(w, e)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Admin    []item            `json:"admin"`
		Enforcer []json.RawMessage `json:"enforcer"`
	}{out, enforcerEvents})
}
func (a *app) page(w http.ResponseWriter, r *http.Request) {
	v, e := a.store.Snapshot()
	if e != nil {
		fail(w, e)
		return
	}
	st := acl.StatusForDesired(v.Desired, a.store.StateDir)
	syncStatus, e := a.store.LastSync()
	if e != nil {
		fail(w, e)
		return
	}
	type row struct {
		Peer     acl.Peer
		Resource acl.Resource
		Cell     acl.MatrixCell
	}
	rows := []row{}
	access := map[int64][]string{}
	// ponytail: a direct join is enough for small admin tables; index peers/resources if this view grows slow.
	for _, cell := range v.Matrix {
		for _, p := range v.Peers {
			if p.ID == cell.PeerID {
				for _, res := range v.Resources {
					if res.ID == cell.ResourceID {
						rows = append(rows, row{p, res, cell})
						if cell.Result == "ALLOW" {
							access[p.ID] = append(access[p.ID], res.Name)
						}
					}
				}
			}
		}
	}
	data := struct {
		V      acl.Snapshot
		S      acl.Status
		Sync   acl.SyncStatus
		Rows   []row
		Access map[int64][]string
		CSRF   string
	}{v, st, syncStatus, rows, access, a.csrf}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if e = pageTemplate.Execute(w, data); e != nil {
		log.Print(e)
	}
}

var pageTemplate = template.Must(template.New("page").Funcs(template.FuncMap{"short": func(s string) string {
	if len(s) > 18 {
		return s[:18] + "…"
	}
	return s
}, "port": func(r acl.Resource) string {
	if r.PortStart == 0 {
		return "all"
	}
	if r.PortStart == r.PortEnd {
		return strconv.Itoa(r.PortStart)
	}
	return fmt.Sprintf("%d-%d", r.PortStart, r.PortEnd)
}, "group": func(gs []acl.Group, id int64) string {
	for _, g := range gs {
		if g.ID == id {
			return g.Name
		}
	}
	return "?"
}, "peer": func(ps []acl.Peer, id int64) string {
	for _, p := range ps {
		if p.ID == id {
			return p.Name + " (" + p.IP + ")"
		}
	}
	return "?"
}, "res": func(rs []acl.Resource, id int64) string {
	for _, r := range rs {
		if r.ID == id {
			return r.Name
		}
	}
	return "?"
}}).Parse(pageHTML))
