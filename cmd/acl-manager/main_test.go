package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ibldzn/acl-manager/internal/acl"
)

func TestAdminPageAndPassiveRollout(t *testing.T) {
	dir := t.TempDir()
	s, e := acl.OpenStore(filepath.Join(dir, "acl.db"), dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	if e = s.SyncPeers("admin", []acl.Peer{{ExternalID: "1", PublicKey: "public-key", IP: "10.8.0.2", Name: "Alice", Enabled: true}}); e != nil {
		t.Fatal(e)
	}
	res := acl.Resource{Name: "DWH", Destination: "172.20.57.245/32", Protocol: "tcp", PortStart: 3306, PortEnd: 3306, Enabled: true}
	e = s.Change("admin", "resource.save", "DWH", nil, res, func(tx *sql.Tx) error {
		_, e := tx.Exec("INSERT INTO resources(name,description,destination,protocol,port_start,port_end,enabled) VALUES(?,?,?,?,?,?,?)", res.Name, "", res.Destination, res.Protocol, res.PortStart, res.PortEnd, true)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	v, e := s.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	if v.Desired.Activated {
		t.Fatal("installation activated enforcement")
	}
	a := &app{store: s, user: "admin", password: "secret", csrf: "token"}
	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "secret")
	w := httptest.NewRecorder()
	a.auth(httptestHandler(a.page)).ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("page: %d %s", w.Code, w.Body.String())
	}
	for _, text := range []string{"Alice", "DWH", "default DENY", "ACTIVATE", "OUT_OF_SYNC"} {
		if !strings.Contains(w.Body.String(), text) {
			t.Fatalf("page missing %s", text)
		}
	}
	form := url.Values{"csrf": {"token"}, "confirm": {"ACTIVATE"}}
	req = httptest.NewRequest("POST", "/activate", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("admin", "secret")
	w = httptest.NewRecorder()
	a.auth(httptestHandler(a.activate)).ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("activation without healthy enforcer returned %d", w.Code)
	}
	status, _ := json.Marshal(acl.Status{State: "INACTIVE", Heartbeat: time.Now().UTC().Format(time.RFC3339Nano)})
	if e = os.WriteFile(filepath.Join(dir, "status.json"), status, 0600); e != nil {
		t.Fatal(e)
	}
	req = httptest.NewRequest("POST", "/activate", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("admin", "secret")
	w = httptest.NewRecorder()
	a.auth(httptestHandler(a.activate)).ServeHTTP(w, req)
	if w.Code != 303 {
		t.Fatalf("reviewed activation returned %d: %s", w.Code, w.Body.String())
	}
	v, e = s.Snapshot()
	if e != nil || !v.Desired.Activated {
		t.Fatalf("activation not persisted: %+v %v", v.Desired, e)
	}
}

type httptestHandler func(http.ResponseWriter, *http.Request)

func (h httptestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h(w, r) }

func TestForgetRequiresExplicitIdentityAndAllowsReviewedReuse(t *testing.T) {
	dir := t.TempDir()
	s, e := acl.OpenStore(filepath.Join(dir, "acl.db"), dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	if e = s.SyncPeers("admin", []acl.Peer{{ExternalID: "old", PublicKey: "old-key", IP: "10.8.0.2", Enabled: true}}); e != nil {
		t.Fatal(e)
	}
	if e = s.SyncPeers("admin", nil); e != nil {
		t.Fatal(e)
	}
	v, e := s.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	a := &app{store: s, user: "admin", password: "secret", csrf: "token"}
	call := func(confirm string) int {
		form := url.Values{"csrf": {"token"}, "id": {strconv.FormatInt(v.Peers[0].ID, 10)}, "confirm": {confirm}}
		req := httptest.NewRequest("POST", "/peers/forget", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("admin", "secret")
		w := httptest.NewRecorder()
		a.auth(httptestHandler(a.peerForget)).ServeHTTP(w, req)
		return w.Code
	}
	if code := call("wrong"); code != 400 {
		t.Fatalf("wrong confirmation returned %d", code)
	}
	if code := call("old"); code != 303 {
		t.Fatalf("confirmed forget returned %d", code)
	}
	if e = s.SyncPeers("admin", []acl.Peer{{ExternalID: "new", PublicKey: "new-key", IP: "10.8.0.2", Enabled: true}}); e != nil {
		t.Fatal(e)
	}
	v, e = s.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	if len(v.Peers) != 1 || v.Peers[0].ExternalID != "new" || len(v.Peers[0].Groups) != 0 {
		t.Fatalf("identity was reinterpreted: %+v", v.Peers)
	}
}
func TestAdminAuthenticationAndCSRF(t *testing.T) {
	a := &app{user: "admin", password: "secret", csrf: "token"}
	called := false
	handler := a.auth(httptestHandler(func(http.ResponseWriter, *http.Request) { called = true }))
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != 401 || called {
		t.Fatal("unauthenticated request reached handler")
	}
	req = httptest.NewRequest("POST", "/retry", strings.NewReader("csrf=wrong"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("admin", "secret")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != 403 || called {
		t.Fatal("invalid CSRF reached handler")
	}
}
func TestUnavailablePeerSourceFailsClosed(t *testing.T) {
	dir := t.TempDir()
	s, e := acl.OpenStore(filepath.Join(dir, "acl.db"), dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	if e = s.SyncPeers("admin", []acl.Peer{{ExternalID: "1", PublicKey: "key", IP: "10.8.0.2", Enabled: true}}); e != nil {
		t.Fatal(e)
	}
	a := &app{store: s}
	if e = a.doSync(context.Background(), "system"); e == nil {
		t.Fatal("unavailable source reported success")
	}
	v, e := s.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	if v.Peers[0].SyncStatus != "missing" {
		t.Fatal("stale peer still eligible for ALLOW")
	}
	status, e := s.LastSync()
	if e != nil || status.State != "ERROR" {
		t.Fatalf("sync error not visible: %+v %v", status, e)
	}
}
