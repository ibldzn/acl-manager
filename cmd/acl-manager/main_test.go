package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
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
	for _, text := range []string{"Enforcement health", "Desired revision", "ACTIVATE", "OUT_OF_SYNC"} {
		if !strings.Contains(w.Body.String(), text) {
			t.Fatalf("page missing %s", text)
		}
	}
	if strings.Contains(w.Body.String(), "Alice") || strings.Contains(w.Body.String(), "DWH") {
		t.Fatal("overview contains management inventory")
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
	if w.Header().Get("Location") != "/" {
		t.Fatalf("activation redirect: %s", w.Header().Get("Location"))
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

func TestPageRoutesAndEscaping(t *testing.T) {
	dir := t.TempDir()
	s, e := acl.OpenStore(filepath.Join(dir, "acl.db"), dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	unsafe := `<img src=x onerror=alert(1)>`
	if e = s.SyncPeers("admin", []acl.Peer{{ExternalID: "peer-1", PublicKey: "public-key", IP: "10.8.0.2", Name: unsafe, Enabled: true}}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec("INSERT INTO groups(name) VALUES(?)", unsafe); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec("INSERT INTO resources(name,description,destination,protocol,port_start,port_end,enabled) VALUES(?,?,?,?,?,?,?)", unsafe, unsafe, "172.20.57.245/32", "tcp", 443, 443, true); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec("INSERT INTO policies(peer_id,resource_id,action) VALUES(1,1,'ALLOW')"); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "enforcer-audit.jsonl"), []byte(`{"At":"2026-09-30T00:00:00Z","Actor":"enforcer","Action":"apply","Target":"`+unsafe+`","Error":"test error"}`+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	a := &app{store: s, user: "admin", password: "secret", csrf: "token"}
	h := a.auth(a.routes())
	for _, tc := range []struct{ path, title string }{
		{"/", "Overview"}, {"/peers", "Peers"}, {"/groups", "Groups"}, {"/groups?id=1", "Groups"},
		{"/resources", "Resources"}, {"/resources?edit=1", "Resources"}, {"/policies", "Policies"},
		{"/policies?view=effective", "Policies"}, {"/diagnostics", "Diagnostics"}, {"/audit", "Audit"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.path, nil)
			req.SetBasicAuth("admin", "secret")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != 200 || !strings.Contains(w.Body.String(), "<h1>"+tc.title+"</h1>") {
				t.Fatalf("%s: %d %s", tc.path, w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), `aria-current="page"`) {
				t.Fatal("active navigation missing")
			}
			if strings.Contains(w.Body.String(), unsafe) {
				t.Fatal("unescaped HTML")
			}
		})
	}
	for _, path := range []string{"/peers", "/groups?id=1", "/resources?edit=1", "/policies", "/policies?view=effective"} {
		req := httptest.NewRequest("GET", path, nil)
		req.SetBasicAuth("admin", "secret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if !strings.Contains(w.Body.String(), "&lt;img src=x onerror=alert(1)&gt;") {
			t.Errorf("%s lacks escaped content", path)
		}
	}
	req := httptest.NewRequest("GET", "/audit", nil)
	req.SetBasicAuth("admin", "secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), "enforcer") || !strings.Contains(w.Body.String(), "test error") {
		t.Fatal("enforcer audit event missing")
	}
	req = httptest.NewRequest("GET", "/policies?view=effective&result=DENY", nil)
	req.SetBasicAuth("admin", "secret")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), "No matching access entries") {
		t.Fatal("effective result filter ignored")
	}
	for _, path := range []string{"/unknown", "/peers/unknown"} {
		req := httptest.NewRequest("GET", path, nil)
		req.SetBasicAuth("admin", "secret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 404 {
			t.Errorf("%s: got %d", path, w.Code)
		}
	}
	for _, path := range []string{"/", "/peers", "/groups", "/resources", "/policies", "/diagnostics", "/audit", "/api/diagnostics", "/api/audit", "/static/app.css"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 401 {
			t.Errorf("unauthenticated %s: got %d", path, w.Code)
		}
	}
	req = httptest.NewRequest("POST", "/groups/save", strings.NewReader("csrf=wrong&name=test"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("admin", "secret")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("CSRF: got %d", w.Code)
	}
}

func TestPostRedirects(t *testing.T) {
	dir := t.TempDir()
	s, e := acl.OpenStore(filepath.Join(dir, "acl.db"), dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	if e = s.SyncPeers("admin", []acl.Peer{{ExternalID: "peer-1", PublicKey: "key", IP: "10.8.0.2", Name: "Peer", Enabled: true}}); e != nil {
		t.Fatal(e)
	}
	a := &app{store: s, user: "admin", password: "secret", csrf: "token"}
	h := a.auth(a.routes())
	a.source = acl.PeerSource{URL: "http://wg-easy", Client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`[{"id":"peer-1","name":"Peer","publicKey":"key","ipv4Address":"10.8.0.2","enabled":true}]`)), Header: make(http.Header)}, nil
	})}}
	post := func(path string, values url.Values, want string) {
		t.Helper()
		values.Set("csrf", "token")
		req := httptest.NewRequest("POST", path, strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("admin", "secret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 303 || w.Header().Get("Location") != want {
			t.Fatalf("%s: %d %s: %s", path, w.Code, w.Header().Get("Location"), w.Body.String())
		}
	}
	post("/sync", url.Values{}, "/peers")
	post("/groups/save", url.Values{"id": {"0"}, "name": {"IT"}}, "/groups")
	post("/groups/save", url.Values{"id": {"1"}, "name": {"IT"}}, "/groups")
	post("/membership", url.Values{"peer_id": {"1"}, "group_id": {"1"}, "action": {"add"}}, "/groups?id=1")
	post("/membership", url.Values{"peer_id": {"1"}, "group_id": {"1"}, "action": {"remove"}}, "/groups?id=1")
	post("/resources/save", url.Values{"id": {"0"}, "name": {"Server"}, "destination": {"172.20.57.245/32"}, "protocol": {"tcp"}, "port": {"443"}, "enabled": {"on"}}, "/resources")
	post("/resources/save", url.Values{"id": {"1"}, "name": {"Server"}, "destination": {"172.20.57.245/32"}, "protocol": {"tcp"}, "port": {"443"}, "enabled": {"on"}}, "/resources")
	post("/policies/save", url.Values{"peer_id": {"1"}, "group_id": {"0"}, "resource_id": {"1"}, "action": {"ALLOW"}}, "/policies")
	post("/policies/delete", url.Values{"id": {"1"}}, "/policies")
	post("/resources/delete", url.Values{"id": {"1"}}, "/resources")
	post("/groups/delete", url.Values{"id": {"1"}}, "/groups")
	post("/peers/forget", url.Values{"id": {"1"}, "confirm": {"peer-1"}}, "/peers")
	post("/retry", url.Values{}, "/")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
