package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sort"
	"strconv"

	"github.com/ibldzn/acl-manager/internal/acl"
)

//go:embed templates/*.html static/*
var uiFiles embed.FS

type accessRow struct {
	Peer     acl.Peer
	Resource acl.Resource
	Cell     acl.MatrixCell
}
type auditRow struct{ At, Actor, Action, Target, Before, After, Error string }
type pageData struct {
	V                                        acl.Snapshot
	S                                        acl.Status
	Sync                                     acl.SyncStatus
	CSRF, Page, Title                        string
	Rows                                     []accessRow
	Allow                                    map[int64]int
	EnabledResources                         int
	ResourcePolicies                         map[int64]int
	Group                                    *acl.Group
	GroupPolicies                            int
	UnassignedPeers                          []acl.Peer
	Resource                                 *acl.Resource
	NewResource                              bool
	Effective                                bool
	FilterPeer, FilterResource, FilterResult string
	Audit                                    []auditRow
}

var pages = template.Must(template.New("").Funcs(template.FuncMap{
	"short": func(s string) string {
		if len(s) > 18 {
			return s[:18] + "…"
		}
		return s
	},
	"port": func(r acl.Resource) string {
		if r.PortStart == 0 {
			return "All"
		}
		if r.PortStart == r.PortEnd {
			return strconv.Itoa(r.PortStart)
		}
		return fmt.Sprintf("%d-%d", r.PortStart, r.PortEnd)
	},
	"group": func(gs []acl.Group, id int64) string {
		for _, g := range gs {
			if g.ID == id {
				return g.Name
			}
		}
		return "Unknown"
	},
	"peer": func(ps []acl.Peer, id int64) string {
		for _, p := range ps {
			if p.ID == id {
				if p.Name != "" {
					return p.Name
				}
				return p.IP
			}
		}
		return "Unknown"
	},
	"resource": func(rs []acl.Resource, id int64) string {
		for _, r := range rs {
			if r.ID == id {
				return r.Name
			}
		}
		return "Unknown"
	},
	"groupPolicies": func(policies []acl.Policy, id int64) int {
		n := 0
		for _, p := range policies {
			if p.GroupID == id {
				n++
			}
		}
		return n
	},
}).ParseFS(uiFiles, "templates/*.html"))

func stylesheet(w http.ResponseWriter, r *http.Request) {
	b, e := uiFiles.ReadFile("static/app.css")
	if e != nil {
		http.Error(w, "stylesheet unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Write(b)
}

func (a *app) page(w http.ResponseWriter, r *http.Request) {
	name := map[string]string{"/": "overview", "/peers": "peers", "/groups": "groups", "/resources": "resources", "/policies": "policies", "/diagnostics": "diagnostics", "/audit": "audit"}[r.URL.Path]
	if name == "" {
		http.NotFound(w, r)
		return
	}
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
	d := pageData{V: v, S: acl.StatusForDesired(v.Desired, a.store.StateDir), Sync: syncStatus, CSRF: a.csrf, Page: name, Title: map[string]string{"overview": "Overview", "peers": "Peers", "groups": "Groups", "resources": "Resources", "policies": "Policies", "diagnostics": "Diagnostics", "audit": "Audit"}[name], Allow: map[int64]int{}, ResourcePolicies: map[int64]int{}}
	d.Effective = name == "policies" && r.URL.Query().Get("view") == "effective"
	for _, res := range v.Resources {
		if res.Enabled {
			d.EnabledResources++
		}
	}
	for _, p := range v.Policies {
		d.ResourcePolicies[p.ResourceID]++
	}
	if name == "peers" || d.Effective {
		peers := map[int64]acl.Peer{}
		resources := map[int64]acl.Resource{}
		for _, p := range v.Peers {
			peers[p.ID] = p
		}
		for _, res := range v.Resources {
			resources[res.ID] = res
		}
		d.FilterPeer = r.URL.Query().Get("peer")
		d.FilterResource = r.URL.Query().Get("resource")
		d.FilterResult = r.URL.Query().Get("result")
		for _, c := range v.Matrix {
			if c.Result == "ALLOW" {
				d.Allow[c.PeerID]++
			}
			if !d.Effective || (d.FilterPeer != "" && d.FilterPeer != strconv.FormatInt(c.PeerID, 10)) || (d.FilterResource != "" && d.FilterResource != strconv.FormatInt(c.ResourceID, 10)) || (d.FilterResult != "" && d.FilterResult != c.Result) {
				continue
			}
			d.Rows = append(d.Rows, accessRow{peers[c.PeerID], resources[c.ResourceID], c})
		}
	}
	if name == "groups" {
		selected := r.URL.Query().Get("id")
		for i := range v.Groups {
			if strconv.FormatInt(v.Groups[i].ID, 10) == selected {
				d.Group = &v.Groups[i]
				break
			}
		}
		if d.Group != nil {
			for _, p := range v.Policies {
				if p.GroupID == d.Group.ID {
					d.GroupPolicies++
				}
			}
			for _, p := range v.Peers {
				member := false
				for _, id := range d.Group.Members {
					if p.ID == id {
						member = true
						break
					}
				}
				if !member {
					d.UnassignedPeers = append(d.UnassignedPeers, p)
				}
			}
		}
	}
	if name == "resources" {
		d.NewResource = r.URL.Query().Get("new") == "1"
		selected := r.URL.Query().Get("edit")
		for i := range v.Resources {
			if strconv.FormatInt(v.Resources[i].ID, 10) == selected {
				d.Resource = &v.Resources[i]
				break
			}
		}
	}
	if name == "audit" {
		data, err := a.auditData()
		if err != nil {
			fail(w, err)
			return
		}
		for _, x := range data.Admin {
			d.Audit = append(d.Audit, auditRow{At: x.At, Actor: x.Actor, Action: x.Action, Target: x.Target, Before: x.Before, After: x.After})
		}
		for i := len(data.Enforcer) - 1; i >= 0; i-- {
			var x auditRow
			if json.Unmarshal(data.Enforcer[i], &x) == nil {
				d.Audit = append(d.Audit, x)
			}
		}
		sort.SliceStable(d.Audit, func(i, j int) bool { return d.Audit[i].At > d.Audit[j].At })
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if e = pages.ExecuteTemplate(w, name, &d); e != nil {
		log.Print(e)
	}
}
