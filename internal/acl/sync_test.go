package acl

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(code int, body string, cookie bool) *http.Response {
	headers := http.Header{}
	if cookie {
		headers.Add("Set-Cookie", "wg-easy-session=session")
	}
	return &http.Response{StatusCode: code, Header: headers, Body: io.NopCloser(strings.NewReader(body))}
}
func TestWGEasyPeerSources(t *testing.T) {
	for _, version := range []string{"14", "15"} {
		t.Run(version, func(t *testing.T) {
			client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
				if version == "14" && r.URL.Path == "/api/session" {
					return response(200, "", true), nil
				}
				if version == "14" {
					if r.URL.Path != "/api/wireguard/client" {
						t.Error(r.URL.Path)
					}
					if _, e := r.Cookie("wg-easy-session"); e != nil {
						t.Error(e)
					}
					return response(200, `[{"id":"uuid-1","name":"Alice","address":"10.8.0.2","publicKey":"key","enabled":false}]`, false), nil
				}
				if r.URL.Path != "/api/client" {
					t.Error(r.URL.Path)
				}
				u, p, ok := r.BasicAuth()
				if !ok || u != "admin" || p != "secret" {
					t.Error("missing basic auth")
				}
				return response(200, `[{"id":1,"name":"Alice","ipv4Address":"10.8.0.2","publicKey":"key","enabled":false}]`, false), nil
			})}
			source := PeerSource{URL: "http://wg-easy", Version: version, Username: "admin", Password: "secret", Client: client}
			peers, e := source.Fetch(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if len(peers) != 1 || peers[0].IP != "10.8.0.2" || peers[0].Name != "Alice" || peers[0].Enabled || peers[0].PublicKey != "key" {
				t.Fatalf("%+v", peers)
			}
		})
	}
}
func TestWGEasyBadResponseDoesNotBecomeEmptySync(t *testing.T) {
	client := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		return response(200, `{"error":"wrong shape"}`, false), nil
	})}
	_, e := (PeerSource{URL: "http://wg-easy", Version: "15", Client: client}).Fetch(context.Background())
	if e == nil {
		t.Fatal("malformed response accepted")
	}
}
