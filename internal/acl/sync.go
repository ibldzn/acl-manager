package acl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type PeerSource struct {
	URL, Version, Username, Password string
	Client                           *http.Client
}

func (s PeerSource) Fetch(ctx context.Context) ([]Peer, error) {
	if s.URL == "" {
		return nil, errors.New("WG_EASY_URL is required")
	}
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	base := strings.TrimRight(s.URL, "/")
	path := "/api/client"
	if s.Version == "14" {
		path = "/api/wireguard/client"
		payload, _ := json.Marshal(map[string]string{"password": s.Password})
		login, e := http.NewRequestWithContext(ctx, "POST", base+"/api/session", strings.NewReader(string(payload)))
		if e != nil {
			return nil, e
		}
		login.Header.Set("Content-Type", "application/json")
		loginRes, e := client.Do(login)
		if e != nil {
			return nil, e
		}
		loginRes.Body.Close()
		if loginRes.StatusCode != 200 && loginRes.StatusCode != 204 {
			return nil, fmt.Errorf("wg-easy v14 session: HTTP %d", loginRes.StatusCode)
		}
		cookies := loginRes.Cookies()
		if len(cookies) == 0 {
			return nil, errors.New("wg-easy v14 session cookie missing")
		}
		req, e := http.NewRequestWithContext(ctx, "GET", base+path, nil)
		if e != nil {
			return nil, e
		}
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		return fetchPeers(client, req, path)
	}
	if s.Version != "" && s.Version != "15" {
		return nil, errors.New("WG_EASY_API_VERSION must be 14 or 15")
	}
	url := base + path
	req, e := http.NewRequestWithContext(ctx, "GET", url, nil)
	if e != nil {
		return nil, e
	}
	req.SetBasicAuth(s.Username, s.Password)
	return fetchPeers(client, req, path)
}
func fetchPeers(client *http.Client, req *http.Request, path string) ([]Peer, error) {
	res, e := client.Do(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("wg-easy GET %s: HTTP %d", path, res.StatusCode)
	}
	body, e := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if e != nil {
		return nil, e
	}
	var raw []struct {
		ID          json.RawMessage `json:"id"`
		Name        string          `json:"name"`
		PublicKey   string          `json:"publicKey"`
		IPv4Address string          `json:"ipv4Address"`
		Address     string          `json:"address"`
		Enabled     *bool           `json:"enabled"`
	}
	if e = json.Unmarshal(body, &raw); e != nil {
		return nil, fmt.Errorf("unsupported wg-easy response: %w", e)
	}
	out := make([]Peer, 0, len(raw))
	for _, r := range raw {
		ip := r.IPv4Address
		if ip == "" {
			ip = r.Address
		}
		if strings.Contains(ip, "/") {
			ip = strings.Split(ip, "/")[0]
		}
		ip, e = IPv4(ip)
		if e != nil {
			return nil, e
		}
		externalID := strings.TrimSpace(string(r.ID))
		if strings.HasPrefix(externalID, "\"") {
			if e = json.Unmarshal(r.ID, &externalID); e != nil {
				return nil, e
			}
		}
		if externalID == "" || externalID == "null" {
			return nil, errors.New("wg-easy client missing ID")
		}
		enabled := true
		if r.Enabled != nil {
			enabled = *r.Enabled
		}
		out = append(out, Peer{ExternalID: externalID, PublicKey: r.PublicKey, IP: ip, Name: r.Name, Enabled: enabled, SyncStatus: "present"})
	}
	return out, nil
}
