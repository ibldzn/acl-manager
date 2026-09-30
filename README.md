# WireGuard ACL Manager

ACL Manager reads peers from wg-easy and applies access controls to **registered internal resources only**. wg-easy continues to own peer creation, keys, addresses, WireGuard configuration, and its existing forwarding/NAT rules.

## How it works

- The web service is a non-root Go admin application backed by SQLite. It uses one configured HTTP Basic admin account and a CSRF token for changes. It stores peers, groups, resources, policies, desired revision, and an admin audit trail in `/state/acl.db`.
- The enforcer is a separate container with `CAP_NET_ADMIN`, joined to the `wg-easy` network namespace. It reads `/state/desired.json`, manipulates only `WGACL_*` chains and one `-i wg0` FORWARD anchor, and writes `/state/status.json` plus an append-only enforcement audit log. The web service has no Docker socket or firewall privilege.
- The enforcer uses **iptables-legacy** inside that namespace because wg-easy's observed FORWARD path uses legacy iptables. It never changes host alternatives, wg-easy's `-i wg0 -j ACCEPT` / `-o wg0 -j ACCEPT` rules, or NAT.
- Group and peer policies resolve in the application. Every enabled resource has default DENY; any explicit DENY beats any ALLOW. The firewall sees only peer `/32` ALLOW rules followed by a destination/protocol/port DROP for each enabled resource, then RETURN. Disabled resources emit no rules. Unregistered destinations RETURN to wg-easy.
- Enabled resources with overlapping destination/protocol/port matches are rejected, so one resource's ALLOW cannot bypass another's DENY.
- The web service synchronizes peers on startup and every 30 seconds. If wg-easy cannot provide a valid peer list, it marks synchronized peers missing and republishes a deny-only managed-resource policy. A detected IP/key identity collision quarantines the old peer and requires an explicit **Forget ACL record** action before reuse. The UI and diagnostics show the last sync result. Unregistered destinations still RETURN to wg-easy.

The [wg-easy v15 API](https://wg-easy.github.io/wg-easy/v15.1/advanced/api/) uses Basic auth and `GET /api/client`. Set `WG_EASY_API_VERSION=14` for the older session-cookie API (`POST /api/session`, then `GET /api/wireguard/client`). The adapter stores no private or preshared keys. wg-easy's API is [not stable](https://wg-easy.github.io/wg-easy/v15.1/advanced/api/); validate sync against the deployed version before activation.

## Deployment

1. Leave the existing `wg-easy` container and its image unchanged. Ensure its container name is `wg-easy`, its admin API is reachable from the web container, and `wg0` / the broad FORWARD ACCEPT rule are present.
2. Create `secrets/acl_admin_password` and `secrets/wg_easy_password` (owner-only permissions). Set `WG_EASY_URL`, `WG_EASY_USER`, and `WG_EASY_API_VERSION` as needed. v14 uses only the password; v15 requires an admin username/password without 2FA for API access.
3. Run `docker compose -f compose.acl.example.yaml up -d --build`. The example binds the admin UI to host loopback port 8080; put it behind your existing authenticated HTTPS reverse proxy if remote access is needed. Keep wg-easy's API on a trusted local path.
4. Run `scripts/firewall-integration.sh` on a Docker host to check real legacy iptables syntax in a disposable namespace. Open `http://127.0.0.1:8080`. Confirm peer sync succeeds and the enforcer reports `INACTIVE`, create resources and policies, inspect the effective policy matrix, then type `ACTIVATE`. **Installation and synchronization do not install an ACL anchor.** Activation is the first enforcement step.
5. Confirm the UI shows matching desired/applied revisions and `IN_SYNC`. After activation, any peer without ALLOW to an enabled registered resource is denied there. Unregistered destinations keep wg-easy behavior.

The example is for an **existing named container**. Install `scripts/watch-wg-easy.sh` as a host service using `systemd/acl-enforcer-watch.service.example`: copy the unit to `/etc/systemd/system/acl-enforcer-watch.service`, edit `ExecStart` to this checkout, then run `sudo systemctl daemon-reload && sudo systemctl enable --now acl-enforcer-watch`. It checks the wg-easy container ID and network-namespace inode every five seconds and recreates **only the enforcer** when either changes or the sidecar is stopped. This host service needs Docker access; the web container never receives it. The enforcer also exits if a previously seen `wg0` disappears. This explicit lifecycle step is needed because [Docker can leave namespace-sharing containers attached to an old parent namespace](https://github.com/moby/moby/issues/36334).

If wg-easy is already a service in the same Compose project, prefer `network_mode: "service:wg-easy"` and `depends_on: {wg-easy: {condition: service_started, restart: true}}` for the enforcer. [Compose restarts a dependent service after explicit Compose operations](https://docs.docker.com/compose/how-tos/startup-order/). Keep the watcher or otherwise verify automatic runtime restarts and recreation on your Docker version. After any wg-easy replacement, check `IN_SYNC` and the anchor order.

## Safe inspection and recovery

```sh
curl -u admin http://127.0.0.1:8080/api/diagnostics
curl -u admin http://127.0.0.1:8080/api/audit
docker compose -f compose.acl.example.yaml exec acl-enforcer iptables-legacy -S FORWARD
docker compose -f compose.acl.example.yaml exec acl-enforcer iptables-legacy -S WGACL_CHAIN_NAME
```

Use the chain name reported by diagnostics in the last command. The API shows synchronized peers, effective peer/resource results and reasons, desired and applied revisions, active chain, anchor presence/order, checksum, last attempt/success/error, and heartbeat. A stale enforcer heartbeat displays `OUT_OF_SYNC`.

For break-glass, **stop the host watcher (if installed) and enforcer first** so neither can reapply desired policy:

```sh
sudo systemctl stop acl-enforcer-watch
docker compose -f compose.acl.example.yaml stop acl-enforcer
docker compose -f compose.acl.example.yaml run --rm --no-deps acl-enforcer breakglass
docker exec wg-easy iptables-legacy -S FORWARD
```

`breakglass` removes only `-i wg0 -j WGACL_*` anchors and owned chains. It leaves wg-easy's `-i wg0 -j ACCEPT` and `-o wg0 -j ACCEPT` in place. It does not delete peers. If the ACL image is unavailable, run `iptables-legacy -S FORWARD` inside the wg-easy namespace, delete only `WGACL_*` anchor rules with `iptables-legacy -D FORWARD -i wg0 -j WGACL_NAME`, then flush/delete those now-unreferenced `WGACL_*` chains. Do not flush FORWARD.

To retry after fixing wg-easy or the enforcer, start the enforcer and host watcher, then use **Reconcile / retry** in the UI. It checks actual chain content and anchor order every five seconds, so missing firewall state is rebuilt. Policy updates stage a new unreferenced chain, verify it, switch one anchor rule, verify the active state, and only then remove the previous chain. A failed switch attempts rollback and reports an error; saved policy alone never counts as applied.

To roll back policy data, stop the web service, back up `acl.db`, restore a known-good copy, and start web/enforcer again. Web republishes the database's desired state on startup. For decommissioning, stop the watcher, perform break-glass, then remove the ACL services and volume only after preserving any audit data you need. The original wg-easy forwarding remains.

## Data and operational limits

- SQLite schema version 1 is created on first start; no existing wg-easy data is migrated or modified. Unique constraints reserve every synchronized VPN IPv4, including missing peer tombstones. A peer with the same wg-easy ID and public key may move to an unused IP; public-key changes or IP reassignment to a different ID fail sync for manual review. After review, use **Forget ACL record** on the old peer and type its exact wg-easy ID. That audited action removes only its ACL record, memberships, and direct policies; the next sync imports the current wg-easy identity as a new, default-denied peer.
- Initial activation requires a successful peer sync, at least one resource, and a healthy inactive enforcer. The current UI deliberately has no deactivation control: use break-glass when immediate original forwarding is required.
- The example uses a shared named volume. Back it up as durable policy/audit state. `status.json` reflects applied kernel state, not policy ownership; an enforcer restart rechecks the kernel before reporting `IN_SYNC`.
- Run one web replica against the SQLite state volume. Admin writes are serialized in that process.
- Routine tests use a fake iptables runner and need no root. The deployment's real kernel path should be smoke-tested in an isolated wg-easy namespace before production activation.

## Development

```sh
go test ./...
go run ./cmd/acl-manager web
```

For local web use, set `ACL_ADMIN_PASSWORD`, `WG_EASY_URL`, `WG_EASY_USER`, and `WG_EASY_PASSWORD`. The web process never calls iptables.

`scripts/firewall-integration.sh` is an opt-in real iptables test in a disposable Docker network namespace. It requires a Docker daemon; normal `go test ./...` does not require root or Docker.
`scripts/watch-test.sh` checks the host watcher with a fake Docker CLI.
