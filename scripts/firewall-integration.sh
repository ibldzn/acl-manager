#!/bin/sh
# Opt-in real iptables test. Docker creates a throwaway network namespace.
set -eu
cd "$(dirname "$0")/.."
image=acl-manager:firewall-integration
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp internal/acl/testdata/desired.json "$tmp/desired.json"
docker build -t "$image" .
docker run --rm --network none --cap-drop ALL --cap-add NET_ADMIN \
  -v "$tmp:/state:Z" --entrypoint /bin/sh "$image" -ceu '
  iptables-legacy -A FORWARD -i wg0 -j ACCEPT
  iptables-legacy -A FORWARD -o wg0 -j ACCEPT
  acl-manager reconcile-once
  iptables-legacy -S FORWARD | awk '"'"'
    /^-A FORWARD -i wg0 -j WGACL_/ { anchor=NR }
    /^-A FORWARD -i wg0 -j ACCEPT$/ { broad=NR }
    /^-A FORWARD -o wg0 -j ACCEPT$/ { inbound=1 }
    END { exit !(anchor && broad && anchor<broad && inbound) }
  '"'"'
  chain=$(iptables-legacy -S | awk '"'"'/^-N WGACL_/ { print $2; exit }'"'"')
  iptables-legacy -S "$chain" | tail -n 1 | grep -q -- "-j RETURN"
  before=$(iptables-legacy -S FORWARD)
  acl-manager reconcile-once
  test "$before" = "$(iptables-legacy -S FORWARD)"
  acl-manager breakglass
  iptables-legacy -S FORWARD | grep -q "^-A FORWARD -i wg0 -j ACCEPT$"
  iptables-legacy -S FORWARD | grep -q "^-A FORWARD -o wg0 -j ACCEPT$"
  ! iptables-legacy -S FORWARD | grep -q WGACL_
'
