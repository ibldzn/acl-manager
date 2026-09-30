#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/docker" <<'EOF'
#!/bin/sh
case "$1:$2:$3" in
  'inspect:-f:{{.Id}}') echo container-id ;;
  'inspect:-f:{{.State.Pid}}') echo 12345 ;;
  'compose:-f:'*) case "$*" in
    *' ps -q acl-enforcer') : ;;
    *' up -d --no-build --force-recreate --no-deps acl-enforcer') echo recreated > "$WATCH_TEST_LOG" ;;
    *) exit 1 ;;
  esac ;;
  *) exit 1 ;;
esac
EOF
cat > "$tmp/stat" <<'EOF'
#!/bin/sh
echo namespace-inode
EOF
chmod +x "$tmp/docker" "$tmp/stat"
ACL_WATCH_ONCE=1 WATCH_TEST_LOG="$tmp/result" PATH="$tmp:$PATH" sh scripts/watch-wg-easy.sh
test "$(cat "$tmp/result")" = recreated
