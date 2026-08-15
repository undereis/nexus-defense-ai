#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this installer with sudo." >&2
  exit 1
fi

NEXUS_USER=${SUDO_USER:-}
if [ -z "$NEXUS_USER" ] || [ "$NEXUS_USER" = "root" ]; then
  echo "SUDO_USER must identify the non-root Nexus operator." >&2
  exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HELPER_DST=/usr/local/libexec/nexus-firewall
ANCHOR_DST=/etc/pf.anchors/nexus_defense
SUDOERS_DST=/etc/sudoers.d/nexus_defense
PF_CONF=/etc/pf.conf
PF_BACKUP=$(mktemp /tmp/nexus-pf.conf.XXXXXX)
SUDOERS_TMP=$(mktemp /tmp/nexus-sudoers.XXXXXX)

cleanup() {
  rm -f "$PF_BACKUP" "$SUDOERS_TMP"
}
trap cleanup EXIT INT TERM

install -d -o root -g wheel -m 755 /usr/local/libexec
install -o root -g wheel -m 755 "$SCRIPT_DIR/nexus_firewall_helper.py" "$HELPER_DST"
install -o root -g wheel -m 600 "$SCRIPT_DIR/nexus_defense.anchor" "$ANCHOR_DST"

cp "$PF_CONF" "$PF_BACKUP"
if ! grep -q 'load anchor "nexus_defense"' "$PF_CONF"; then
  {
    printf '\nanchor "nexus_defense"\n'
    printf 'load anchor "nexus_defense" from "/etc/pf.anchors/nexus_defense"\n'
  } >> "$PF_CONF"
fi

if ! /sbin/pfctl -nf "$PF_CONF"; then
  cp "$PF_BACKUP" "$PF_CONF"
  echo "Invalid pf configuration; restored the original file." >&2
  exit 1
fi

sed "s/__NEXUS_USER__/$NEXUS_USER/g" "$SCRIPT_DIR/nexus_defense.sudoers" > "$SUDOERS_TMP"
/usr/sbin/visudo -cf "$SUDOERS_TMP"
install -o root -g wheel -m 440 "$SUDOERS_TMP" "$SUDOERS_DST"

/sbin/pfctl -f "$PF_CONF"
/sbin/pfctl -e 2>/dev/null || true
echo "Nexus firewall helper installed for $NEXUS_USER."
