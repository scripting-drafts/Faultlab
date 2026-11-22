#!/usr/bin/env bash
# Install a per-user crash collector for machines where the system unit has not
# been installed yet.  No root is required.  Use --disable before switching to
# the system-wide service.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
conf=${FAULTLAB_CONF:-/etc/faultlab/config}

show_help() {
    cat <<EOF
usage: ./install-user.sh [--dir PATH] [--disable]

  --dir PATH   crash store (default: \$HOME/faultlab-crashes)
  --disable    stop and remove the user service
EOF
}

crash_dir=${FAULTLAB_CRASH_DIR:-$HOME/faultlab-crashes}
action=install
while [[ $# -gt 0 ]]; do
    case $1 in
    --dir) crash_dir=${2:?missing value}; shift 2 ;;
    --disable) action=disable; shift ;;
    -h | --help) show_help; exit 0 ;;
    *) echo "install-user.sh: unknown argument: $1" >&2; show_help >&2; exit 2 ;;
    esac
done

unit_dir=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user
unit=$unit_dir/faultlab-crashd.service
dropin_dir=$unit_dir/faultlab-crashd.service.d

if [[ $action == disable ]]; then
    systemctl --user disable --now faultlab-crashd.service 2>/dev/null || true
    rm -f "$unit"
    rm -rf "$dropin_dir"
    systemctl --user daemon-reload
    echo "removed user faultlab-crashd service"
    exit 0
fi

if [[ $EUID -eq 0 ]]; then
    echo "install-user.sh: run as your normal user, not root" >&2
    exit 1
fi
if systemctl is-active --quiet faultlab-crashd.service 2>/dev/null; then
    echo "install-user.sh: system faultlab-crashd is already active" >&2
    echo "use 'sudo faultlab-crashes status' instead" >&2
    exit 1
fi
if [[ ! -x $here/bin/faultlab-crashd ]]; then
    echo "install-user.sh: $here/bin/faultlab-crashd is missing" >&2
    exit 1
fi

safe=""
if [[ -r $conf ]]; then
    # shellcheck disable=SC1090
    . "$conf"
    if [[ -n ${SAFE_CPUS:-} ]]; then
        safe=${SAFE_CPUS//,/ }
    fi
fi

install -d -m 0700 "$crash_dir"
install -d -m 0755 "$unit_dir"
python3 - "$here/systemd/faultlab-crashd.user.service.in" "$unit" \
    "$here/bin/faultlab-crashd" "$crash_dir" <<'PY'
import sys
from pathlib import Path
template, target, exec_path, crash_dir = sys.argv[1:5]
text = Path(template).read_text()
text = text.replace("@EXEC@", exec_path).replace("@CRASH_DIR@", crash_dir)
Path(target).write_text(text)
PY
chmod 0644 "$unit"

rm -rf "$dropin_dir"
if [[ -n $safe ]]; then
    install -d -m 0755 "$dropin_dir"
    cat >"$dropin_dir/50-faultlab-cpus.conf" <<EOF
[Service]
CPUAffinity=$safe
EOF
    chmod 0644 "$dropin_dir/50-faultlab-cpus.conf"
fi

systemctl --user daemon-reload
systemctl --user enable --now faultlab-crashd.service
systemctl --user restart faultlab-crashd.service
if [[ ! -d $HOME/.local/bin ]]; then
    install -d -m 0755 "$HOME/.local/bin"
fi
ln -sfn "$here/bin/faultlab-crashes" "$HOME/.local/bin/faultlab-crashes"

echo "installed user faultlab-crashd.service"
echo "crash store: $crash_dir"
echo "inspect:     faultlab-crashes status"
if [[ -d /var/log/faultlab/crashes ]] && [[ ! -w /var/log/faultlab/crashes ]]; then
    echo "system store exists; use 'sudo faultlab-crashes list' for those incidents"
fi
