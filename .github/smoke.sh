#!/bin/sh
# Checks inside a distribution container that the released module loads with
# that distribution's libc and libpam, and that otputil runs.
set -eu
arch="$1"
so="$PWD/dist/pam_totp-$arch-linux-gnu.so"

if ldd "$so" | grep -q 'libpam.so.0 => not found'; then
    if command -v dnf >/dev/null; then dnf -y -q install pam
    elif command -v apt-get >/dev/null; then apt-get update -q && apt-get install -y -q libpam0g
    elif command -v zypper >/dev/null; then zypper -n install pam
    elif command -v pacman >/dev/null; then pacman -Sy --noconfirm pam
    fi
fi

ldd "$so"
# Preloading makes the dynamic loader resolve every symbol and symbol version
# the module needs; any complaint means it would not load under PAM either.
out=$(LD_BIND_NOW=1 LD_PRELOAD="$so" /bin/true 2>&1)
if [ -n "$out" ]; then
    echo "$out"
    exit 1
fi
# RFC 6238 test vector.
"./dist/otputil-$arch-linux-gnu" --key GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ --time 59 | grep 'current: 287082'
echo "OK on $(. /etc/os-release && echo "$PRETTY_NAME")"
