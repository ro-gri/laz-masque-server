#!/usr/bin/env sh
# Test release URL resolution and verified archive selection without host changes.
set -eu
cd "$(dirname "$0")/.."
TEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/masque-bootstrap-test.XXXXXX")
trap 'rm -rf -- "$TEST_TMP"' EXIT
trap 'exit 1' HUP INT TERM
export TEST_TMP
mkdir -p "$TEST_TMP/bin" "$TEST_TMP/fixtures"
cat >"$TEST_TMP/bin/id" <<'MOCK'
#!/bin/sh
echo 0
MOCK
cat >"$TEST_TMP/bin/uname" <<'MOCK'
#!/bin/sh
case "$1" in -s) echo Linux ;; -m) echo x86_64 ;; *) exit 1 ;; esac
MOCK
cat >"$TEST_TMP/bin/curl" <<'MOCK'
#!/bin/sh
set -eu
output=
url=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) output=$2; shift 2 ;;
        *) url=$1; shift ;;
    esac
done
case "$url" in
    */releases/latest) printf '%s\n' "${FAKE_LATEST_URL:?}" ;;
    https://github.com/ro-gri/laz-masque-server/releases/download/v0.1.0+masque.0.15.0/*)
        cp "$TEST_TMP/fixtures/${url##*/}" "$output" ;;
    *) echo "unexpected download URL" >&2; exit 1 ;;
esac
MOCK
chmod +x "$TEST_TMP/bin/"*
root=laz-masque-server-v0.1.0+masque.0.15.0-linux-x86_64
mkdir -p "$TEST_TMP/$root"
cat >"$TEST_TMP/$root/install.sh" <<'MOCK'
#!/bin/sh
printf '%s\n' "${MASQUE_START_SERVICE:?}" >"$TEST_TMP/installed"
MOCK
chmod +x "$TEST_TMP/$root/install.sh"
tar -C "$TEST_TMP" -czf "$TEST_TMP/fixtures/$root.tar.gz" "$root"
(cd "$TEST_TMP/fixtures" && sha256sum "$root.tar.gz" >"$root.tar.gz.sha256")
export PATH="$TEST_TMP/bin:$PATH"
for pin in '0.1.0+masque.0.15.0' 'v0.1.0+masque.0.15.0'; do
    MASQUE_VERSION=$pin sh install-latest.sh >"$TEST_TMP/install.log"
    [ "$(cat "$TEST_TMP/installed")" = 1 ]
done
for plus in '+' '%2B' '%2b'; do
    MASQUE_VERSION='' FAKE_LATEST_URL="https://github.com/ro-gri/laz-masque-server/releases/tag/v0.1.0${plus}masque.0.15.0" \
        sh install-latest.sh >"$TEST_TMP/latest.log"
    [ "$(cat "$TEST_TMP/installed")" = 1 ]
done
for invalid in 'v0.1.0+' 'v0.1.0+masque..1' 'v0.1.0+masque/1' 'v0.1.0+masque%2F1' 'v0.1.0+masque.0.15.0
extra'; do
    if MASQUE_VERSION=$invalid sh install-latest.sh >"$TEST_TMP/invalid.log" 2>&1; then
        echo "invalid version accepted: $invalid" >&2; exit 1
    fi
    grep -q 'invalid release tag' "$TEST_TMP/invalid.log"
done
rm "$TEST_TMP/installed"
printf '%s\n' tampered >>"$TEST_TMP/fixtures/$root.tar.gz"
if MASQUE_VERSION=v0.1.0+masque.0.15.0 sh install-latest.sh >"$TEST_TMP/tampered.log" 2>&1; then
    echo 'tampered archive accepted' >&2; exit 1
fi
[ ! -e "$TEST_TMP/installed" ]
grep -q 'SHA-256 verification failed' "$TEST_TMP/tampered.log"
echo 'server bootstrap metadata, latest redirects and checksum checks passed'
