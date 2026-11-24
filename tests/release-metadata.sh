#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

die() {
    echo "release metadata test: $*" >&2
    exit 1
}

TEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/masque-release-metadata.XXXXXX")
MANIFEST=$TEST_TMP/Cargo.toml
LOCKFILE=$TEST_TMP/Cargo.lock
CHANGELOG=$TEST_TMP/CHANGELOG.md
VALIDATOR=$PWD/scripts/validate-release.sh

cleanup() {
    rm -rf -- "$TEST_TMP"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

write_manifest() {
    version=$1
    cat >"$MANIFEST" <<EOF
[workspace]
members = ["."]

[package]
name = "laz-masque-server"
version = "$version"
EOF
}

write_lockfile() {
    version=$1
    cat >"$LOCKFILE" <<EOF
version = 4

[[package]]
name = "laz-masque-server"
version = "$version"
EOF
}

write_changelog() {
    version=$1
    date=$2
    cat >"$CHANGELOG" <<EOF
# Changelog

## Unreleased

## $version - $date

### Fixed

- Fixture.
EOF
}

validate() {
    MASQUE_RELEASE_MANIFEST=$MANIFEST \
        MASQUE_RELEASE_LOCK=$LOCKFILE \
        MASQUE_RELEASE_CHANGELOG=$CHANGELOG \
        "$VALIDATOR" "$1"
}

expect_failure() {
    label=$1
    shift
    if "$@" >"$TEST_TMP/failure.log" 2>&1; then
        die "$label unexpectedly passed"
    fi
}

write_manifest 0.5.1+masque.0.15.0
write_lockfile 0.5.1+masque.0.15.0
write_changelog 0.5.1+masque.0.15.0 2026-08-21
validate v0.5.1+masque.0.15.0 >/dev/null || die "matching release metadata was rejected"

expect_failure "mismatched tag" validate v0.5.0+masque.0.15.0

write_manifest 0.5.2+masque.0.15.0
expect_failure "mismatched manifest" validate v0.5.1+masque.0.15.0
write_manifest 0.5.1+masque.0.15.0

write_lockfile 0.5.0+masque.0.15.0
expect_failure "mismatched lockfile" validate v0.5.1+masque.0.15.0
write_lockfile 0.5.1+masque.0.15.0

write_changelog 0.5.1+masque.0.15.0 not-a-date
expect_failure "malformed changelog date" validate v0.5.1+masque.0.15.0

cat >"$CHANGELOG" <<'EOF'
# Changelog

## 0.5.1+masque.0.15.0 - 2026-08-21

## Unreleased
EOF
expect_failure "release before Unreleased" validate v0.5.1+masque.0.15.0

cat >"$CHANGELOG" <<'EOF'
# Changelog

## Unreleased

## 0.5.1+masque.0.15.0 - 2026-08-21

## 0.5.1+masque.0.15.0 - 2026-08-22
EOF
expect_failure "duplicate release heading" validate v0.5.1+masque.0.15.0

# Reject invalid schemes even when all metadata files agree.
for invalid in '0.1.0' '0.1.0+other.0.15.0' '0.1.0+masque.01.15.0' '0.1.0-01+masque.0.15.0' '0.1.0+masque.0.15.0/extra' '0.1.0+masque.0.15.0
extra'; do
    write_manifest "$invalid"
    write_lockfile "$invalid"
    write_changelog "$invalid" 2026-11-25
    expect_failure "invalid release scheme $invalid" validate "v$invalid"
done
write_manifest 0.1.0-rc.1+masque.0.15.0
write_lockfile 0.1.0-rc.1+masque.0.15.0
write_changelog 0.1.0-rc.1+masque.0.15.0 2026-11-25
validate v0.1.0-rc.1+masque.0.15.0 >/dev/null

echo "release metadata validation passed"
