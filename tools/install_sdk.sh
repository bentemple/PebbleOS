#!/usr/bin/env bash
#
# Install the firmware build's exported SDK beside the released Pebble SDKs, so
# `pebble build --sdk <name>` links against the firmware you just built.
#
# `pbl build sdk` fills in build/sdk/, but pebble-tool only ever looks in
# ~/.pebble-sdk/SDKs. The firmware build exports the single platform its board
# was configured for, so a standalone install there would break every other
# target platform: this overlays that one platform onto a copy of a released
# SDK and symlinks the rest back to the release.
#
# The failure this exists to prevent is a silent one. include/ and lib/ are
# real copies, so they go stale the moment the firmware is rebuilt, while the
# manifest keeps the same version and `pebble sdk list` keeps showing it. An
# app then links yesterday's libpebble.a, whose trampolines carry hardcoded
# indices into g_pbl_system_tbl, and calls whatever now sits at that index --
# or off the end of the table. It compiles without complaint and crashes at
# the call, which the watch reports as "<app> is not responding".
#
# Usage:
#   tools/install_sdk.sh
#   tools/install_sdk.sh --name 4.36-preview
#   tools/install_sdk.sh --no-export          # reuse the existing build/sdk
#   tools/install_sdk.sh --from ~/.pebble-sdk/SDKs/4.3
#
# Then, in an app project:
#   pebble build --sdk <name>

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BUILD_SDK="$REPO_ROOT/build/sdk"
SDK_ROOT="${PEBBLE_SDK_ROOT_DIR:-$HOME/.pebble-sdk/SDKs}"
#! Written into every install this script makes. Its presence is what says the
#! directory is ours to delete from; a released SDK has no such file and is
#! never touched without --force.
MARKER=".pebbleos-local-sdk"

NAME="local"
FROM=""
EXPORT=y
FORCE=n

die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
note() { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) NAME="${2:-}"; shift 2 ;;
    --name=*) NAME="${1#*=}"; shift ;;
    --from) FROM="${2:-}"; shift 2 ;;
    --from=*) FROM="${1#*=}"; shift ;;
    --sdk-root) SDK_ROOT="${2:-}"; shift 2 ;;
    --sdk-root=*) SDK_ROOT="${1#*=}"; shift ;;
    --no-export) EXPORT=n; shift ;;
    --force) FORCE=y; shift ;;
    -h|--help) sed -n '3,28p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -n "$NAME" ]] || die "--name cannot be empty"
[[ "$NAME" != */* ]] || die "--name is a directory name, not a path: $NAME"

if [[ "$EXPORT" == y ]]; then
  command -v pbl >/dev/null || \
    die "pbl is not on PATH -- activate the virtualenv it was installed into
       (pip install -r requirements.txt), or pass --no-export."
  note "exporting the SDK"
  pbl build sdk
fi

[[ -d "$BUILD_SDK" ]] || \
  die "$BUILD_SDK does not exist. Configure and build a board first, then
       run this without --no-export."

# The firmware build exports exactly one platform, named after the board's
# CONFIG_PLATFORM_*. Read it back rather than asking for it, so this cannot
# disagree with what was actually built.
#
# Recognised by what a platform holds rather than by name: build/sdk also
# collects `common`, and running the bundled waf from there leaves its
# unpacked .waf3-* library alongside them.
PLATFORMS=()
for d in "$BUILD_SDK"/*/; do
  d="${d%/}"
  [[ -f "$d/include/pebble.h" && -f "$d/lib/libpebble.a" ]] || continue
  PLATFORMS+=("$(basename "$d")")
done
[[ ${#PLATFORMS[@]} -gt 0 ]] || \
  die "no platform under $BUILD_SDK holds include/pebble.h and lib/libpebble.a
       -- did 'pbl build sdk' run?"
[[ ${#PLATFORMS[@]} -eq 1 ]] || {
  printf '  %s\n' "${PLATFORMS[@]}" >&2
  die "several platforms under $BUILD_SDK; expected exactly one."
}
PLATFORM="${PLATFORMS[0]}"

TARGET="$SDK_ROOT/$NAME"

# Checked before anything else looks at the filesystem: refuse to delete from a
# directory this script did not create, because overlaying onto a real release
# would destroy the platform every other project builds against.
if [[ -d "$TARGET" && ! -f "$TARGET/$MARKER" ]]; then
  [[ "$FORCE" == y ]] || \
    die "$TARGET exists but was not created by this script.
       It may be a released SDK. Move it aside, pick another --name, or pass
       --force if you are sure."
  warn "overwriting $TARGET, which this script did not create"
fi

# A released SDK to borrow the toolchain, node modules and the other platforms
# from. Newest by name, which is how the releases sort, and never one of ours.
if [[ -z "$FROM" ]]; then
  [[ -d "$SDK_ROOT" ]] || \
    die "$SDK_ROOT does not exist. Install a released SDK with pebble-tool
       first -- this overlays one platform onto a copy of it."
  for candidate in $(ls -1 "$SDK_ROOT" 2>/dev/null | sort -Vr); do
    [[ "$candidate" == "$NAME" ]] && continue
    [[ -f "$SDK_ROOT/$candidate/$MARKER" ]] && continue
    [[ -f "$SDK_ROOT/$candidate/sdk-core/manifest.json" ]] || continue
    FROM="$SDK_ROOT/$candidate"
    break
  done
  [[ -n "$FROM" ]] || \
    die "no released SDK found under $SDK_ROOT to overlay onto.
       Install one with pebble-tool, or point --from at it."
fi

[[ -f "$FROM/sdk-core/manifest.json" ]] || \
  die "$FROM does not look like an SDK install (no sdk-core/manifest.json)."
[[ ! -f "$FROM/$MARKER" ]] || \
  die "--from points at an install this script made ($FROM).
       Overlay onto a released SDK, not onto another overlay."

DESCRIBE="$(git describe 2>/dev/null || echo unknown)"
COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

note "platform   $PLATFORM"
note "from       $FROM"
note "target     $TARGET"
note "firmware   $DESCRIBE"

# Redone on every run rather than only at creation, so an install made by an
# older version of this script -- or one the release has since grown a file in
# -- is repaired by running it again instead of having to be deleted first.
note "linking the release's half"
mkdir -p "$TARGET/sdk-core/pebble"

# Everything that is not the platform comes from the release: the toolchain
# and node modules the app build runs, and the manifest that names it.
for item in .venv node_modules toolchain; do
  [[ -e "$FROM/$item" ]] && ln -sfn "$FROM/$item" "$TARGET/$item"
done
for item in "$FROM"/package*.json; do
  [[ -e "$item" ]] && ln -sfn "$item" "$TARGET/"
done
for item in package.json requirements.txt use_requirements.json; do
  [[ -e "$FROM/sdk-core/$item" ]] && ln -sfn "$FROM/sdk-core/$item" "$TARGET/sdk-core/"
done

# The version pebble-tool lists and `--sdk` selects.
sed "s/\"version\": .*/\"version\": \"${NAME}\",/" \
    "$FROM/sdk-core/manifest.json" > "$TARGET/sdk-core/manifest.json"

# Everything beside our platform keeps coming from the release: the other
# platforms, which is what a PBL_API_EXISTS()-guarded feature wants, and the
# entries that are not platforms at all -- `common`, and the `waf` the app
# build actually runs, which is a file rather than a directory.
for p in "$FROM"/sdk-core/pebble/*; do
  [[ -e "$p" ]] || continue
  [[ "$(basename "$p")" == "$PLATFORM" ]] && continue
  ln -sfn "$p" "$TARGET/sdk-core/pebble/"
done

DEST="$TARGET/sdk-core/pebble/$PLATFORM"
mkdir -p "$DEST"

# Replace rather than copy over: `cp -r` onto an existing directory merges, so
# a header or a symbol dropped from the export would linger here and keep
# compiling against something the firmware no longer has.
note "refreshing include/ and lib/"
rm -rf "$DEST/include" "$DEST/lib"
cp -r "$BUILD_SDK/$PLATFORM/include" "$BUILD_SDK/$PLATFORM/lib" "$DEST/"

# QEMU comes from the release; the firmware build does not export one.
if [[ ! -e "$DEST/qemu" && -e "$FROM/sdk-core/pebble/$PLATFORM/qemu" ]]; then
  ln -sfn "$FROM/sdk-core/pebble/$PLATFORM/qemu" "$DEST/qemu"
fi

cat > "$TARGET/$MARKER" <<EOF
# Written by tools/install_sdk.sh. Its presence marks this install as a local
# overlay that the script may delete from.
platform:   $PLATFORM
commit:     $COMMIT
describe:   $DESCRIBE
from:       $FROM
installed:  $(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

# libpebble.a is the file that carries the trampolines, so this comparison is
# the one that says the app will link against the firmware that was just built.
cmp -s "$BUILD_SDK/$PLATFORM/lib/libpebble.a" "$DEST/lib/libpebble.a" || \
  die "libpebble.a did not land: $DEST/lib/libpebble.a differs from the export."
cmp -s "$BUILD_SDK/$PLATFORM/include/pebble.h" "$DEST/include/pebble.h" || \
  die "pebble.h did not land: $DEST/include/pebble.h differs from the export."

# pebble-tool needs more than the platform: it runs the `waf` beside it and
# reads `common`. Anything the release has here and we do not is missing, and
# the symptom is only "SDK unavailable; can't run this command."
MISSING=()
for p in "$FROM"/sdk-core/pebble/*; do
  entry="$(basename "$p")"
  [[ -e "$TARGET/sdk-core/pebble/$entry" ]] || MISSING+=("$entry")
done
[[ ${#MISSING[@]} -eq 0 ]] || {
  printf '  %s\n' "${MISSING[@]}" >&2
  die "the install is missing entries the release has under sdk-core/pebble."
}

note "verified against the export"
printf '\nbuild an app against it with:\n  pebble build --sdk %s\n\n' "$NAME"
warn "re-run this after every firmware rebuild; the copies above go stale
         silently, and an app linked against a stale one crashes at the call."
