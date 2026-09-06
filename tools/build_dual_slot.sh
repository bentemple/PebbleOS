#!/usr/bin/env bash
#
# Build a dual-slot PebbleOS firmware bundle.
#
# The firmware is linked for a specific flash slot (CONFIG_FIRMWARE_SLOT), so a
# dual-slot board needs the tree built twice and the two bundles merged into one
# archive holding slot0/ and slot1/ folders. This mirrors what
# .github/workflows/build-firmware.yml does across its matrix, in one command.
#
# The merged bundle is the one to install. Gadgetbridge picks the manifest for
# the watch's *inactive* slot out of those folders, so handing it a bare
# _slot0.pbz leaves it nothing to choose between.
#
# Usage:
#   tools/build_dual_slot.sh --board obelix@pvt
#   tools/build_dual_slot.sh --board getafix@dvt2 --debug --outdir /tmp/fw
#   tools/build_dual_slot.sh --board obelix@pvt -- -DCONFIG_SERVICE_SECURITY_LOCK=n
#
# Anything after `--` is passed through to `pbl configure`, which forwards
# unrecognised arguments to CMake.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BUILD_DIR="$REPO_ROOT/build"

# Boards that set CONFIG_PBLBOOT, and so have two firmware slots. Kept as a list
# rather than read from the defconfig because the board argument may carry a
# revision suffix (obelix@pvt) that the defconfig path does not.
DUAL_SLOT_BOARDS="obelix getafix"

BOARD=""
OUTDIR=""
RELEASE=y
PASSTHROUGH=()

die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
note() { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --board) BOARD="${2:-}"; shift 2 ;;
    --board=*) BOARD="${1#*=}"; shift ;;
    --outdir) OUTDIR="${2:-}"; shift 2 ;;
    --outdir=*) OUTDIR="${1#*=}"; shift ;;
    # Release is the default deliberately. A debug build compiles in the
    # security lock's console test hooks and logs at INFO over UART, both of
    # which cost real battery -- not what you want on a watch you are wearing.
    --debug) RELEASE=n; shift ;;
    --release) RELEASE=y; shift ;;
    --) shift; PASSTHROUGH=("$@"); break ;;
    -h|--help) sed -n '3,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (use -- to pass flags to pbl configure)" ;;
  esac
done

[[ -n "$BOARD" ]] || die "--board is required, e.g. obelix@pvt, getafix@dvt2"

# pbl is installed from requirements.txt, not run out of the checkout.
command -v pbl >/dev/null || \
  die "pbl is not on PATH -- activate the virtualenv it was installed into
       (pip install -r requirements.txt)."

BOARD_BASE="${BOARD%%@*}"
# The bundle names its file after the normalised board, same as CI does.
BOARD_NAME="${BOARD//@/_}"

IS_DUAL_SLOT=0
for b in $DUAL_SLOT_BOARDS; do
  [[ "$BOARD_BASE" == "$b" ]] && IS_DUAL_SLOT=1
done

[[ -d "boards/$BOARD_BASE" ]] || die "no such board: $BOARD_BASE (see boards/)"

# pbl applies build/menuconfig.conf on top of the defconfig, which would happily
# override the slot we are asking for and leave both images linked for the same
# one -- a bundle that looks right and bricks the update.
if [[ -f "$BUILD_DIR/menuconfig.conf" ]]; then
  die "$BUILD_DIR/menuconfig.conf exists and would override CONFIG_FIRMWARE_SLOT.
       Move it aside before building both slots."
fi

# The version string the bundle is named after comes from `git describe`, so a
# tree that changes between the two builds produces two differently-named
# bundles that cannot be merged. Record HEAD now and check it again at the end.
HEAD_SHA="$(git rev-parse HEAD)"
HEAD_SHORT="$(git rev-parse --short HEAD)"

DIRTY=no
if ! git diff-index --quiet --ignore-submodules=dirty HEAD --; then
  DIRTY=yes
fi

# The same rule as tools/gitinfo.py get_git_revision(), which is what the build
# names the bundle after: `git describe`, plus -dirty when the tree has changes,
# and a fixed placeholder when there is no tag to describe from (which does not
# get the suffix). Reproduced here only to know which file to pick up
# afterwards; collect_bundle() falls back to globbing if this ever drifts.
if DESCRIBE="$(git describe 2>/dev/null)"; then
  [[ "$DIRTY" == yes ]] && DESCRIBE="${DESCRIBE}-dirty"
else
  DESCRIBE="v9.9.9-dev"
fi
[[ "$DIRTY" == yes ]] && warn "working tree is dirty; version is ${DESCRIBE}"

if [[ -z "$OUTDIR" ]]; then
  OUTDIR="$REPO_ROOT/dist/${BOARD_NAME}-${DESCRIBE}"
  [[ "$DIRTY" == yes ]] && OUTDIR="${OUTDIR}-dirty"
fi
mkdir -p "$OUTDIR"

note "board      $BOARD"
note "head       $HEAD_SHORT ($DESCRIBE${DIRTY:+, dirty=$DIRTY})"
note "release    $RELEASE"
note "outdir     $OUTDIR"
note "dual slot  $([[ $IS_DUAL_SLOT == 1 ]] && echo yes || echo 'no, single slot board')"

# Collect the bundle a slot build just produced.
#
# Globbed rather than predicted: the version string is built from `git describe`
# inside the build, and reproducing that here would be a second implementation
# of the same rule, free to drift from it. Ambiguity is an error rather than a
# newest-wins guess, because picking the wrong one silently flashes a firmware
# that is not the tree you are looking at.
collect_bundle() {
  local slot="$1" pattern matches expected suffix=""
  [[ $IS_DUAL_SLOT == 1 ]] && suffix="_slot${slot}"

  # The name we expect, which also skips over bundles an earlier build of a
  # different version left in build/ -- those are not stale enough to delete on
  # the user's behalf, but they must not be mistaken for this build's output.
  expected="$BUILD_DIR/normal_${BOARD_NAME}_${DESCRIBE}${suffix}.pbz"
  if [[ -f "$expected" ]]; then
    printf '%s' "$expected"
    return
  fi

  pattern="$BUILD_DIR/normal_${BOARD_NAME}_"*"${suffix}.pbz"
  mapfile -t matches < <(compgen -G "$pattern" || true)
  [[ ${#matches[@]} -gt 0 ]] || die "no bundle matched $pattern -- did pbl bundle run?"
  if [[ ${#matches[@]} -gt 1 ]]; then
    printf '  %s\n' "${matches[@]}" >&2
    die "several bundles match $pattern; stale builds from another version are
       in $BUILD_DIR. Remove them, or point --outdir at a clean tree."
  fi
  printf '%s' "${matches[0]}"
}

build_slot() {
  local slot="$1" configure_args=()
  configure_args=(--board "$BOARD")
  [[ $IS_DUAL_SLOT == 1 ]] && configure_args+=("-DCONFIG_FIRMWARE_SLOT=${slot}")
  [[ "$RELEASE" == y ]] && configure_args+=("-DCONFIG_RELEASE=y")
  configure_args+=("${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}")

  note "configuring slot ${slot}"
  pbl configure "${configure_args[@]}"

  # Belt and braces: read the slot back out of the configuration that was
  # actually generated, rather than trusting that our -D reached Kconfig.
  if [[ $IS_DUAL_SLOT == 1 ]]; then
    local configured
    configured="$(sed -n 's/^CONFIG_FIRMWARE_SLOT=\([01]\)$/\1/p' "$BUILD_DIR/.config" || true)"
    [[ "$configured" == "$slot" ]] || \
      die "asked for slot ${slot} but the build configured slot '${configured:-unset}'"
  fi

  note "building slot ${slot}"
  pbl build
  pbl bundle
}

SLOTS=(0 1)
[[ $IS_DUAL_SLOT == 1 ]] || SLOTS=(0)

declare -a BUNDLES=()
for slot in "${SLOTS[@]}"; do
  build_slot "$slot"
  src="$(collect_bundle "$slot")"
  cp "$src" "$OUTDIR/"
  BUNDLES+=("$OUTDIR/$(basename "$src")")
  note "slot ${slot} bundle -> $(basename "$src")"

  # Symbols and the log-hash dictionary are per slot and are what makes a
  # coredump from this build readable later. Cheap to keep, impossible to
  # reconstruct once the build directory is reconfigured for the other slot.
  suffix=""
  [[ $IS_DUAL_SLOT == 1 ]] && suffix="_slot${slot}"
  for artifact in pebbleos.elf pebbleos.bin pebbleos.hex pebbleos_loghash_dict.json; do
    [[ -f "$BUILD_DIR/$artifact" ]] || continue
    ext="${artifact##*.}"
    base="${artifact%.*}"
    cp "$BUILD_DIR/$artifact" "$OUTDIR/${base}${suffix}.${ext}"
  done
done

[[ "$(git rev-parse HEAD)" == "$HEAD_SHA" ]] || \
  die "HEAD moved during the build; the two slot images are from different trees"

OUTPUT="$OUTDIR/normal_${BOARD_NAME}_${DESCRIBE}.pbz"

if [[ $IS_DUAL_SLOT == 1 ]]; then
  # Both bundles have to carry the same version, or the two slots would hold
  # different firmware and an update would flip the watch between them.
  v0="$(basename "${BUNDLES[0]}")"; v0="${v0#normal_${BOARD_NAME}_}"; v0="${v0%_slot0.pbz}"
  v1="$(basename "${BUNDLES[1]}")"; v1="${v1#normal_${BOARD_NAME}_}"; v1="${v1%_slot1.pbz}"
  [[ "$v0" == "$v1" ]] || die "slot0 is $v0 but slot1 is $v1 -- rebuild from a stable tree"

  OUTPUT="$OUTDIR/normal_${BOARD_NAME}_${v0}.pbz"
  note "merging slots"
  python3 tools/merge_pbz.py \
    --slot0-pbz "${BUNDLES[0]}" \
    --slot1-pbz "${BUNDLES[1]}" \
    --output "$OUTPUT"
else
  OUTPUT="${BUNDLES[0]}"
fi

# What was in the tree at build time, which the filename alone does not say:
# the full sha, whether it was dirty, and the switches that change the
# firmware's behaviour rather than just its version.
cat > "$OUTDIR/buildinfo.txt" <<EOF
board:      $BOARD
commit:     $HEAD_SHA
describe:   $DESCRIBE
dirty:      $DIRTY
release:    $RELEASE
dual_slot:  $([[ $IS_DUAL_SLOT == 1 ]] && echo yes || echo no)
extra:      ${PASSTHROUGH[*]+${PASSTHROUGH[*]}}
built:      $(date -u +%Y-%m-%dT%H:%M:%SZ)
branch:     $(git rev-parse --abbrev-ref HEAD)
EOF

note "done"
printf '\ninstall this one:\n  %s\n\n' "$OUTPUT"
if [[ "$DIRTY" == yes ]]; then
  warn "built from a dirty tree -- this bundle is not reproducible from $HEAD_SHORT alone"
fi
