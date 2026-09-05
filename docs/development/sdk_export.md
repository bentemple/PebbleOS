# Exposing functions to the SDK

Third-party apps do not link against the firmware directly: the app SDK is
generated from the firmware sources at build time. When you expose a new
function to apps (i.e. anything declared in an `applib/` header that user apps
can call), three things must change together — the firmware build alone will
not surface it to apps:

1. **Implement the applib wrapper and syscall** — add the function to the
   appropriate `src/fw/applib/.../<area>.c/.h`, declare the `sys_*` syscall in
   `src/fw/syscall/syscall.h`, and define it with `DEFINE_SYSCALL` (from
   `src/fw/syscall/syscall_internal.h`), either in the matching
   `src/fw/syscall/<area>_syscalls.c` or alongside the implementation it
   wraps.

   Not every export needs a new syscall. Anything built on the event service
   — the `*_service_subscribe()` family — rides the existing
   `sys_event_service_client_subscribe`, and the event service creates its
   entry lazily on first subscribe, so no registration is needed either.
2. **Register the symbol** in
   `tools/generate_native_sdk/exported_symbols.json` under the matching
   group, with an `addedRevision` matching the new SDK revision, **and bump
   the file's own top-level `"revision"` field to match**. Both. If
   `addedRevision` is greater than the file's `revision`, the generator logs
   a warning and **silently omits your symbol** — the build succeeds, the
   firmware compiles, and the function simply is not in the SDK. The warning
   is easy to miss among the pre-existing ones.
3. **Bump the SDK revision** in
   `src/fw/process_management/pebble_process_info.h`: increment
   `PROCESS_INFO_CURRENT_SDK_VERSION_MINOR` and add a comment line above the
   `#define` following the existing pattern, e.g. `// sdk.major:0x5
.minor:0x66 -- <description> (rev 105)`. The `rev` number in the comment
   must match `addedRevision` from step 2.

Forgetting steps 2 or 3 means the function compiles into the firmware but is
invisible to the app SDK build, so third-party apps can't link against it.

```{warning}
It is **not** possible to add publicly exposed functions to an already
released firmware/SDK combination. The generated `pebble.auto.c`
function-pointer table must be compiled into the firmware the SDK targets:
an app built against a newer SDK calls a trampoline that indexes past the
end of an older firmware's table and crashes. New exports always ship as a
new firmware plus a new SDK build.
```

## How the SDK generator works

The generator (`tools/generate_native_sdk/generate_pebble_native_sdk_files.py`)
runs automatically as part of the firmware build (normal variant only — PRF
and test builds skip it). It exports the white-listed functions, `typedef`s
and `#define`s from the firmware tree and produces the files needed to build
native watchapps, all under `build/`:

- `build/sdk/<platform>/include/pebble.h` — typedefs, defines and function
  prototypes for apps (plus `pebble_worker.h` for background workers and a
  few version/fonts headers)
- `build/sdk/<platform>/lib/libpebble.a` — static library containing
  trampolines that call the exported functions in flash
- `build/src/fw/pebble.auto.c` — `g_pbl_system_tbl`, the table of function
  pointers the trampolines use to find an exported function's address;
  compiled into the firmware image

The rest of the distribution is packaged by the firmware build's `sdk`
target, which fills in the same `build/sdk/` tree:

```shell
pbl configure --board $BOARD
pbl build sdk
```

`tools/cmake/sdk.py` copies the common files from `sdk/` into
`build/sdk/common/` — the app project templates under `sdk/defaults/`, and
the tools and resource pipeline the app build shares with the firmware —
and bundles `sdk/waftools/` into the `waf` binary app developers use to
build their apps. That waf is the only one left in the tree: everything it
needs lives under `sdk/`, and it is built out of tree, so packaging leaves
the checkout untouched.

## `exported_symbols.json` format

```json
{
  "revision": "<exported symbols revision number>",
  "version": "x.x",
  "files": ["<files to parse>"],
  "exports": ["<symbols to export>"]
}
```

Each exported symbol has a `type` of `function`, `define`, `type`,
`forward_struct`, or `group`:

```json
{
  "type": "function",
  "name": "<symbol name>",
  "sortName": "<sort order>",
  "addedRevision": "<revision number>"
}
```

A `group` nests further `exports` under a `name`. Functions support
additional flags (`internal`, `removed`, `deprecated`, `appOnly`,
`workerOnly`, `implName`, `skipDefinition`) — see existing entries and
`tools/generate_native_sdk/exports.py` for their meaning.

Notes:

- Functions are sorted by `addedRevision`, then alphabetically (by `sortName`
  if present, else `name`) within a revision. This ordering is the ABI — it
  is why new functions must use a new revision: it guarantees new firmware
  stays backwards compatible with apps compiled against an older
  `libpebble.a`.
- `types` are emitted in the order listed; put typedefs after the typedefs
  they depend on (`includeAfter` is the escape hatch for ordering
  exceptions).
- The generator errors out on exports it cannot find in the parsed headers,
  but an `addedRevision` newer than the file's `revision` only warns, and the
  symbol is dropped. It also does not verify that the resulting `pebble.h`
  compiles — review its output.
- Platforms frozen at an older revision (`FROZEN_AT_REVISION`, set per
  platform in `tools/pebble_sdk_platform.py`) turn a too-new function into a
  stub define — basalt gets
  `#define your_function(...) (0)`. That is the answer for a capability the
  older platforms do not have: apps compile everywhere without an `#ifdef`,
  so an export does not need guarding for their sake.
- The comment ledger above `PROCESS_INFO_CURRENT_SDK_VERSION_MINOR` is the
  only mapping between SDK revisions and version minors: no formula relates
  them (the minor once jumped `0x19` → `0x20` between revs 35 and 36, and a
  few minors and revs are skipped or doubled up). Treat the ledger as
  append-only history.

## Verifying the export actually landed

Since the whole point is that a clean firmware build proves nothing, check
the generated output rather than the compile:

```bash
grep -c '<your_function>' build/src/fw/pebble.auto.c build/sdk/<platform>/include/pebble.h
```

Both must be non-zero. A useful negative control: before registering the
symbol, `arm-none-eabi-nm build/pebbleos.elf | grep <your_function>` will not
find it at all — `--gc-sections` drops it, because nothing references it
until `pebble.auto.c` does.

Two further checks worth doing for anything ABI-visible:

- Diff the function-pointer table against the previous build and confirm your
  entries are **appended** with no reordering of existing ones. That ordering
  is the ABI.
- `generate_shim_files()` (in
  `tools/generate_native_sdk/generate_pebble_native_sdk_files.py`) runs the
  real generator against a given symbol file into an output directory of your
  choice, for any platform — so you can check platforms other than your
  configured board, and test a change to `exported_symbols.json` against a
  copy before touching the real one.

  It parses the firmware headers with libclang, so it needs an `autoconf.h`
  to resolve `CONFIG_*` macros, and an absolute `pbl_src_dir` (it derives the
  repo root from it). Point it at a configured build directory, and run it
  from the repo root:

  ```python
  import os, sys
  sys.path[:0] = ["tools/generate_native_sdk", "tools"]
  from generate_pebble_native_sdk_files import generate_shim_files

  out, build = "/tmp/sdkcheck", "build"  # any configured build dir
  for d in ("include", "lib", "src/fw"):
      os.makedirs(f"{out}/{d}", exist_ok=True)
  generate_shim_files("tools/generate_native_sdk/exported_symbols.json",
                      os.path.abspath("src"), f"{out}/src", f"{out}/include",
                      f"{out}/lib", "basalt", internal_sdk_build=False,
                      autoconf=os.path.abspath(f"{build}/autoconf.h"))
  ```

  `tools/build_sdk.py` wraps the same call but passes no `autoconf`, so its
  CLI (`python tools/build_sdk.py basalt`) fails in `parse_c_decl.py` on the
  first `CONFIG_*` macro it meets. Its `--output-dir` also defaults to
  `build/sdk`, which overwrites the real SDK tree — always pass one.
