# Manual lockdown arms a countdown instead of erasing

## Checkpoints
<!-- Resumable state for kraken agent -->
**Task:** Manual triggers lock and arm the Erase After countdown; Erase After
defaults to Never; a manual countdown must survive a reconnect and must not be
rescheduled by a disconnect.
**Started:** 2026-08-25
**Last Updated:** 2026-08-25

### Phase Status
- Phase 1 (Tests written, red): VALIDATED — compile failure first, then each
  hazard guard mutated in turn and the right tests went red
- Phase 2 (Implementation): VALIDATED — 33/35
- Phase 3 (clang-format): VALIDATED — git-clang-format clean except
  prompt_commands.h, whose command table is pre-existingly unformatted and
  which would otherwise be reflowed in full
- Phase 4 (Docs): VALIDATED — trigger matrix, state machine, menu table,
  §7 deadline section, §8 protocol section, risks list
- Phase 5 (Live QEMU proof): VALIDATED — countdown survives
  `security session 0` then `security session 1`, and later expires reporting
  "manual panic"

### Validation State
```json
{
  "tests_passing": 33,
  "tests_total": 35,
  "known_failures": ["test_health_db", "test_weather_db"],
  "last_test_command": "./waf test -M '.*/tests/.*(security_lock|settings_security|pin_entry|system_apps/lockdown/|sha256|test_pfs|flash_api|notification|blob_db).*'",
  "last_test_exit_code": 0
}
```

### Environment left behind
- Build configured for `qemu_emery`, normal variant,
  `--relax_toolchain_restrictions`.
- One QEMU instance, one `pebble_harness.py serve`.
- Watch: armed, PIN 1234, Lock After 5 min, Erase After Never. Its flash was
  reset by the reconfigure, so it is a fresh record on the new default.
- `--variant=prf` does NOT link, at HEAD as well as here
  (`lock.c: dangerous relocation` in `security_lock_ui_quiesce`). Pre-existing.
