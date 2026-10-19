# CLAUDE.md -- Skyrim-Loading-Threader

Read first: `Docs/FEASIBILITY.md` (the dialysis goal; caching/read-ahead is OUT of scope, it is the cache project's),
`Docs/LT-1-contract-map.md` (what in the serial loop is pure), `Docs/LT-2-probe-howto.md` (the probe).

## Rules
- **Engine hooks are tier-A.** Every hook, site, signature or struct offset is authored by Opus and reviewed by Opus
  before it ships (global CLAUDE.md model roles).
- **Verify every site before writing it**, per `hook-site-verification.md` in https://github.com/marthofdoom/Linux-Native-Tools: id -> RVA with the
  right Address Library file, bytes from the UNPACKED exe, register use read from the callee's own code. Record what
  was verified next to the code (`native/Sites.h`). If an id/RVA disagrees with a doc, stop on that site; do not guess.
- **Install-time guards on every hook:** runtime refusal (1.6.1170.0 only, never VR), Address Library offset check,
  E8/rel32-target or full-prologue check, all-or-nothing per group, INI kill-switch (`[General] bEnabled=0` installs
  nothing). A failed check logs and skips; it never crashes the game.
- **Passive means passive:** chain the original with every argument register forwarded, return its rax untouched,
  read fields only, call no vfunc, no allocation/lock/file I/O in a hot thunk. No co-save, no persisted state, no hotkeys.
- **Never deploy to a live play-through.** Use a dedicated test instance and ask which one.
- **No local compiler.** CI (`.github/workflows/native.yml`) is the only build; never claim code builds before a green
  run on the exact commit. Do not push, create remotes or run `gh` unless marth asks.
- ASCII only in source strings and logs. Never read vendored code, `build/` or `.git/`.
- Generic findings go back to https://github.com/marthofdoom/Linux-Native-Tools in the same session.
