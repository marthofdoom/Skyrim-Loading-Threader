# LT-2: the stage-1 timing probe, how to build, deploy and read it

Status: written 2026-10-18. **Not compiled yet.** CI is the only compiler; the first green run is the first proof
that it builds. Runtime: SkyrimSE **1.6.1170.0 only** (it refuses any other build and VR, and installs nothing).

## What it is
`LoadingThreader.dll` is a passive SKSE plugin. It measures the startup data load (`13753`, LoadFiles) once, writes a
report at `kDataLoaded`, then turns every hook into a pass-through. It changes no behaviour: each hook calls the
original with the same arguments and returns its result, reads a few `static_assert`ed `TESFile` fields, and writes
nothing to the engine, the co-save or any file except its own log.

Hooked sites (all bytes verified offline on the unpacked 1.6.1170 exe and re-verified at install, see `native/Sites.h`):

| Group | Site(s) | Technique | Measures |
|---|---|---|---|
| gate | 36553+0x341 (0x642F11) -> 13753 | call site | opens the window; LoadFiles total. Only the startup caller of 13753 |
| perPlugin | 13753+0x323, +0x343 -> 13760 | call site | wall time per plugin |
| record | 13760+0x271 (0x1BB931) -> 13763 | call site | records per plugin, compressed-flag count, dispatcher exclusive time |
| loadBody | 16 calls of 13690 inside 13763 | call site | Load bodies exclusive time |
| rawRead | 13991 entry (0x1C8640) | entry detour, 5 stolen bytes | ReadData exclusive time |
| inflate | 13991+0x1DA, 14029+0x15, 14034+0x41 -> 14032 | call site | count, bytes in/out, time, per caller path |
| postLoop | 13753+0x363 -> 13784 | call site | InitItem pass wall time |

Not hooked: the runtime callers of 13763/13760 (cell reload, save load), the 17th 13690 caller (0x306C00, outside
13763), 13767 (buffer housekeeping, lands in "LoadFiles rest"). All five LT-2 targets in the task are hooked.

## Build (CI only)
1. Commit under `native/` and push to the GitHub remote. The `native` workflow (`.github/workflows/native.yml`) runs
   on `windows-latest`; only pushes that touch `native/**` or the workflow trigger it (or `gh workflow run native`).
2. Wait for green and prove it is your commit (`Linux-Native-Tools/native-dll-via-github-actions.md`, "prove the
   green run is yours"): `headSha == git rev-parse HEAD`, `status=completed`, `conclusion=success`.
3. Download the artifact `LoadingThreader-dll` (`LoadingThreader.dll` + `.pdb`):
   `gh run download <id> -n LoadingThreader-dll -D <dir>`. Keep the PDB from the same run.

The first build is cold (about 30 min: the vcpkg cache key is new for this repo).

## Deploy (TEST instance only)
- **Never deploy into a live play-through.** Use a dedicated test instance; **ask the owner
  which one** before copying anything.
- Make a mod folder in that instance, e.g. `<instance>/mods/LoadingThreader/SKSE/Plugins/`, and copy
  `LoadingThreader.dll` and `Data/SKSE/Plugins/LoadingThreader.ini` from this repo into it. Enable the mod in MO2.
- `sha256sum` the artifact and the deployed DLL; they must match. Quit and relaunch the game executable (SKSE loads
  DLLs only at process start).
- Let the game reach the main menu (kDataLoaded). No save needs to be loaded. Copy the log before the next launch:
  it is truncated on every start.
- Log location: `<prefix>/drive_c/users/steamuser/Documents/My Games/Skyrim Special Edition/SKSE/LoadingThreader.log`
  (find it with `find ~ -iname LoadingThreader.log`). If that directory is unavailable the log goes to
  `Data/SKSE/Plugins/LoadingThreader.log`, which MO2 redirects into `<instance>/overwrite/SKSE/Plugins/`.
- To back out without removing the DLL: `bEnabled=0` in the INI (installs nothing). If a crash is suspected, try
  `bRawRead=0` first (the only entry detour).

## Reading the report
- `[install]` lines: one per group, `installed` or `NOT installed: <reason>`. A refused gate means nothing was measured.
- `load thread id`: the thread that ran the startup LoadFiles (expected: the InitTES worker, not the main thread).
- `LoadFiles (13753) total`: wall ms of the whole startup load (steady_clock), and the same in TSC ticks.
- Hook-group table: `measured` calls per group. **`UNPROVEN`** = installed but 0 calls: its zeros mean nothing.
  `foreignThread` = calls from other threads during the window (passed through, not measured). `outsideWindow` =
  calls before or after the window but before the report.
- `probe cost estimate`: measured calls x the cost of two timestamps; subtract it mentally from the shares.
- Global split (exclusive ms, so the rows sum to LoadFiles):
  - `inflate 14032`: zlib inflate of compressed records.
  - `raw read 13991 (excl)`: ReadData minus the inflate it triggers. ReadData copies subrecord bytes from the file
    buffer; disk I/O done elsewhere (framing, BSFile reads) is in the 13760 row.
  - `Load bodies 13690 (excl)`: the form-type Load functions minus nested ReadData/inflate.
  - `record dispatch 13763 ex`: LookupByID, create/reuse, ClearData/InitializeData, AddFormToDataHandler, context.
  - `per-plugin loop 13760 ex`: OpenTES, SeekNextForm/headers, group skipping, editor-ID registration (R7),
    progress, CloseTES.
  - `post-loop 13784`: the InitItem pass. `LoadFiles rest`: pass 1 (record counts), 13767, 13403, 30433.
- `SHARES`: the four numbers the task asks for (% inflate, % raw read, % Load bodies, % post-loop).
- Per-plugin tables (top N by wall, then all in load order): `wall_ms`, `records` (13763 calls), `compress` (records
  with the compressed flag), `load_ms`, `read_ms`, `infl_n`, `infl_in_B`, `infl_out_B`, `infl_ms`, plugin name.
  Slot 0 is work inside LoadFiles but outside any plugin.

## Decision rule
- **inflate share > ~15 % of LoadFiles: stage 2 (decompress-ahead worker pool + RETURN hook at 14032) is worth
  building.**
- **inflate share < ~5 %: it is not.** The simple dialysis form has nothing to draw; only LT-6 (Load bodies) remains.
- 5-15 %: grey zone; weigh it against the Load-body share and the probe cost before deciding.
The report prints this verdict on its `DECISION:` line, or `UNPROVEN` if the inflate group measured nothing.

## LT-1 open verification items (LT-1 section 7) and what this log answers
1. **How 13760's time splits** between inflate (14032), raw read (13991), Load bodies (13690) and the rest.
   **Answered**: the global split and the per-plugin table.
2. **Whether a pre-filled `+0x4A0` buffer is honoured on every path / each compressed record inflates exactly once.**
   **Partly answered**: `inflates` vs `compressed-flag` record count (equal => one inflate per compressed record),
   `entered with +0x4A0 already set` (expect 0), `same record inflated twice in a row` (expect 0), and the per-caller
   counts (which of 13991 / 14029 / 14034 actually inflate). Not answered: a non-consecutive re-inflate of the same
   record (that needs a per-record set; not cheap enough for this probe).
3. **Whether the engine's record stream matches an offline walker.** **Not answered** by this probe (it would need
   the full (file, offset, sig, formID) sequence). The per-plugin `records` count is a coarse cross-check: compare
   it against an offline walker's count of non-GRUP, non-TOFT records per plugin on the same load order.

## Known limits / reviewer notes
- If another plugin (possibly SKSE itself, for its kDataLoaded hook) has already re-pointed the gate call, the probe
  refuses to install and says so. `bAllowPatchedGate=1` chains instead (LoadFiles ms then includes the wrapper).
- If kDataLoaded arrives while LoadFiles is still running, the report is written when LoadFiles returns.
- Timing uses `rdtsc`, calibrated against steady_clock over the window (invariant TSC assumed).
