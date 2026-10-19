# Skyrim-Loading-Threader: feasibility (SkyrimSE 1.6.1170.0)

Date: 2026-10-13. Scope: can an SKSE DLL take over Skyrim SE's loading and remove its single-thread block?
For each loading phase, what is it worth?

> **CORRECTION (marth, 2026-10-13) - READ FIRST.** The first version of this document was written for the wrong goal and
> leaned toward caching/read-ahead. Caching and read-ahead are out of scope: they belong to marth's separate cache
> project. The goal here is the **"dialysis machine"**: draw work out of the engine's serial loop, process it in
> parallel off-thread, and return results in the ORIGINAL serial order through a reorder buffer, so commit order (and
> therefore load-order winner semantics) never changes. The middle is a generic ordered-parallel pipeline; only the two
> connectors (draw, return) are Skyrim-specific. Surgically replacing the receiving side is in scope where the engine's
> consumer cannot accept an ordered commit.
>
> What this changes below: (1) every "read-ahead / prefetch pool" seam and milestone is **superseded** (kept struck-through
> in place for the record); (2) the Phase A "NO for parallel parse" verdict assumed the engine's consumer stays as is, and is
> **reopened**: the deciding question is whether the work inside the serial loop (13760 and the record loop) is **pure**
> (bytes in, result out, no hidden writes to the form table or singletons). That is task LT-1 and is **not yet answered**.
> (3) The structural facts, addresses, thread-model findings and [V]/[I] labels are unaffected. Plan: ClickUp folder
> "Loading Threader", tasks LT-0 to LT-6.

Method: offline only. Inputs were `binaries/1.6.1170/SkyrimSE.unpacked.exe` (build 1.6.1170.0), the Address Library
`versionlib-1-6-1170-0.bin` (self-check id 38048 = 0x6A35F0 passed), CommonLibSSE-NG ids (`_commonlib/live-alandtse-ng`,
the AE column of `RELOCATION_ID`/`VariantID`), capstone disassembly, RTTI/vtable xref scans, and .pdata function bounds.
Nothing ran in-game, so no timings were measured. The scratch scripts are in the session scratchpad and are not kept.

Labels: **[V]** = verified in the 1.6.1170 disassembly in this pass. **[I]** = inferred (from naming, structure, CommonLib,
or memory); not checked byte-for-byte. All RVAs are image-relative (base 0x140000000). "id" means AE Address Library id.

---

## Phase A: startup data load (InitTES / TESDataHandler file load, ending in kDataLoaded)

### What the engine does
| Step | id | RVA | Status |
|---|---|---|---|
| `Main` init (id 36548) builds an `InitTESThread` (vtable id 207137 @0x18966A8; `lea` of the vtable @0x641579) and starts it through `BSThread::Create` | 36548 | 0x641190 | [V] |
| The main thread then sits in a `Sleep` + `PeekMessageA/TranslateMessage/DispatchMessageA` loop (0x6415A2-0x64162B) until the worker finishes, then tears it down (`68260` @0x641635) | - | 0x6415A2 | [V] |
| `InitTESThread` vtable slot 1 (ThreadProc) @0x64C5A0 makes one call, to the init body | 36553 | 0x642BD0 | [V] |
| The init body (36553) also builds the IOManager (`13279` @0x1999E0 is called at 0x642CD8, and `IOManager::ctor` 0xE01330 is called only from 13279) | 13279 | 0x1999E0 | [V] |
| Shaped like `TESDataHandler::LoadFiles`: reached from 36553 and calls `TESFile::OpenTES` (13931). The name is [I]; the structure is [V] | 13753 | 0x1B96E0 | [V] structure / [I] name |
| - pass 1: for every file, `OpenTES` adds a record count into the progress-total global (id 400469 @0x20FBA4C) | | 0x1B9910-0x1B9987 | [V] |
| - pass 2: a **serial** for-each-file loop (0x1B99D0-0x1B9A0E) calls the per-file loader 13760 once per plugin | 13760 | 0x1BB6C0 | [V] |
| - after the loop: 13767, 13784 (post-load passes, likely form init/link; [I]), then 13403 and 30433 | | 0x1B9A2D-0x1B9A71 | [V] calls / [I] meaning |
| The per-file loader 13760 runs `OpenTES`, a record loop over `TESFile::SeekNextForm` (13979 @0x1C7D30), `TESForm::LookupByID` (14667 @0x1E1640) for each record (override detection), a virtual call `[vtbl+0x190]` on the form object (probably the form's Load/merge; [I]), and `CloseTES` (13933) | 13760 | 0x1BB6C0 | [V] calls / [I] semantics |
| Global form map `allForms` (id 400507 @0x20FBB88), guarded by `BSReadWriteLock allFormsMapLock` (id 400517 @0x20FC018) | | | addresses [V via lib]; lock use inside 14667 [I] |
| `kDataLoaded`: SKSE sends it after this init finishes. The exact SKSE hook site was **not** located here | | | [I] |

### Thread model
- [V] **One worker thread does the entire data load, serially.** The main thread only pumps window messages. There is no
  fan-out in 13753 or 13760: no task submission and no job-list call appears in either call list.
- [V] Engine threads are all created by `BSThread::Create` (id 68261 @0xCC9F10, which calls `CreateThread`,
  `SetThreadPriority`, `ResumeThread`). That makes it a single choke point for enumerating every engine thread.
- [V] INI knobs exist that touch this phase: `bLoadEsmInMemory:Archive`, `sEsmToLoadInMemoryList:Archive`,
  `bEnableFileCaching:General`, `sEssentialFileCacheList`. What the engine does with them was not traced ([I]).

### Proposed seams
1. **Timing probe** (passive): hook the call at 0x1B9A03 (the 13760 call inside the file loop), and the 13753 call site in 36553
   (0x642F11). Time each plugin, and split the time into OpenTES/IO, the record loop, and the post-load passes (13767/13784).
2. ~~**I/O prefetch**~~ **SUPERSEDED (caching territory, out of scope).**
3. **Draw/return split = the dialysis design (THE seam):** DRAW the pure per-record/per-plugin work out of the loop in
   13760 onto workers; RETURN results through a reorder buffer into one serial commit in load order. Needs the record loop
   in 13760 and the form factory/Load virtual (`[vtbl+0x190]`) reversed to separate the pure part from the part that writes
   engine state. **Not reversed yet; this is LT-1.** If parsing is pure and only creation/commit touches `allForms`,
   the design is small. If Load virtuals mutate singletons mid-parse, those steps stay on the commit side.
4. Optimize `LookupByID` (14667), which runs once per record: this is already done by Engine Fixes `FormCaching` (see prior art).

### Parallelism hazards (A)
- **Load order is semantic.** The last plugin to touch a record wins, and override detection needs `LookupByID` to see every
  earlier plugin's forms. Truly parallel form creation across plugins would break override resolution.
- **allForms / allFormsMapLock** is one global RW lock. Concurrent writers would serialize on it or corrupt the map.
  Engine Fixes FormCaching already wraps lookups, so a second layer must cooperate with it.
- **FormID resolution:** master-index remapping (ESL/ESM/ESP compile indices) is per-file state on `TESFile` and the
  data handler. Form Load virtuals also resolve references to other FormIDs; some resolve right away, some in the later
  InitItem/link pass (13767/13784). [I]
- **The Load virtuals are not thread-safe.** They write global singletons (default objects, string tables, condition
  lists, BSFixedString pool, MemoryManager pools) [I].
- `TESFile` keeps a shared read cursor and buffer per file. Worker threads must use their own handles and never share
  `TESFile` state.
- Wine/Proton plus the MO2 VFS: file-open cost per plugin may dominate on Linux. The probe has to separate open, read
  and parse time.

### Verdict (A): PARTLY. LT-1 answered on 2026-10-18; details in `LT-1-contract-map.md`
- **Corrections to the table above (LT-1):** id 14667 is `TESForm::AddCompileIndex`, not LookupByID. [V] The per-record
  lookup is **14617 @0x1E01A0 = `TESForm::LookupByID`** (read lock on 400517) [V]. `[vtbl+0x190]` is slot 0x32
  `GetFormEditorID`, used for editor-ID map registration (write lock 400518, map 400509), not Load [V]. The per-record
  body is **13763 @0x1BBAA0**. It calls `Load` (slot 6) through 13690 @0x1B11F0 [V].
- **Yes:** a passive per-plugin profiler (M0). It shows how the 2m20s splits between open/read, parse and commit, which is
  **unknown until M0** and sets how much the dialysis design can win.
- **The serial loop is not pure (LT-1) [V].** Each form type's Load reads subrecords straight off the engine's TESFile
  cursor while it writes the form. Before the first subrecord it registers the form in `allForms` (`SetFormID`, write
  lock) and appends the file to the form's source list (`SetFile`). Some Loads keep parse state in globals (TESNPC → 401439),
  touch SkyrimVM (VMAD), and build BSFixedStrings. CELL/WRLD/DIAL children depend on context globals 400461/400462/401555.
  Override detection (LookupByID) and `AddFormToDataHandler` order are load-order dependent.
- **Pure part [V]:** record framing, header FormID remap (a function of the file's masters and compile indices only) and
  zlib inflate of compressed records (14032).
- **Viable now (simple dialysis):** DRAW = workers inflate compressed records ahead, in load order. RETURN = hook 14032
  @0x1C9790 (the engine inflates only when `file+0x4A0` is null, 0x1C9C49) to hand over the pre-inflated buffer. All of
  13763, editor-ID registration and 13767/13784 stay serial and unchanged, so commit order is preserved by construction.
  The gain is capped by the inflate share of 13760's time, which is **unknown until M0/LT-2** [I: possibly modest].
- **Hard (LT-6 class):** parallel subrecord decode. This needs replacement Load functions per form type, because the
  engine's Load is not reentrant. Do not start before M0 shows that Load-body CPU dominates.
- **13784 must stay after the loop** [V calls / I semantics]. It runs `InitItemImpl` over every `formArrays[type]`.
  13767 is only per-file buffer-size housekeeping [V].
- The identity oracle still applies: the final `allForms` content must match the serial loader's, form by form, on the same load order.
- ~~I/O read-ahead/prefetch pool~~ superseded (cache project).

---

## Phase B: save-game load

### What the engine does
| Item | id | RVA | Status |
|---|---|---|---|
| `BGSSaveLoadManager::LoadMostRecentSaveGame` | 35766 | 0x612300 | address [V via lib], body not traced |
| `BGSSaveLoadManager::Thread` vtable | 206620 | 0x188D0F0 | [V] |
| ... created in 35720 (0x60F140, called from 35722) | 35720 | 0x60F140 | [V] |
| ... ThreadProc slot 1 = 35790 (0x617550): it waits on an object (`WaitForSingleObjectEx`), then dispatches a virtual job and 35794 | 35790 | 0x617550 | [V] calls / [I] purpose: likely async save-file read/write |
| Change-form application, Papyrus VM state restore (`VMInitThread` RTTI exists; `bBackgroundLoadVMData:General`), and cell/actor 3D load through the IOManager (phase C) | | | [I] |

### Thread model
- [I] A dedicated save-load thread does the file IO. Change-form application and the VM restore are serial on the
  main/loading path, and the cell load then goes through phase C's IOManager.

### Seam and hazards
- Probe: hook 35766 and the generic load entry, and timestamp the boundary between save-file read and decompress,
  change-form apply, VM restore, and first-frame cell ready.
- Hazards: change forms must be applied in order. RefHandles, the Papyrus VM and actor processes are all global and
  single-threaded. Save corruption is permanent and hits the user's saves, which is worse than a crash.

### Verdict (B): NO for the parse/apply core (low ROI, highest blast radius). PARTLY for overlapping the save-file read
with cell prefetch. On large lists the time is probably dominated by phase-C cell/actor loading and the VM, not the save
parse ([I]; M0 must confirm).

---

## Phase C: in-game cell/exterior streaming and load screens

### What the engine does
| Item | id | RVA | Status |
|---|---|---|---|
| `IOManager` vtable | 238133 | 0x19CDBE8 | [V] |
| `IOManager*` singleton | 411121 | 0x3275DF0 | [V via lib] |
| `IOManager::ctor` 0xE01330 calls `BSTaskManager::ctor` (75630 @0xDFD410) with edx=0x10, **r8d=1**, r9d=0x18 | 75630 | 0xDFD410 | [V] |
| `BSTaskManager::ctor` loops `i < [this+0xA8]` creating `BSTaskManagerThread` objects (vtable 238121 @0x19CD7C0), each with a `CreateSemaphoreA` and a `CreateEventA`, named `"BSTaskManager"` (string @0x19CD808), via `BSThread::Create` | | 0xDFD5A4-0xDFD68B | [V] |
| Thread count = r8d = **1** for the IOManager | | | [I], strongly suggested (esi=r8d, loop bound at +0xA8) |
| `QueuedFile` vtable (IO task unit) | 238140 | 0x19CDDB0 | [V] |
| Other workers present (RTTI [V]): `BSJobs::JobThread`, `JobListManager::ServingThread`, `BackgroundProcessThread`, `BSResource::ArchiveManager`, `AsyncArchiveStream`, Havok `hkCpuJobThreadPool`, `ImageCreationThread` | | | [V] presence, roles [I] |
| INI controls [V strings]: `bUseBackgroundFileLoader`, `bBackgroundCellLoads`, `bUseMultiThreadedFaceGen`, `bUseMultiThreadedTrees`, `iPostProcessMilliseconds`, `iPostProcessMillisecondsLoadingQueuedPriority`, `iNumHWThreads`, `iMaxJobThreads`, `bForceAsync:Archive`, `bLoadArchiveInMemory`, `sArchiveToLoadInMemoryList`, `uExterior Cell Buffer`, `uInterior Cell Buffer`, `iPreloadSizeLimit` | | | [V] strings / [I] effect |

### Thread model
- [V/I] Streaming is **already asynchronous**. One IOManager worker thread runs a 16-way priority task queue (edx=0x10 [I]).
  Finished tasks are **post-processed on the main thread** within a per-frame millisecond budget
  (`iPostProcessMilliseconds*`). During a load screen, progress therefore depends on how often the main thread
  ticks, which is why loading-screen FPS limits change load times.

### Seams
1. Probe: hook the `QueuedFile` vtable process slots and the IOManager post-process to measure queue depth, worker busy
   time, and main-thread post-process time.
2. More IO workers: patch the r8d=1 argument in `IOManager::ctor` (0xE01354, `lea r8d,[rdx-0xF]`), or add a
   read-ahead/decompress pool under `BSResource` archive streams. **Hazard:** QueuedFile tasks may assume a single
   worker (ordering, shared `BSResource` stream state, NIF/Havok loaders not reentrant). Unverified.
3. Main-thread post-process budget: already tunable by INI (`iPostProcessMillisecondsLoadingQueuedPriority`) and by
   SSE Display Tweaks' loading-screen FPS. No DLL is needed for the first experiment.

### Hazards (C)
BSA archive handles and `BSResource` streams are shared. NIF/texture/Havok object construction is not documented as
reentrant. The main-thread attach of 3D to the scene graph cannot be moved off the main thread. A raised IO thread count
could cause rare, non-deterministic crashes that are hard to tell apart from mod crashes.

### Verdict (C): PARTLY (unchanged facts; reframed 2026-10-13)
The engine already overlaps IO with play. INI/FPS tuning is prior art. Read-ahead pools are out of scope (cache project).
Applying the dialysis pattern to the IOManager (more workers drawing queued tasks, main-thread post-process as the ordered
return) is a possible LATER extension and stays medium-to-high risk until the NIF/Havok/BSResource reentrancy
question is answered. Phase A comes first.

---

## Prior art (from memory unless marked; do not rebuild these)
- **SSE Engine Fixes** (installed in Tuxborn; `EngineFixes.toml` read [V]): `FormCaching` (cache in front of the
  global form table, which speeds up LookupByID, used per record in phase A), `TreeLODReferenceCaching`, `MaxStdio=8192`
  (more file handles for large plugin counts), `DisableChargenPrecache` (Precache Killer), `ScaleformAllocator`, plus
  memory-manager replacement (part 2 / TBB).
- **SSE Display Tweaks** (installed [V]): `LoadingScreenFramerateLimit` and the `LoadingScreenLimitExtraTime*` options
  uncap or limit FPS during load screens, which changes how fast main-thread post-processing drains (phase B/C).
- **Skyrim Priority SE AE** (installed [V]): process and thread priority / CPU affinity tuning.
- **powerofthree's Tweaks, Scrambled Bugs, Bug Fixes SSE** (installed): correctness fixes, not loading speed.
- **Load Game CTD Fix:** fixes a crash during save load, not speed.
- "Better Loading Screens" and similar: I do not have reliable knowledge that any of them changes the loader's threading.
  Treat them as cosmetic until checked.
- Vanilla INI: `bLoadEsmInMemory` / `sEsmToLoadInMemoryList` and `bLoadArchiveInMemory` / `sArchiveToLoadInMemoryList`
  already read files into RAM up front. This is the zero-code experiment for "is phase A IO-bound?".
- As far as I know, **no public mod parallelizes the phase-A plugin parse.** That is the open niche, and also the hardest
  and most dangerous part. The pipeline machinery itself (ordered-parallel work with a reorder buffer) is generic and
  solved elsewhere; choose an existing library in LT-4 instead of writing one. Plugin PARSERS in other tools (xEdit,
  Mutagen, esplugin, libespm, OpenMW) are not drop-in: none builds the game's in-memory TESForm objects.

---

## Recommended milestones
- **M0: passive timing probe** (no behavior change). Hook `BSThread::Create` (68261) to log every engine thread (name,
  priority). Wrap 13753, each 13760 call (0x1B9A03 site), 13767/13784, `OpenTES`, the IOManager queue and the save-load
  entry. Output per-plugin ms, a split of IO time (open/read) vs CPU time, and a load-screen timeline. Run it on the
  4000-plugin list. **Every later milestone depends on this data.**
- **LT-1 (first, cheapest stop point):** contract map of the serial loop: which steps are pure, which write engine state.
- ~~M1 zero-code INI tests, M2 phase A read-ahead pool, M3 phase C archive read-ahead~~ **superseded** (cache project).
- **Dialysis build (LT-4 design, LT-5 connectors, LT-6 receiving-side rework only if needed):** generic ordered-parallel
  pipeline + draw and return connectors, INI kill-switch to the engine's original path. Proceed only with the diff harness
  that compares the final `allForms` state, form by form, against a serial load of the same load order.
- Later, same pattern: phase C IOManager (draw = queued tasks, return = main-thread post-process).
- Phase B core: do not attempt.

## Not verified (honest gaps)
- The function names of 13753 (LoadFiles), 13767, 13784, 36553 and the `[vtbl+0x190]` virtual are structural guesses.
- The IOManager thread count = 1 is inferred from the ctor argument; it was not observed at runtime.
- The kDataLoaded dispatch site, the save-load call chain past 35766, and what `BGSSaveLoadManager::Thread` actually does.
- Whether `LookupByID` (14667) takes `allFormsMapLock` on this build, and how Engine Fixes' FormCaching hook interacts with it.
- Whether the INI knobs (`bLoadEsmInMemory`, `bUseBackgroundFileLoader`, ...) are still honored in 1.6.1170.
- There is no timing data at all. The 2m20s split between IO and CPU is unknown.
