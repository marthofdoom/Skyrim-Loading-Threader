# LT-1b: the post-loop InitItem pass (13784) and the LoadFiles remainder (SkyrimSE 1.6.1170.0)

Date: 2026-10-18. Offline only (capstone + pefile on `binaries/1.6.1170/SkyrimSE.unpacked.exe`, AE Address Library,
CommonLibSSE-NG `live-alandtse-ng` for vtable ids, class names and the FormType enum).
Labels: **[V]** = seen in the 1.6.1170 disassembly in this pass. **[I]** = inferred (from names, structure, or engine
knowledge). RVAs are image-relative (base 0x140000000). "id" = AE Address Library id. Field numbers come from
`LT-2-results-first-run.md` (3499 plugins, 117.3 s LoadFiles, InitItem pass 40.6 s, remainder 20.8 s).

## Summary
- **13784 is a fixed sequence of about 10 phases** [V]. The big one is a plain loop over `formArrays[0..0x89]` that
  calls `InitItemImpl` (vtable slot 0x13, `[vtbl+0x98]`) on every form. It has no progress or UI updates.
  References (REFR/ACHR) are **not** in `formArrays`. They are initialized later, cell by cell, inside the WRLD phase and
  the interior-cell phase [V for the call structure, I for "this is where the persistent refs go"].
- **Most InitItem overrides are "resolve my own FormID fields into pointers" bodies** [V]: `GetFile` (14621) →
  `AddCompileIndex` (14667) → `LookupByID` (14617, read lock on `allForms`) → `RTDynamicCast` → store the pointer in
  the form's own field → set `kInitialized` (14637). These are form-local writes plus a locked read. Running them in
  parallel within one form type is plausible.
- **There are four hazard classes** [V]:
  1. **On-demand recursive init.** WEAP→template WEAP, ARMO→template ARMO, anything→SOUN (33043), SMQN→parent node,
     DIAL→branch, CELL→refs, WRLD→children. Each uses a non-atomic check-then-run on `kInitialized`.
  2. **Unsynchronized global containers.** INFO inserts into global hash maps and walks a global list. NPC_ pushes onto
     a global linked list.
  3. **Heavy reference, cell and navmesh bodies** (REFR/ACHR/CELL/WRLD/NAVM/NAVI). They touch dozens of globals, take
     write locks and cell spinlocks, and create forms.
  4. **A benign error-path global** (400487).
- **Verdict:** split by form type, run each type's forms in parallel with a **barrier between types**, and keep the
  current order of the phases. That is viable for the resolve-only types. INFO and NPC_ need a lock around their
  global-container calls. The ref/cell/navmesh phases stay serial. **How much of the 40.6 s that frees is not known**:
  the ref phases may be the largest part, and they stay serial. One more probe run settles it (section 7).
- **The minimal seam is two addresses**: EXFIL = a 5-byte `jmp` at **0x1BE1CB** (replace the type loop), and
  JOIN = **0x1BE236** (resume at the AVIF loop). No ordered commit is needed for resolve-only types.
- **The 17.8 % remainder** contains two I/O-bound per-plugin loops: **pass-1 `OpenTES` over all 3499 files** and the
  **per-plugin BSA auto-load (13786)**. It also contains the **navmesh-graph build 30433**. The other items are constant
  or trivial (13767 is 6 instructions per master; 13403 is a lazy allocation). The probe has to say which of the three
  dominates. Pass 1 is the leading suspect [I].

## A. Structure of 13784 @0x1BE0F0 (`rcx` = TESDataHandler, kept in `rbp`; `r14` = 0 for the whole function)
Array layout [V]: `formArrays[t]` is a `BSTArray` at `dh + 0x10 + t*0x18` (data +0, size +0x10). For example
FLST 0x5B is at +0x898, NPC_ 0x2B at +0x418, RACE 0x0E at +0x160 and WRLD 0x47 at +0x6B8.

| # | Phase | Code | What it calls per item | Status |
|---|---|---|---|---|
| P0 | `BGSDefaultObjectManager::GetSingleton()` (13894) → `InitItemImpl` | 0x1BE111-0x1BE11C | DOBJ InitItem (20770) | [V] |
| P1 | **FLST array first** (`formArrays[0x5B]`) | loop 0x1BE140-0x1BE16F, call **0x1BE165** `FF 90 98 00 00 00` | BGSListForm InitItem 20905 (resolve only) | [V] |
| P2 | Calendar singleton (400447) created if null (36289); 18779 / DOBJ+0x100 fix-up; `IOManager(411121)` 75708(…, 5) | 0x1BE171-0x1BE1C6 | — | [V] calls / [I] purpose of 75708 |
| **P3** | **Main loop: `for t in 0..0x89, t ∉ {0x13 SCPT, 0x47 WRLD, 0x5B FLST}: for form in formArrays[t]: form->InitItemImpl()`** | head 0x1BE1D0, call **0x1BE221** `FF 90 98 00 00 00`, `inc sil` 0x1BE22D, exit 0x1BE236 | slot 0x13 of each class | [V] |
| P4 | ActorValueInfo: `for i in 0..0xA3: 27202(i)->InitItemImpl()` | 0x1BE240-0x1BE25B | AVIF InitItem 27250 | [V] |
| P5 | NPC_ post pass: `npc->actorData(+0x30)->vfunc[4](0)` then **24787(npc)** for every NPC_ | 0x1BE270-0x1BE2B1 | 24787 (61 instructions, 6 calls) | [V] |
| P6 | RACE post pass: **25362(race)** for every RACE | 0x1BE2C6-0x1BE2EA | 25362 (268 instructions) | [V] |
| P7 | `TES(403450)` → 13403 = lazily created NavMeshInfoMap (TES+0x2B0, 0xF0 bytes, ctor 30376) → `InitItemImpl` (30380) | 0x1BE2EC-0x1BE30F | NAVI InitItem | [V] / [I] class name from ctor and slot |
| **P8** | **WRLD array**: `InitItemImpl` (20455) on every worldspace. WRLD then calls InitItem on its children/persistent cell (20563, `[+0x98]` at 0x30CE4C) | 0x1BE330-0x1BE35F, call **0x1BE355** | WRLD → CELL → **REFR/ACHR InitItem** | [V] calls / [I] "persistent exterior refs init here" |
| P9 | 20544; then **interior cells** `dh->interiorCells` (NiTPrimitiveArray at +0xD08, data +0xD10, count u16 +0xD1A): **18882(cell, visitor)**, which walks the cell's refs under the cell spinlock and calls `ref->InitItemImpl` (0x2B35A2, 0x2B365C) | 0x1BE361-0x1BE3C0, call **0x1BE3B5** | CELL body → REFR/ACHR InitItem | [V] |
| P10 | 24591(400451), 20683(401131), 11160, 24527; sort the RACE array (13796 with comparator 13791); `400461 = 0` (current CELL) | 0x1BE3E5-0x1BE426 | — | [V] |

Loop details (P3) [V]:
- The counter is `sil`, a byte from 0 to 0x89. There is no early exit apart from the three skipped types.
- **The end pointer is recomputed from `[rdi+0x10]`/`[rdi+0x20]` on every iteration**. If an InitItem appends to the
  array being walked, the serial loop also visits the new forms. A parallel dispatcher must snapshot the array and
  re-check its size at the barrier.
- The loop has no side effects of its own (no progress counter, no UI, no TLS write).

Other facts:
- Each InitItemImpl except a few starts with `if (formFlags & 8 /*kInitialized*/) return;` and ends with 14637(dl=1),
  which sets bit 3 with a plain read-modify-write on `+0x10` [V]. NAVI, CELL, SMBN and ACHR do not test the flag at
  entry, so "run it twice" is not safe for every type [V].
- 13784 has a second caller, **0x1BEFEB in 13785**, the runtime path. Any hook must be gated on the 13753 call at
  0x1B9A43 (the LT-2 probe already gates there) [V].
- `formArrays[REFR..PHZD]` get no entries from load: `AddFormToDataHandler` (13693) attaches REFR and the projectiles
  to their parent cell (19411), not to `formArrays` (jump table at 0x1B187C/0x1B189C) [V]. CELL goes to
  `interiorCells` (interior only), REGN to `regionList`, WRLD and PACK to their own arrays, and the rest to
  `formArrays[type]` [V]. **So the P3 iterations over REFR/ACHR/CELL are empty or nearly empty** [I]. Ref and cell
  init happens in P8/P9.

## B. InitItemImpl overrides (slot 0x13) by type
Method: for each FormType class, take the primary vtable from CommonLib `VTABLE_<class>`[0] (AE id), resolve it with
the Address Library, read slot 0x13, follow the chained `.pdata` chunks, and measure the function. "Reach" is the set of
distinct functions within 3 direct-call levels and the instructions in them, a rough indicator of weight.
Recursion means a virtual `[+0x98]` call on another form.

### B1. Trivial or no-op (P3 cost is only the virtual call)
`ret` (13879): NONE, KYWD, AACT, TXST, MICN, GLOB, CLAS, EYES, CLMT, LAND, DEBR, IMGS, IMAD, VTYP, WOOP, ASTP,
MATO, CLFM, REVB [V]. MSTT returns `al=1` (10915). LCRT and SPGD only set `kInitialized`. SCPT is skipped by the loop [V].

### B2. Resolve-only. Writes are form-local, plus the locked `allForms` read, allocation and BSFixedString
Reads: their own raw FormID fields, the source-file list (14621), `allForms` under `allFormsMapLock` (read).
Writes: their own pointer fields and `formFlags`. Some allocate (MemoryManager 68115) or build BSFixedStrings. On a
failed cast only, they call `19995` / `14145`-family, which toggles the **global reentrancy byte 400487** around
`GetFormEditorID` for the warning text. That is a data race in the error path only: harmless at the logic level, but
not data-race-free.

| Types (own instructions / reach instructions) | Recursion | Notes |
|---|---|---|
| FLST 20905 (94/301), PERK 23814 (55/587), MGEF 11058 (417/1037), LVLI 17553 / LVSP 17574 (18/1014), LVLN 17530 (21/1273), COBJ 16914 (57/759), OTFT 17111 (90), ALCH 10830 (56/776), INGR 11227, ENCH 11177, SPEL 11483 (51/816), SCRL 11448, BOOK 17833, MISC/APPA/KEYM/SLGM 17991 (30/659), STAT 18019, ACTI 17696, TACT 17182, FLOR 17368, FURN 17394, AMMO 17235, LIGH 17602, DOOR 17917, CONT 17885, ARMA 17758, HDPT 23629, IDLM 23673, NOTE 23749, HAZD 17025, PROJ 17131, EXPL 16980, IPCT 20838, IPDS 20859, MATT 20967, FACT 24494 (241/1188), AVIF 27250, DLBR 23520, SNDR 21250, SOUN 23393, LSCR 21831, RELA 24069, EQUP 23604, MOVT 23725, COLL 20727, … | MGEF, ALCH, BOOK, MISC, CONT → **SOUN** via 33043 (`LookupByID`; if SOUN and not initialized → `InitItemImpl`, return its descriptor) [V] | SOUN (0x0F) comes before all of these in P3, so with per-type barriers the recursion is always a no-op [I, from the type order] |
| **WEAP 18075** (329/3305), **ARMO 17791** (189/2564) | **WEAP→WEAP template (+0x208, CNAM)**, **ARMO→ARMO template (+0x220)**: `if (!(tmpl->flags & 8)) tmpl->InitItemImpl()` [V] (0x2859F8, 0x279061); also → SOUN | **Recursion within the same type.** Two workers can start the same template at once. The check-then-run is not atomic, and InitItem rewrites FormID fields into pointers in place, so a second run would misread pointers as IDs. **Needs a per-form atomic claim or serial pre-init of the templates** |
| QUST 24972 (322/2384), SCEN 24116 (215/1695) | none seen | Both reach 32346, which writes **402507** [V write / I meaning]. Mostly resolve. Classify as "global write, unknown" until it is probed |
| DIAL 25518 (95/1841) | **DIAL→form at +0x40** (`[+0x98]` at 0x3E6E3A; [I] the DLBR branch or the quest) | cross-type recursion into DLBR (0x73, a later type): racy if two DIALs share a branch |
| SMQN 32452 (330/2586), SMBN 32396, SMEN 32410 | **SMQN→parent `BGSStoryManagerNodeBase` (+0x30)** (0x52E78C) | recursion into the same or another SM node type (0x70/0x72) |
| PACK 29548 (241/4104), LCTN 18354 (320/809) | — | take a **write lock** through 12325/12326 (global table 400622 under BSReadWriteLock **400621**) [V] → lock-protected writes. PACK also writes 400619/400620 under that lock [V] |
| RACE 25303 (521/7153) | — | BSFixedString-heavy (69161/69164/69167). Writes only its own fields and the allocator statics [V]. RACE also has P6 and the P10 sort |

### B3. Global-container mutators (must be serialized or locked)
| Type | Global state written | Where | Class |
|---|---|---|---|
| **INFO 25598** (375 own / 5169 reach) | (a) **global BSTHashMaps 369960 and 369965**: lookup keyed by the INFO (0x3EAEBB, 0x3EAFB6), then insert/erase through **25668 / 25669** with plain `inc` of the size counters 369962/369967 [V]; (b) walks the **global list 401560** and calls 25492 for each node (0x3EAF7A) [V]; (c) 25611 → global maps 369986/369987 (0x3EABE5) [V]; (d) on the error path, 25608 → 25626 **duplicates the TESFile, seeks and re-reads the record** for a diagnostic string, using a **one-entry global cache 401559/401560** [V]; (e) 11436: a thread-safe static (MSVC `_Init_thread_header`) that creates one dummy form via the TESForm ctor 14593, which does a **non-atomic `++400506`** [V] | call sites 0x3EAF64 (25668), 0x3EB064 (25669), 0x3EABE5 (25611), 0x3EAF96 (25492) | **global/singleton, unsynchronized** → serialize these calls with a lock: an INFO-local mutex around these call sites, or run INFO serially |
| **NPC_ 24719** (546 own / 6306 reach) | (a) if `actorData.flags` bit 2 [I: chargen-preset flag]: **push onto the global singly linked list 401428/401429** (inline, 0x3BA4F5-0x3BA561, not a call) [V]; (b) 24765 lazily clamps cached settings 369714/369719 (idempotent; a benign race) and 24804 writes 401400 [V]; (c) resolves template, race, class, factions and so on (resolve-only) [V calls] | inline | **global list, unsynchronized; list order = push order** → needs a lock **and** an ordered commit if preset order matters [I] |
| DOBJ 20770 | 401152/401153 | P0 (called once) | serial anyway |

### B4. Heavy reference, cell, world and navmesh bodies (stay serial)
| Type | Size | What it touches [V unless marked] |
|---|---|---|
| **REFR 19507** (also PMIS..PBAR) | 628 own instructions, **reach 358 functions / 27.5k instructions, 332 indirect calls** | 36 distinct globals (e.g. 400305, 400503 via **the form factory 13765/14587 → creates forms**, 401070, 401105, 401680-401682, 403767/403768, 403799/403800, 406616-406623, 410113/410114), the TES singleton (403450), write lock 68234, and the 411226 counter |
| **ACHR 37791** | reach 254 / 16k | calls REFR InitItem plus 24682/38019/41343/41433 (actor process and inventory [I]); write locks; 27 globals |
| PHZD 43960 | reach 228 / 14k | REFR InitItem + hazard setup |
| **CELL 18881 → 18882** | reach 91 / 7.3k | cell spinlock (`lock cmpxchg [cell+4]`), NiPointer refcounts, **ref->InitItemImpl for every ref in the cell**, 19283, 400305/400308, 401005-401007, 401039/401040 |
| WRLD 20455 | 292 / 2.9k | resolves parent/climate/water/music/encounter zone/location (resolve-only part), then **13 worldspace globals 402323-402340**, 402263, and child-cell init (20563) |
| NAVM 30336, NAVI 30380 | reach 86-87 / 5-7k | TES singleton, write locks, 402040, 400506/400512 (TESForm ctor), 13403 |

## C. Verdict on parallelizing InitItem
**Ordering dependencies between forms:**
- **Between types, the order is deliberate** [V by the code order, I by intent]: DOBJ → FLST (P1, before every other
  type, because other inits read list contents [I]) → types ascending → AVIF → NPC_/RACE fix-ups → NAVI → WRLD (P8,
  skipped in P3 on purpose, after the NPC_/RACE passes) → interior cells and their refs (P9).
  **Keep the phase order and a barrier between types.**
- **Within a type** the engine depends on order only through on-demand recursion (WEAP/ARMO templates, SM nodes, DIAL)
  and through the order of global containers (the NPC_ preset list). Resolve-only bodies read other forms only
  through `LookupByID`. That returns the *object pointer*, which already exists after the load loop, not
  InitItem-produced state [V for the pattern / I that no hidden read of a not-yet-initialized field exists in every
  body].

| Option | Verdict |
|---|---|
| (i) **Split by form type, parallel inside each type, barrier between types** | **Viable for the B1/B2 resolve-only types** (most of the ~120 types). WEAP/ARMO/DIAL/SM nodes also need an **atomic claim on `kInitialized`**, or a serial pre-pass over the forms that others use as templates or parents |
| (ii) Split by form, with a lock around the problem classes | **Needed for INFO** (lock around 25668/25669/25611/25492 call sites) and **NPC_** (the list push is inline at 0x3BA4F5, so the lock has to go around the whole NPC_ InitItem, or the push moves to a serial post-pass). This is safe but adds lock traffic |
| (iii) Not at all | **REFR/ACHR/PHZD/CELL/WRLD/NAVM/NAVI and the P0/P2/P4-P7/P10 tail**: they create forms, touch dozens of globals, take cell spinlocks and write locks, and use the TES singleton. These are P7-P9, outside the P3 loop |

**Share of the 40.6 s:** **this cannot be estimated from code alone.** The P3 loop holds every non-ref form; the field
list dispatched 1.34 M records in total (LT-2). P8/P9 hold every persistent reference. REFR/ACHR InitItem is by far the
heaviest code: about 5-10 times the reach of NPC_/INFO, and 30-100 times a typical resolve-only body. As a reference
point, the vanilla masters alone contain 58k persistent refs against about 225k other non-ref forms (offline header-walk count
of Skyrim/Update/Dawnguard/HearthFires/Dragonborn.esm in this pass, unique FormIDs). So **P8+P9 (serial) could plausibly be half or more of the 40.6 s** [I].
Within P3, INFO and NPC_ are likely the biggest per-type costs [I].
A realistic first build (P3 only, 8 workers, INFO and NPC_ locked or serial) frees somewhere between a few seconds and
about 15 s [I, wide]. The histogram probe in section 7 replaces this guess with measured shares.

**Additional risks** [I unless marked]:
- **`allFormsMapLock` contention.** Every resolve takes the shared read lock (68233/68239). All workers do atomic
  read-modify-writes on one cache line, which may cap scaling.
- **The `formFlags` read-modify-write in 14637** [V]. A lost update is possible if two threads touch flags on the same
  form (only through recursion targets).
- **Arrays that grow during P3** [V that the loop re-reads the size]. Snapshot each array and re-run the tail serially
  at the barrier.
- **Worker threads and engine TLS** [I]. TLS `taskFlag` (+0x768) and the scrap heaps are per thread. Workers need an
  engine-valid TLS block; static TLS exists for all threads, but verify that MemoryManager is safe on non-engine
  threads.
- **Error-path global 400487** [V]. Benign race; it can be serialized by locking around 19995 if needed.

## D. The 17.8 % remainder (20.8 s): 13753 outside 13760 and 13784
13753 starts with `dl = 0` at the startup call 0x642F08/0x642F11 [V].

| Order | Call site(s) | What | Cost by structure | Parallelizable? |
|---|---|---|---|---|
| 1 | 0x1B974F | 13295(TES, 0, 0): TES world reset (reach 130 functions) [V calls / I purpose] | constant; the world is empty at startup [I] | n/a |
| 2 | 0x1B977E | 13281: 8 instructions | trivial [V] | — |
| 3 | 0x1B97A9 / 0x1B97BB | **only if `[dh+0xDA2]`**: 13936 (reads records through ReadData/14033/14034) and 13945, which build the file list from the active file | unknown; **whether the branch is taken at startup is not verified** | ? |
| 4 | loop 0x1B9820-0x1B9894 over `dh->files` (all 3499) | per file: flag getters (14006/14001/13958/14008), **13741** = compile-index assignment (96 instructions), **453528** (`_strnicmp` scan of the name table 505567 plus a BSFixedString scan of 505564) and, if that returns true, **13786 = BSA auto-load: builds `"<plugin>.bsa"` and `"<plugin> - Textures.bsa"`, checks the loaded-archive hash 359016, calls 69852 (open and register the archive)** [V strings and calls] | 13741 cheap. **13786 is I/O (opening archives, reading archive directories)**; how many plugins pass the 453528 gate is not known [I: the gate is a name-list membership test] | archive opens are per file and independent [I]; the archive registry is global → registration stays serial |
| 5 | 0x1B98C5/0x1B98DD | the same for the active file | — | — |
| 6 | **pass 1, 0x1B9910-0x1B9987**, call sites **0x1B991B** (`compiledFileCollection.files`) and **0x1B996B** (`smallFiles`) | **`OpenTES` (13931 → 13932) on every plugin**, then `400469 += file->+0x430` (record count from HEDR) for the progress bar. **It does not call CloseTES**, so the files stay open; the second OpenTES in 13760 sees `+0x38` set and takes the short path (0x1C4EDB) [V branch / I that it is cheaper] | **3499 file opens + TES4 header reads**, I/O and path-resolution bound. Under Proton + a VFS, an open can cost milliseconds: 3499 × 2-5 ms ≈ 7-17 s [I] | opens are per file and independent [I]; can be warmed or pre-opened on workers. Under Wine, opens serialize in wineserver, which caps the gain [I] |
| 7 | 0x1B9998 | **13698** (startup only, `dl == 0`): creates about 55 hard-coded forms (55 allocations, 54 `AddFormToDataHandler`, 52 `LookupByID`) | constant, milliseconds [I] | not needed |
| 8 | 0x1B99BC, 0x1B9A34 | **13767**: walks `dh->files`; for masters, 14049 (6 instructions: `bufferAllocSize`) | trivial [V] | — |
| 9 | 0x1B9A4F/0x1B9A65 | 13403: returns or creates the TES NavMeshInfoMap | trivial [V] | — |
| 10 | 0x1B9A71 | **30433(navi+0x30)**, if NAVI `formFlags` bit 1: loops over the navmesh infos and builds the pathing graph (90350/90356/90370, 30436/30437/30636; reach 88 functions) [V loop / I purpose] | proportional to the navmesh-info count (tens of thousands on a large list [I]) → **possibly seconds** | graph build, global → serial [I] |

**Answer:** the remainder holds two I/O loops over all 3499 plugins (pass-1 OpenTES and the gated BSA auto-load) and
one CPU loop (30433). The rest is constant. **Pass-1 OpenTES is the most likely dominant item** [I]: it is the only
item that certainly runs on all 3499 files and does a real file open each time. LT-2 also shows the *second* OpenTES
(inside "13760 ex", 3.9 s including all per-record overhead) is far cheaper, which fits "the first open pays the path
lookup". The reasoning is structural, not measured.

## E. What is still unverified, and the next probe
| # | Unverified | Cheap probe (extends LT-2; all sites are `E8` unless noted) |
|---|---|---|
| 1 | **How the 40.6 s splits by phase and by form type.** This decides whether P3 parallelism pays at all | **(a) Phase timers in 13784**: QPC at the E8 sites 0x1BE1C6 (enter P3), 0x1BE242 (first hit = P3 end), 0x1BE2A8, 0x1BE2E1, 0x1BE2F3, 0x1BE361, 0x1BE3B5, 0x1BE3EC, plus 13784 exit. Phase = difference between consecutive timestamps, using last-hit logic because empty arrays skip sites. **(b) Per-type histogram**: patch slot 0x13 in the primary vtable of each form class (about 110 vtables, about 75 distinct functions, ids from CommonLib `VTABLE_*`) with a thunk that calls the original and accumulates **count, inclusive time and exclusive time** (TLS nesting stack) per `formType = [rcx+0x1A]`, active only while inside the 0x1B9A43 call. Also log **recursion edges** (parent type → child type, and how often the child was not yet initialized). That measures hazard class 1 directly |
| 2 | **Which item dominates the 20.8 s** | E8 call-site timers plus counts at 0x1B974F (13295), 0x1B97A9/0x1B97BB (13936/13945, also "taken?"), 0x1B986F/0x1B98C5 (13741), 0x1B9878/0x1B98D1 (453528, count true), **0x1B9885/0x1B98DD (13786)**, **0x1B991B/0x1B996B (pass-1 OpenTES)**, 0x1B9998 (13698), 0x1B99BC/0x1B9A34 (13767), **0x1B9A71 (30433)**. The current 13753 "ex" bucket then splits into named rows |
| 3 | **Whether P3 bodies are really independent within a type** (no hidden reads of another same-type form's initialized state; INFO/NPC_ global writes are the only real conflicts) | Part of (1b): count recursion edges; count hits of 19995/400487 (error path); for INFO, count calls through 0x3EAF64/0x3EB064 (global map writes) and 0x3EAF7A loop length (the 401560 list). A later offline audit of the top 5 types by measured time can then be targeted |

**Recommended next probe (one field run decides the build):** add 1a + 1b + 2 to the existing LT-2 DLL. Decision
rules:
- if P3 ≥ 50 % of 13784 and the resolve-only types (B1/B2 minus INFO/NPC_/WEAP/ARMO) are ≥ 30 % of P3 → build the
  P3 dispatcher;
- if P8+P9 dominate → P3 parallelism is capped and the real target is ref init (LT-6 territory);
- if pass-1 OpenTES dominates the remainder → a parallel pre-open/warm-up stage before 0x1B9910 is the cheapest win
  in the whole load.

## F. The minimal seam (for P3)
| Role | Address | Bytes | Contract |
|---|---|---|---|
| Gate | 0x1B9A43 (13753 → 13784) | `E8 A8 46 00 00` | only the startup call; 13785 @0x1BEFEB is the runtime caller and must not be affected [V] |
| **EXFIL** (replace the P3 loop) | **0x1BE1CB** | `40 32 F6 66 90` (`xor sil,sil; nop`): exactly 5 bytes; no branch targets this range (the loop head 0x1BE1D0 is the only internal target) [V] | `jmp` to a stub: `mov rcx, rbp; sub rsp, 0x20; call Dispatcher(dh); add rsp, 0x20; jmp 0x1BE236`. Body `rsp` is 16-aligned. `rbp` (= dh) and `r14` (= 0, read at 0x1BE236) are callee-saved; `rbx/rsi/rdi` are reloaded after 0x1BE236 [V] |
| **JOIN** | **0x1BE236** (`mov ebx, r14d`, start of P4) | — | Dispatcher returns only after every type has passed its barrier. Everything from here on stays engine-serial |
| Alternative EXFIL (per form, keeps the engine loop) | 0x1BE221 `FF 90 98 00 00 00` (6 bytes; `rcx` = form, `sil` = type, `rbx` = cursor) with a per-type barrier at 0x1BE22D (`inc sil`, 3 bytes) | — | finer-grained "dialysis": serial types pass through, parallel types enqueue; drain at 0x1BE22D before the type advances |

**Ordered commit:** none for resolve-only types (writes are form-local; no order-visible global). **NPC_** needs one if
the preset list order (push order) is observable [I]: do the 0x3BA4F5 push in a serial post-pass in array order, or
run NPC_ serially. **INFO** needs mutual exclusion, not ordering: its global containers are hash maps [V], though the
401560 list traversal is a read whose stability during P3 has not been verified.
