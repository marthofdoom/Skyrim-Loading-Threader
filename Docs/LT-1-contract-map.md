# LT-1: contract map of the phase-A serial loop (SkyrimSE 1.6.1170.0)

Date: 2026-10-18. Offline only. I used capstone on `binaries/1.6.1170/SkyrimSE.unpacked.exe` and the Address Library
`versionlib-1-6-1170-0.bin`. Names come from CommonLibSSE-NG (`_commonlib/live-alandtse-ng`, the AE column).
Labels: **[V]** = verified in the 1.6.1170 disassembly in this pass. **[I]** = inferred (from naming, CommonLib, or prior
knowledge of the plugin format). All RVAs are image-relative (base 0x140000000). "id" means the AE Address Library id.

## 0. Corrections to FEASIBILITY.md Phase A
- **id 14667 @0x1E1640 is `TESForm::AddCompileIndex(FormID&, TESFile*)`, not `LookupByID`** (CommonLib
  `RELOCATION_ID(14509, 14667)`). [V] 13760 calls it only on the topic-children group path. The real per-record lookup is
  **id 14617 @0x1E01A0 = `TESForm::LookupByID`** [V]. It takes `allFormsMapLock` (400517) **for read** (68233/68239)
  and probes `allForms` (400507).
- **`[vtbl+0x190]` is slot 0x32 = `TESForm::GetFormEditorID()`, not Load** [V by CommonLib's slot table]. 13760 uses it
  to register the editor ID after the form is loaded. **Load is slot 6 (`[vtbl+0x30]`)**, called through the wrapper
  **13690 @0x1B11F0**, which the per-record dispatcher **13763 @0x1BBAA0** calls [V].
- The real per-record body is **13763** (a switch over 0x75 form types). 13760 is only the loop and bookkeeping around it.

## 1. Per-record flow, in order
Outer loop: `13753` (LoadFiles-shaped) → for each file with a compile index (`13964`: `compileIndex != 0xFF`, excluding
`activeFile`), `13760(dataHandler, file, isFirstFile)`. The flag is 1 only for the first file (dil at 0x1B99C1/0x1B9A08) [V].

| # | Step | Where | Status |
|---|---|---|---|
| F0 | `OpenTES` (13931), then 13883: reads the TES4 header and masters, and builds the master table (calls 14667 and 13805 on 359018) | 0x1BB6FC/0x1BB704 | [V] calls / [I] purpose |
| F1 | Reset the context globals 400461 (current CELL), 400462 (current WRLD) and 400458 to 0; `[dh+0xDAA]=0` (`gameSettingsLoadState`) | 0x1BB70F-0x1BB738 | [V] writes / [I] names from use in 13763 |
| R1 | `SeekNextForm(true)` (13979): advance `fileOffset` (+size+0x18 for a record, +0x18 to descend into a GRUP), clear `decompressedFormBuffer` (+0x4A0), then `14033` reads the 0x18-byte FORM header into `file->currentform` (+0x284) | 13979 @0x1C7D30 | [V] |
| R2 | **Header FormID remap, inside 14033**: `idx=formID>>24`; owner=`masterPtrs[idx]` if idx<`masterCount`, else self; unless `formID` is hardcoded (1..0x7FF, 14652): ESL owner (`recordFlags` bit 9) → `0xFE000000 \| smallFileCompileIndex<<12 \| id&0xFFF`, else `compileIndex<<24 \| id&0xFFFFFF` | 0x1C9B37-0x1C9BCC | [V] |
| R3 | Skip records with flag 0x1000 (ignored) when `a_skipIgnored` | 0x1C7D9D | [V] |
| R4 | `GetFormType` (13982). GRUP: group types 4/5/9 call 14001/13973 (skip/descend); type 7 (topic children) can skip the whole group using 401555 (current DIAL) and a FormID hash set 359023 | 0x1BB75A-0x1BB865 | [V] branches / [I] meaning |
| R5 | TOFT (0x56): offset-table bookkeeping (14050, 20458, 19081), no form | 0x1BB86A-0x1BB91A | [V] calls / [I] purpose |
| R6 | Otherwise `13763(dh, file, isFirstFile, nullptr)` | 0x1BB931 | [V] |
| 13763.a | Set the TLS `taskFlag` (TLSData+0x768) to 0x65, and TLS byte +0x5DB=1 | 0x1BBAD7 | [V] (thread-local) |
| 13763.b | GMST state machine: `[dh+0xDAA]` 0→1 on the first GMST (type 3), 1→2 on the first non-GMST | 0x1BBB1C | [V] |
| 13763.c | **Override detection**: `LookupByID(currentform.formID)` (14617), **skipped for the first file** unless the ID is hardcoded. A type mismatch with the existing form → error path | 0x1BBB4A-0x1BBB97 | [V] |
| 13763.d | Existing CELL/WRLD/DIAL (`IsParentForm`, slot 0x34): set the context global (CELL→400461, WRLD→400462, DIAL→401555), call `LoadPartial` (slot 7), `SetFile` (14623), clear `kInitialized` (14637), return | 0x1BBBD0-0x1BBC85 | [V] |
| 13763.e | Existing form (override), not deleted: refs (0x3D-0x46) get extra handling (`[vtbl+0x4B8]`, 19032); then the **SkyrimVM handle policy releases script handles** (400475+0x200, `[+0x168]`/`[+0x20]`, 104183); `14602`, **`ClearData`** (slot 5), `14599`, **`InitializeData`** (slot 4). An override replaces the whole form | 0x1BBC93-0x1BBDCB | [V] calls / [I] semantics |
| 13763.f | `switch(formType)`: CELL/WRLD/REFR/ACHR/LAND/NAVM/DIAL/INFO/TES4(ONAM) and others have their own cases. They read and write the context globals 400461/400462/401555/400458 and attach children to the current parent (18903, 11638, 19544, 20528, ...). NAVM takes write lock 402042 | 0x1BBDE6 jump table | [V] calls / [I] case meanings |
| 13763.g | **Default case**: form = existing ?: `13765(type)` = `IFormFactory::GetFormFactoryByType` (14587, table 400508, 0x8A types) `->Create()` | 0x1BC91C-0x1BC92E | [V] |
| 13763.h | `13690(form, file)`: **`form->Load(file)` (slot 6)**, then 14635 (flag bit 0 sticky with file kMaster), and `SetAltered` (slot 0x24) if the file is kActive | 0x1B11F0 | [V] |
| 13763.i | New form only: **`TESDataHandler::AddFormToDataHandler`** (13693): push into `formArrays[type]` and per-type side lists | 0x1BC950 | [V] |
| 13763.j | Restore TLS `taskFlag` | 0x1BC95B | [V] |
| R7 | Editor-ID registration: `LookupByID(formID)` again; if type ∉ {NPC_ 0x2B, 0x3D-0x46} and `GetFormEditorID()` (slot 0x32) is non-empty → **write-lock `allFormsEditorIDMapLock` (400518)** → 13907 inserts into `allFormsByEditorID` (400509; builds a BSFixedString) | 0x1BB93F-0x1BB9AB | [V] |
| R8 | Progress: `++400472`; recompute `400472/400469*scale`; when it changes, 12920 formats a progress string with the file name | 0x1BB9B1-0x1BBA04 | [V] writes / [I] the 12920 meaning |
| F2 | `CloseTES` (13933) | 0x1BBA31 | [V] |

### Inside the Load virtual (sampled: TESForm base, BGSKeyword, TESGlobal, TESNPC, TESObjectWEAP, TESObjectREFR, TESObjectCELL)
| Step | What | Status |
|---|---|---|
| L1 | Base `TESForm::Load` (13882) is `return true` | [V] |
| L2 | Each Load starts with **14656 → TESFile 13996 (apply the header to the form)**: `formType` (14624), `formFlags` from the record flags, then **`SetFormID(currentform.formID, true)`** (slot 0x38 = 14666): erase the old ID and **insert into `allForms` under the `allFormsMapLock` write lock** (14710/14688), then **`SetFile`** (14623): append to the form's source-file array (allocates) | [V] for Keyword and Global (direct call), [V] that NPC/WEAP/REFR/CELL call 14656 |
| L3 | Loop: `GetCurrentSubRecordType` (13988) → switch → `ReadData` (13991) into a scrap buffer or straight into form fields → `SeekNextSubrecord` (13990). Subrecord headers come from 14034. A compressed record (flag 0x40000) is inflated once by 14032 into `decompressedFormBuffer` (+0x4A0, backed by +0x4B0) | [V] |
| L4 | Side effects seen in the sampled Loads: EDID → `SetFormEditorID` (slot 0x33) → **BSFixedString pool** (69161/69164/69167); OBND → `LoadObjectBound` (slot 0x26); VMAD → 14654: **SkyrimVM** and handle policy, sets global byte 411225, `lock inc` on 411119; **TESNPC::Load keeps condition-parse state in global 401439** across subrecords (0x3B6417/0x3B6462); REFR Load calls `LookupByID` (14617) and `AddCompileIndex` (14667), and takes a write lock (68234); heap allocations through MemoryManager (10854 → 68115) and the thread scrap heap (68108/68109) | [V] calls/writes / [I] each one's purpose |
| L5 | End: clear `kInitialized` (14637, flag bit 3). Cross-form links are resolved later in `InitItem` (13784) | [V] flag write / [I] the deferral |

## 2. Reads and writes per step, by ordering class
Classes: **OD** = order-dependent (must commit in load order). **LK** = order-independent but needs the engine lock.
**TL** = thread-local or worker-private (safe). **PF** = pure function of per-file data that is fixed before the loop.

| Step | Reads | Writes | Class |
|---|---|---|---|
| R1 SeekNextForm / 14033 header read | file bytes (BSFile, or the in-memory buffer when 359065 and `file+0x29` are set) | `file->currentform`, `fileOffset`, `+0x4A0` cleared | TL for a worker's own parser; the engine's TESFile cursor is per-file shared state [V] |
| R2 FormID remap | `masterPtrs`, `masterCount`, `compileIndex`, `smallFileCompileIndex`, `recordFlags` | `currentform.formID` | **PF** [V]. Compile indices are assigned before the loop [I] |
| 14032 inflate | compressed bytes | `+0x4A0/+0x4A8/+0x4B0/+0x4B8` (per-file buffer), MemoryManager | **pure bytes→bytes** apart from the buffer; TL if the worker has its own buffer [V] calls / [I] zlib names |
| R4/R5 group/TOFT handling | 401555, 359023, currentform | file cursor | OD (order within the file) |
| 13763.b GMST state | `[dh+0xDAA]` | `[dh+0xDAA]` | OD |
| 13763.c LookupByID | `allForms` (read lock) | — | **OD**: the result depends on every earlier record and plugin |
| 13763.d/f context globals | 400461/400462/401555/400458 | same | **OD** (CELL/WRLD/DIAL nesting); one set of globals, not thread-safe [V] |
| 13763.e override reset | existing form | form (`ClearData`/`InitializeData`), VM handle policy | OD |
| 13763.g factory Create | factory table 400508 | heap (new form) | LK (the allocator is thread-safe [I]); the result only matters if this record is new, which is OD |
| L2 SetFormID / SetFile | `allForms` | **`allForms` insert (write lock)**, form fields, form source-file list | map content is LK; *which object* gets the ID is OD; source-file list order is OD |
| L3/L4 Load body | TESFile cursor, scrap heap | form fields, BSFixedString pool, SkyrimVM, 401439, 411225/411119, other lookups | **OD**, mixed with globals; not reentrant (401439 is one global) |
| 13763.i AddFormToDataHandler | — | `formArrays[type]` and side lists | **OD** (array order = load order; 13784 iterates it) |
| R7 editor-ID insert | form | `allFormsByEditorID` (write lock), BSFixedString | LK for distinct IDs, OD for duplicates [I] |
| R8 progress | 400469 | 400472, progress text | OD-cosmetic (could be batched) |
| TLS `taskFlag` | — | TLSData+0x768 / +0x5DB | TL |

## 3. The seam: where byte parsing ends and engine mutation begins
- **There is no seam inside a record's Load.** [V] Each sampled Load pulls subrecords one by one from the engine's
  `TESFile` cursor and writes each field into the form as it goes. It registers the form in `allForms` (SetFormID) *before*
  it reads the first subrecord, and some types keep parse state in globals (TESNPC → 401439). Decode and apply are one
  code path per form type (about 0x8A factory types, each with its own Load).
- **There is a clean seam one layer down, at the record-bytes level** [V]. Everything up to "the bytes of this record
  are in memory, decompressed, with a remapped header FormID" is a pure function of the file contents and the
  per-file master table:
  - framing (record and group headers, 14033/14034),
  - header FormID remap (R2, PF),
  - zlib inflate of compressed records (14032).
  The engine already accepts a ready buffer here. 14034 inflates only when `file->decompressedFormBuffer` (+0x4A0) is
  null (`test rcx,rcx; jne` at 0x1C9C49), and then reads subrecords out of that buffer. 14032 has exactly three
  callers, all inside TESFile: 13991 `ReadData`, 14029 and 14034 [V].
- A **neutral pre-decoded struct per form type** (a worker decodes subrecords, and the serial side applies them) would mean
  writing a replacement Load for each form type and matching the engine's field semantics exactly. That is LT-6
  (receiving-side rework) territory, at hundreds of functions.

## 4. Dependencies on earlier records
- Override detection: `LookupByID` once per record (13763.c), skipped for the first file [V]. **OD**.
- Header FormID remap: depends only on the file's masters and compile indices (R2). **No dependency on earlier records** [V].
- Subrecord FormIDs: `AddCompileIndex` (14667) uses the same per-file data (PF) [V for the REFR call sites / I in general].
- Group nesting: CELL/WRLD/DIAL set 400461/400462/401555, and children (REFR/ACHR/LAND/NAVM/INFO) read them. They are
  reset at the start of each file [V]. **OD inside a file.**
- REFR Load looks up its base object directly (14617) [V]. Most other cross-form links are deferred to `InitItem` [I].
- Existing CELL/WRLD/DIAL forms take the `LoadPartial` path (13763.d) [V]: that is a merge, not a replace. **OD**.

## 5. Post-load passes
- **13767** @0x1BCC30 (`(dh, -3)` before the file loop; `(*400269, -1)` after it): walks `dh->files` and calls 14049 on
  master files, which sets `file->bufferAllocSize = 0x10000` unless the file is in memory. Buffer housekeeping, no
  form work [V]. It has no ordering constraint against the loop beyond running before or after it.
- **13784** @0x1BE0F0 (after the loop): runs **`InitItemImpl` (slot 0x13) over every form in `formArrays[type]` for
  type 0..0x89** (skipping 0x13, 0x47, 0x5B), after a first pass over the array at +0x898. Then over 0xA4 entries of
  27202 (likely the ActorValueInfo table [I]), then NPC-specific passes (24787, 25362), then IOManager (75708), and so on [V calls].
  **It must stay after the whole loop**, because InitItem resolves references to forms from any plugin [I, standard
  engine behaviour]. It runs serially in array (load) order. Whether InitItem can be parallelized is a separate question,
  not answered here.

## 6. Verdict
**The work inside the per-record loop is not pure.** The unit the engine calls is `Load`, and Load reads and mutates in
one pass. The dialysis design is **viable in a simple form with a capped gain**, and **hard (LT-6) in its full form**.

- **Simple form (recommended first build):**
  - **DRAW** (per record, any file, run ahead in load order on workers, each with its own file handle and parser,
    never the engine's TESFile): walk the record stream and **inflate compressed records**. Optionally also precompute
    the header remap and the subrecord offset table. Hook point: the file loop in 13753 (the 13760 call at 0x1B9A03) gives
    the file order up front.
  - **RETURN**: hook **14032 @0x1C9790** (or the null check at 0x1C9C42 in 14034). When the reorder buffer holds this
    (file, fileOffset) record, point `+0x4A0/+0x4A8` at the pre-inflated bytes and skip the zlib call. The engine still
    pulls records serially, so commit order is unchanged by construction. Buffer lifetime must match the engine's
    `+0x4B0` reserved buffer: SeekNextForm only nulls `+0x4A0`, it does not free it [V].
  - **Serial commit surface (unchanged engine code):** all of 13763 (lookup, create/reuse, ClearData/InitializeData,
    Load with SetFormID/SetFile/BSFixedString/VM/conditions, context globals, AddFormToDataHandler), R7 editor-ID insert,
    R8 progress, GMST state, then 13767/13784.
  - Gate every hook on "inside 13753": 13763 is also reached from runtime cell reload (13785), 15138, 15360, 19112
    and save load (35941) [V callers].
- **Full form (parallel subrecord decode):** a worker cannot run the engine's Load (it is not reentrant: 401439,
  context globals, SkyrimVM, allForms write inside), so this needs per-type replacement Loads. Hard; do not start
  before M0 shows that Load-body CPU time dominates.
- **Parallel fraction:** **unknown until M0.** The drawable share is the inflate CPU (plus framing, which is cheap) as a
  fraction of 13760's time. Plain I/O read-ahead belongs to the cache project, not here. From prior knowledge [I], in
  vanilla data only some record types are commonly compressed (NPC_, LAND, NAVM, some CELL/WRLD), so the simple form's
  ceiling may well be modest (tens of percent at best, possibly single digits).
  The Load bodies (the likely bulk of CPU time) remain serial in the simple form.

## 7. Still unverified, and the cheap LT-2 probe for each
1. **How 13760's time splits** between inflate (14032), raw read (13991/69418), the Load bodies (13690 minus nested
   inflate and read) and R7. *Probe:* QPC-accumulating hooks on 14032, 13690, 13991 and the 13760 call at 0x1B9A03,
   logged per plugin. This settles the parallel fraction and whether the simple form is worth building.
2. **Whether a pre-filled `+0x4A0` buffer is honoured on every path.** 14032 has three callers (13991, 14029, 14034);
   Seek (13984) or the special cases in 13763 might re-read a record. *Probe:* hook 14032 and log (file,
   fileOffset, call count). Each compressed record should inflate exactly once per load, and no call should arrive
   with `+0x4A0` already set.
3. **Whether the record stream that the engine consumes matches a stream a worker can enumerate offline**
   (`a_skipIgnored`, the group-skip optimisations at R4/R5, `bLoadEsmInMemory` 359065 and `file+0x29`). *Probe:* log the
   sequence of (file, fileOffset, sig, formID) in SeekNextForm for one run, and diff it against an offline walker on the
   same load order. Only records the engine actually visits should be drawn, though over-drawing is harmless.
