# LT-2b: the v2 site table, validated (SkyrimSE 1.6.1170.0)

Date: 2026-10-19. Offline, scripted cross-check of every v2 row in `native/Sites.h` against the unpacked 1.6.1170 exe,
the `versionlib-1-6-1170-0.bin` Address Library (self-check id 38048 = 0x6A35F0) and the exe's `.pdata`. Nothing was
compiled. RVAs are image-relative. Labels as in LT-1b: [V] seen in the disassembly, [I] inferred.

## 1. Result
| Table | Rows | Validated | Removed | Notes |
|---|---|---|---|---|
| `Fn` callees (v1 + v2) | 54 | 54 | 0 | every id -> rva equals the Address Library |
| v1 call sites + gate | 25 | 25 | 0 | unchanged |
| `kTimedSites` (E8) | 55 | 55 | 0 | boundary, inside fnId's primary `.pdata` chunk, `E8 rel32` (5 bytes), target == callee |
| `kVfSites` (virtual InitItem) | 10 | 10 | 0 | 6-byte `call [rax/rdx+98h]`; 2 placeholder hashes replaced (0x306496, 0x30CE4C -> 0x12968933da5cb618) |
| LookupByID counter (14617+0x2A -> 68233) | 1 | valid | deferred | an E8 call site (needs no entry hook) and its entry hash matches, but it is a gameplay hot path: `#if 0` |
| Lock entry detours 68233 / 68234 | 2 | hashes match | deferred | global entry detours on every lock of every thread: `#if 0`, not compiled |

Completeness [V]: 13753, 13784, 13760 and 13763 are each one `.pdata` chunk. 13753 contains exactly the 25 v2 + 3 v1 E8
calls and no other call. 13784 contains the 22 v2 E8 calls, the 6 virtual calls in `kVfSites`, and one 3-byte
`call [rax+20h]` at 0x1BE2A2 (NPC_ actorData vfunc), which cannot be hooked and falls into the P5 wall.

Calling convention [V]: no wrapped callee reads a 5th (stack) argument or xmm0-3 on entry (whole-chunk scan; the leaf
callees without `.pdata` were read to their `ret`). The `[rsp+20h+]` stores before some calls are the callers' own
locals (the EH-state marker, the P9 visitor object whose address is passed in rdx, the P10 locals), not arguments.
As a control, the same scan flags 13763's known 5th stack byte (0x1BC033). The generic 4-register thunk (`Fn4`) is
therefore correct for every `kTimedSites` row.

## 2. 13784 (InitItem pass) phase boundaries
Use monotonic "last hit wins" markers: a phase starts at the first marker that fires for it. "always" means the
marker sits on an unconditional path. An empty array skips its marker, and that phase's time then lands in the
previous phase. That bias is negligible because the loop is empty.

| Phase | Code range | Starts at | Always? | Contents |
|---|---|---|---|---|
| P0 DOBJ | 0x1BE0F0-0x1BE122 | 13784 entry (v1 site 0x1B9A43) | yes | 13894 at 0x1BE111, DOBJ InitItem vf 0x1BE11C |
| P1 FLST | 0x1BE122-0x1BE171 | return of vf 0x1BE11C | yes | vf 0x1BE165 per FLST form |
| P2 misc | 0x1BE171-0x1BE1CB | entry of 0x1BE181 (only if Calendar is null) or else 0x1BE18D | 0x1BE18D yes | 36289, 18779 x2, 13894, IOManager 75708 at 0x1BE1C6 |
| **P3 core** | 0x1BE1CB-0x1BE236 | **return of 0x1BE1C6** | yes | **per-form vf 0x1BE221**, see section 3 |
| P4 AVIF | 0x1BE236-0x1BE25D | entry of the first 0x1BE242 (27202) | yes, 0xA4 times | vf 0x1BE24D x 0xA4 |
| P5 NPC_ | 0x1BE25D-0x1BE2B3 | return of the 0xA4th vf 0x1BE24D | yes | 0x1BE2A2 vfunc (not hookable) + 24787 at 0x1BE2A8 per NPC_ |
| P6 RACE | 0x1BE2B3-0x1BE2EC | entry of the first 0x1BE2E1 (25362) | per RACE | |
| P7 NAVI | 0x1BE2EC-0x1BE315 | entry of 0x1BE2F3 (13403) | yes | 13403 again at 0x1BE304 and vf 0x1BE30F, only if the map exists |
| P8 WRLD | 0x1BE315-0x1BE361 | return of vf 0x1BE30F, or entry of the first vf 0x1BE355 | per WRLD | WRLD InitItem 20455 -> persistent cell vf 0x306496, child cells via 20563 (vf 0x30CE4C) -> refs |
| P9 cells | 0x1BE361-0x1BE3E5 | entry of 0x1BE361 (20544) | yes | 35993, 35984, 18882 at 0x1BE3B5 per interior cell (ref vfs 0x2B35A2 / 0x2B365C), 68146 |
| P10 tail | 0x1BE3E5-return | entry of 0x1BE3EC (24591) | yes | 20683, 11160, 24527, 13796 (only if >1 RACE), 35994 |

## 3. The per-form site in the core loop
**0x1BE221** (13784+0x131), a 6-byte `call qword ptr [rax+98h]` = slot 0x13 InitItemImpl [V]. At the call: rcx = the
form, rax = its vtable (loaded from [rcx] by the two instructions right before), sil = the formArrays index t
(0..0x89; 0x13 SCPT, 0x47 WRLD and 0x5B FLST are skipped), rbx = the array cursor. rbx, rsi and rdi are callee-saved and
are used after the call; rax is reloaded. The type advances at 0x1BE22D (`inc sil`) and the loop exits at 0x1BE236.
For the per-type table, the type is t (= the form's formType byte at +0x1A for these arrays [I]). The end pointer is
re-read on every iteration (LT-1b A).

## 4. 13753 (LoadFiles) direct callees, in code order
| Site | Callee | What | Segment |
|---|---|---|---|
| 0x1B974F | 13295 | TES world reset | setup |
| 0x1B977E | 13281 | 8-instruction setter | setup |
| 0x1B97A9 / 0x1B97BB | 13936 / 13945 | only if dh+0xDA2: file list from the active file | setup |
| 0x1B97D3 / 0x1B97DF | 14006 / 13960 | active-file precheck (flag getters) | setup |
| 0x1B982E, 0x1B983A, 0x1B984F, 0x1B9857 | 14006, 14001, 13958, 14008 | per-file flag getters | file loop |
| 0x1B986F / 0x1B98C5 | 13741 | compile-index assignment (rdx = file) | file loop / activeFile |
| 0x1B9878 / 0x1B98D1 | 453528 | BSA name-list gate (rcx = file+0x58), al = pass | file loop / activeFile |
| 0x1B9885 / 0x1B98DD | 13786 | per-plugin BSA auto-load (rcx = file+0x58) | file loop / activeFile |
| 0x1B991B / 0x1B996B | 13931 | pass-1 OpenTES on `files` / `smallFiles` (rcx = file) | pass 1 |
| 0x1B9998 | 13698 | hard-coded forms | hardcoded |
| 0x1B99BC | 13767 | buffer housekeeping (dh, -3) | buf1 |
| 0x1B99E7 | 13964 | "has a compile index" filter | plugins |
| 0x1B9A03 / 0x1B9A23 | 13760 | per-plugin loader (v1) | plugins |
| 0x1B9A34 | 13767 | buffer housekeeping (-1) | buf2 |
| 0x1B9A43 | 13784 | InitItem pass (v1) | initItems |
| 0x1B9A4F, 0x1B9A65 | 13403 | NavMeshInfoMap get/create (2nd only if NAVI flag bit 1) | navTail |
| 0x1B9A71 | 30433 | navmesh graph build (only if NAVI flag bit 1) | navTail |
"Residual unattributed" = 13753 inclusive time minus the sum of these calls (inline code: loops, flag stores).

## 5. Gotchas for the implementer
1. **6-byte virtual sites.** Patch with `SKSE::Trampoline::write_call<6>`. It writes `FF 15 disp32` (call through an
   8-byte slot), so the return address stays site+6 as in the original. **Its return value is garbage for these
   sites**: it computes site+6+disp32 as if the original were rip-relative. Ignore it. The original target is
   per object: the thunk calls `(*(fn**)(*(char**)rcx + 0x98))(rcx, rdx, r8, r9)`. Before patching, check the
   FNV-1a hash of [site-pre, site+6). E8+90 is a valid alternative (the return address is then site+5, inside the
   original instruction). At the FF 92 sites rdx holds the vtable. Forward it unchanged.
2. **13763 has a 5th stack argument** (v1 `Fn5`). The new 13693 row inside 13763 (0x1BC950) is plain 4-register:
   rcx = dh, rdx = the new form. It runs only for a new form (an override skips it).
3. **Not wrapped on purpose:** 12920 (progress text, 0x1BBA04, takes a stack argument) and the 3-byte vfunc at
   0x1BE2A2.
4. **The vf sites outside 13784 (20455, 20563, 18882) and everything inside 13763/13760 also run at runtime** (cell
   attach, save load) on any thread. Gate them by the episode state and the thread id as v1's `Enter()` does.
5. **Nesting.** InitItem bodies recurse into other forms through un-hooked calls (33043 -> SOUN, WEAP/ARMO templates).
   Per-type time at 0x1BE221 is therefore inclusive of recursive inits. WRLD -> cell -> ref nests the hooked vf sites,
   so use the v1 exclusive `Scope`.
6. **activeFile path:** 453528 and 13786 at 0x1B98D1 / 0x1B98DD get `rdi+0x58`, where rdi is left over from the
   file loop [V]. kRcxName (subtract 0x58) still names the file the engine actually passes.
7. **Trampoline budget:** v1 reserved 512 bytes. 55 E8 sites with distinct thunks need 14 bytes each, plus 8 bytes
   per distinct 6-byte destination. Reserve at least 2 KiB.
