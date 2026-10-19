#pragma once

// Verified address table for the LT-2 probe. SkyrimSE 1.6.1170.0 (AE) ONLY.
//
// Provenance of every row (2026-10-18, offline):
//   * id -> RVA: Linux-Native-Tools/tools/steamstub-rtti/addrlib.py on
//     versionlib-1-6-1170-0.bin (self-check id 38048 = 0x6A35F0 passed). Every
//     id/RVA pair below matches Docs/LT-1-contract-map.md.
//   * bytes: capstone over MFO binaries/1.6.1170/SkyrimSE.unpacked.exe
//     (SteamStub removed). Each call site is an instruction boundary in a
//     linear disassembly of its function, lies inside that function's .pdata
//     range, and is `E8 rel32` whose target is the listed callee.
//   * Signatures (register use read from the callee's own code, not a header):
//       13753 LoadFiles(dh, bool)                 rcx, dl            -> al (caller ignores)
//       13760 LoadFile(dh, TESFile*, bool first)  rcx, rdx, r8b      -> al
//       13763 LoadRecord(dh, file, first, p, b)   rcx,rdx,r8b,r9 + ONE stack byte [rsp+0x20]
//             (read at 0x1BC033: cmp byte [rbp+0x140],0)            -> al
//       13690 LoadForm(TESForm*, TESFile*)        rcx, rdx           -> eax (movzx of Load's al)
//       13991 TESFile::ReadData(file, buf, size)  rcx, rdx, r8d      -> al; no r9 / stack args read
//       14032 TESFile inflate(file)               rcx only; all 3 callers ignore rax and re-read +0x4A0
//       13784 InitItem pass(dh)                   rcx only; caller ignores rax
//   The thunks forward all four integer argument registers as full 64-bit
//   values (and the 5th stack slot for 13763) and return rax untouched, so an
//   over-declared argument is harmless and no argument is ever narrowed.
//   None of these functions takes a floating-point argument.
//
// The runtime re-checks all of this at install (Probe.cpp): Address Library
// offset == rva below, the E8 byte, the rel32 target, and the full 16-byte
// prologue for the one entry detour. Any mismatch => that group is not
// installed (and if the GATE fails, nothing is installed). Never a crash.

#include <array>
#include <cstddef>
#include <cstdint>

namespace lt::sites
{
	struct Fn
	{
		std::uint64_t  id;
		std::uintptr_t rva;
		const char*    name;
	};

	struct CallSite
	{
		std::uint64_t  fnId;    // id of the function CONTAINING the call
		std::uintptr_t fnRva;   // its RVA (checked against the Address Library)
		std::uintptr_t off;     // offset of the E8 inside it
		std::uintptr_t siteRva; // fnRva + off, spelled out so a typo cannot hide
		const char*    name;
	};

	[[nodiscard]] constexpr bool Consistent(const CallSite& a_s) noexcept { return a_s.fnRva + a_s.off == a_s.siteRva; }

	template <std::size_t N>
	[[nodiscard]] constexpr bool AllConsistent(const std::array<CallSite, N>& a_sites) noexcept
	{
		for (const auto& s : a_sites) {
			if (!Consistent(s)) {
				return false;
			}
		}
		return true;
	}

	// ---- callees ------------------------------------------------------------
	inline constexpr Fn kLoadFiles{ 13753, 0x1B96E0, "LoadFiles (13753)" };
	inline constexpr Fn kLoadFile{ 13760, 0x1BB6C0, "per-plugin loader (13760)" };
	inline constexpr Fn kLoadRecord{ 13763, 0x1BBAA0, "per-record dispatcher (13763)" };
	inline constexpr Fn kLoadForm{ 13690, 0x1B11F0, "Load wrapper (13690)" };
	inline constexpr Fn kReadData{ 13991, 0x1C8640, "TESFile::ReadData (13991)" };
	inline constexpr Fn kInflate{ 14032, 0x1C9790, "TESFile inflate (14032)" };
	inline constexpr Fn kInitItems{ 13784, 0x1BE0F0, "InitItem pass (13784)" };

	// ---- GATE: the startup LoadFiles call. 13753 has three callers
	// (0x642F11, 0x6492FC, 0x942CFF); the one in the InitTES body is the
	// startup data load ([I] for the other two: their callers were not traced),
	// so gating on THIS call site (one-shot) measures startup only.
	// bytes: E8 CA 67 B7 FF -> 0x1B96E0
	inline constexpr CallSite kGateSite{ 36553, 0x642BD0, 0x341, 0x642F11, "InitTES -> LoadFiles" };

	// ---- per-plugin: both 13760 calls inside 13753 (the file loop, and the
	// trailing activeFile call). The third caller, 0x1BEE07 in 13785, is the
	// runtime path and is deliberately NOT hooked.
	// bytes: E8 B8 1C 00 00 / E8 98 1C 00 00 -> 0x1BB6C0
	inline constexpr std::array<CallSite, 2> kPerPluginSites{ {
		{ 13753, 0x1B96E0, 0x323, 0x1B9A03, "LoadFiles file loop -> 13760" },
		{ 13753, 0x1B96E0, 0x343, 0x1B9A23, "LoadFiles activeFile -> 13760" },
	} };

	// ---- per-record: the R6 call in 13760. bytes: E8 6A 01 00 00 -> 0x1BBAA0
	// Seven other callers of 13763 (cell reload, save load, ...) are not hooked.
	inline constexpr CallSite kRecordSite{ 13760, 0x1BB6C0, 0x271, 0x1BB931, "13760 R6 -> 13763" };

	// ---- Load bodies: all 16 calls of 13690 inside 13763 (every one E8 ->
	// 0x1B11F0; no jmp tail-calls to it in 13763). The 17th caller, 0x306C00 in
	// 0x306A50, is outside the record dispatcher and not hooked.
	inline constexpr std::array<CallSite, 16> kLoadFormSites{ {
		{ 13763, 0x1BBAA0, 0x450, 0x1BBEF0, "13763+0x450" },
		{ 13763, 0x1BBAA0, 0x4BB, 0x1BBF5B, "13763+0x4BB" },
		{ 13763, 0x1BBAA0, 0x631, 0x1BC0D1, "13763+0x631" },
		{ 13763, 0x1BBAA0, 0x9BF, 0x1BC45F, "13763+0x9BF" },
		{ 13763, 0x1BBAA0, 0xA8B, 0x1BC52B, "13763+0xA8B" },
		{ 13763, 0x1BBAA0, 0xAE5, 0x1BC585, "13763+0xAE5" },
		{ 13763, 0x1BBAA0, 0xB41, 0x1BC5E1, "13763+0xB41" },
		{ 13763, 0x1BBAA0, 0xBAF, 0x1BC64F, "13763+0xBAF" },
		{ 13763, 0x1BBAA0, 0xC09, 0x1BC6A9, "13763+0xC09" },
		{ 13763, 0x1BBAA0, 0xC2B, 0x1BC6CB, "13763+0xC2B" },
		{ 13763, 0x1BBAA0, 0xC41, 0x1BC6E1, "13763+0xC41" },
		{ 13763, 0x1BBAA0, 0xCB7, 0x1BC757, "13763+0xCB7" },
		{ 13763, 0x1BBAA0, 0xE18, 0x1BC8B8, "13763+0xE18" },
		{ 13763, 0x1BBAA0, 0xE5B, 0x1BC8FB, "13763+0xE5B" },
		{ 13763, 0x1BBAA0, 0xE6F, 0x1BC90F, "13763+0xE6F" },
		{ 13763, 0x1BBAA0, 0xEA0, 0x1BC940, "13763+0xEA0 (default case, 13763.h)" },
	} };

	// ---- inflate: the THREE callers of 14032 (LT-1 section 3), all E8.
	// index order is used by the per-caller counters in the report.
	// bytes: E8 71 0F 00 00 / E8 36 00 00 00 / E8 3A FB FF FF -> 0x1C9790
	inline constexpr std::array<CallSite, 3> kInflateSites{ {
		{ 13991, 0x1C8640, 0x1DA, 0x1C881A, "ReadData(13991)+0x1DA" },
		{ 14029, 0x1C9740, 0x015, 0x1C9755, "14029+0x15" },
		{ 14034, 0x1C9C10, 0x041, 0x1C9C51, "14034+0x41 (subrecord header path)" },
	} };

	// ---- post-loop InitItem pass. bytes: E8 A8 46 00 00 -> 0x1BE0F0
	inline constexpr CallSite kInitItemsSite{ 13753, 0x1B96E0, 0x363, 0x1B9A43, "LoadFiles -> 13784" };

	// ---- raw read: TESFile::ReadData has ~900 direct call sites (every form
	// type's Load), so a call-site hook is impractical; this one is an ENTRY
	// detour. The first instruction is exactly 5 bytes and position-independent
	// (`mov [rsp+10h], rbx`), so the stolen bytes are one whole instruction and
	// the gateway is that instruction + an absolute jmp back to entry+5. The
	// whole 16-byte prologue is checked at install by FNV-1a 64-bit hash (catches
	// another detour; no game bytes are stored in this repo). The stolen
	// instruction itself is copied from the live process at install.
	inline constexpr std::size_t kReadDataPrologueLen = 16;
	inline constexpr std::uint64_t kReadDataPrologueHash = 0x46ede9c9b95d4a00ULL;
	constexpr std::uint64_t Fnv1a64(const std::uint8_t* a_p, std::size_t a_n) noexcept
	{
		std::uint64_t h = 0xcbf29ce484222325ULL;
		for (std::size_t i = 0; i < a_n; ++i) {
			h ^= a_p[i];
			h *= 0x100000001b3ULL;
		}
		return h;
	}
	inline constexpr std::size_t kReadDataStolen = 5;

	static_assert(Consistent(kGateSite));
	static_assert(AllConsistent(kPerPluginSites));
	static_assert(Consistent(kRecordSite));
	static_assert(AllConsistent(kLoadFormSites));
	static_assert(AllConsistent(kInflateSites));
	static_assert(Consistent(kInitItemsSite));
	static_assert(kReadDataStolen >= 5 && kReadDataStolen <= kReadDataPrologueLen);

	// =========================================================================
	// v2 (LT-2b) sites. Provenance (2026-10-18, offline, same tools and files as
	// above): every row was produced from a linear capstone disassembly of the
	// containing function (start = Address Library offset, end = its .pdata
	// chunk), so each site is an instruction boundary inside that function.
	// For E8 rows the rel32 target was resolved and mapped back to the callee
	// id. Register use of every callee wrapped by the generic 4-register thunk
	// was read at its entry: none reads a stack argument (5th+) or an xmm
	// argument, and no caller reads xmm0 after the call; the callers set only
	// rcx/rdx/r8/r9 before each of these calls (no [rsp+20h+] argument store).
	// The one variadic/stack-arg callee in 13760 (12920, progress text, takes a
	// 5th stack arg) is deliberately NOT wrapped.
	//
	// RE-VALIDATED 2026-10-19 (LT-2b milestone 1, scripted cross-check of every
	// row below against the unpacked exe, the -0.bin Address Library and .pdata):
	//   * all 54 Fn id -> rva pairs match the Address Library;
	//   * all 55 kTimedSites rows: instruction boundary, inside the primary .pdata
	//     chunk of fnId (13753 / 13784 / 13760 / 13763 are each ONE chunk), `E8
	//     rel32` (5 bytes) whose target == callee.rva. 0 rows removed;
	//   * the call lists of 13753 and 13784 are COMPLETE: 13753 has exactly these
	//     25 + the 3 v1 E8 calls and no other call instruction; 13784 has these 22
	//     E8 calls, the 6 kVfSites, and the 3-byte `call [rax+20h]` at 0x1BE2A2;
	//   * no callee reads a stack argument (5th+) or xmm0-3 on entry (whole-chunk
	//     scan; leaf callees 13281/14001/14006/14008/13964/18779/27202/35984/35993
	//     have no .pdata and were read to their ret). The only [rsp+20h+] stores
	//     before these calls are the callers' own locals (EH state marker, the P9
	//     visitor object whose ADDRESS goes in rdx, P10 locals), not arguments.
	//     The control: the same scan does flag 13763's known 5th byte (0x1BC033).
	// =========================================================================

	// LoadFiles (13753) segments, entered monotonically at the marked sites.
	// The wall of every segment sums exactly to the LoadFiles total.
	enum LfSeg : std::int8_t
	{
		kLfNone = -1,
		kLfSetup = 0,  // entry .. file loop: 13295 world reset, 13281, 13936/13945 (only if dh+0xDA2), active-file precheck
		kLfFileLoop,   // per-file flags, 13741 compile index, 453528 BSA name gate, 13786 BSA auto-load (+ activeFile)
		kLfPass1,      // pass 1: OpenTES (13931) on compiledFileCollection.files then .smallFiles, += HEDR record count
		kLfHardcoded,  // 13698: the hard-coded forms (startup only)
		kLfBuf1,       // 13767(dh, -3)
		kLfPlugins,    // the plugin loop: 13964 filter + 13760 per plugin (+ activeFile)
		kLfBuf2,       // 13767(*400269, -1)
		kLfInitItems,  // 13784 InitItem pass
		kLfNavTail,    // 13403 + 30433 navmesh-info graph
		kLfSegCount
	};

	// InitItem pass (13784) phases (Docs/LT-1b-inititem-map.md section A).
	enum IiPhase : std::int8_t
	{
		kIiNone = -1,
		kIiDobj = 0,  // P0  13894 + DOBJ InitItem
		kIiFlst,      // P1  formArrays[FLST] loop
		kIiMisc,      // P2  Calendar 36289 (if null), 18779 fix-up, IOManager 75708(...,5)
		kIiCore,      // P3  the core loop over formArrays[0..0x89] (not SCPT/WRLD/FLST)
		kIiAvif,      // P4  27202(i)->InitItem for i < 0xA4
		kIiNpc,       // P5  NPC_ post pass (actorData vfunc + 24787)
		kIiRace,      // P6  RACE post pass (25362)
		kIiNavi,      // P7  13403 NavMeshInfoMap + its InitItem
		kIiWrld,      // P8  formArrays[WRLD] InitItem (persistent + child cells, their refs)
		kIiCells,     // P9  20544, interior cells: 18882 per cell (refs)
		kIiTail,      // P10 24591, 20683, 11160, 24527, RACE sort 13796, 35994
		kIiPhaseCount
	};

	enum class Owner : std::uint8_t
	{
		kLoadFiles,   // direct callee of 13753          (group lfCallees, segments = LfSeg)
		kInitPass,    // direct callee of 13784          (group initPass,  segments = IiPhase)
		kPluginLoop,  // direct callee of 13760          (group loopSplit, per-plugin slot columns)
		kRecord       // 13763 -> AddFormToDataHandler   (group newForms)
	};

	// Which argument register carries the plugin, for the per-file columns.
	enum class FileArg : std::uint8_t
	{
		kNone,
		kRcx,      // rcx = TESFile*
		kRdx,      // rdx = TESFile*
		kRcxName   // rcx = &file->fileName (file + 0x58) [V: `lea rcx,[rdi+58h]` at both call sites]
	};

	enum class Col : std::uint8_t
	{
		kNone,
		kCompileIdx,  // 13741 compile-index assignment     (per file)
		kBsaGate,     // 453528 BSA name-list gate; al != 0  (per file)
		kBsaLoad,     // 13786 per-plugin BSA auto-load      (per file)
		kPass1Open,   // pass-1 OpenTES                       (per file)
		kOpen2,       // 13760 F0 OpenTES (second open)       (per slot)
		kHeader,      // 13760 F0 13883 TES4 header + masters (per slot)
		kMisc,        // 13760 15469 (only if 14009(file))    (per slot)
		kSeek,        // 13760 R1 SeekNextForm 13979          (per slot)
		kR7Lookup,    // 13760 R7 LookupByID                  (per slot)
		kEdidInsert,  // 13760 R7 13907 editor-ID map insert  (per slot)
		kClose,       // 13760 F2 CloseTES 13933              (per slot)
		kNewForm      // 13763.i AddFormToDataHandler: count by the new form's type (rdx)
	};

	struct TimedSite
	{
		CallSite     site;
		Fn           callee;    // the verified E8 target
		Owner        owner;
		std::int8_t  segEntry;  // LfSeg / IiPhase entered when the call starts (-1: none)
		std::int8_t  segExit;   // ... entered when it returns (-1: none)
		FileArg      file;
		Col          col;
	};

	// callees (id, rva) of the v2 rows; each id -> rva pair is re-checked at install.
	inline constexpr Fn kF13295{ 13295, 0x19C4E0, "13295 TES world reset" };
	inline constexpr Fn kF13281{ 13281, 0x19ABB0, "13281" };
	inline constexpr Fn kF13936{ 13936, 0x1C58D0, "13936 (if dh+0xDA2)" };
	inline constexpr Fn kF13945{ 13945, 0x1C6430, "13945 (if dh+0xDA2)" };
	inline constexpr Fn kF14006{ 14006, 0x1C8E40, "14006 file flag" };
	inline constexpr Fn kF13960{ 13960, 0x1C6E90, "13960 file flag" };
	inline constexpr Fn kF14001{ 14001, 0x1C8D10, "14001 file flag" };
	inline constexpr Fn kF13958{ 13958, 0x1C6D40, "13958" };
	inline constexpr Fn kF14008{ 14008, 0x1C8EE0, "14008 file flag" };
	inline constexpr Fn kF13741{ 13741, 0x1B8580, "13741 compile index" };
	inline constexpr Fn kF453528{ 453528, 0x152D900, "453528 BSA name gate" };
	inline constexpr Fn kF13786{ 13786, 0x1BF710, "13786 BSA auto-load" };
	inline constexpr Fn kF13931{ 13931, 0x1C4DA0, "13931 OpenTES" };
	inline constexpr Fn kF13698{ 13698, 0x1B1D30, "13698 hard-coded forms" };
	inline constexpr Fn kF13767{ 13767, 0x1BCC30, "13767 buffer housekeeping" };
	inline constexpr Fn kF13964{ 13964, 0x1C7040, "13964 has compile index" };
	inline constexpr Fn kF13403{ 13403, 0x1A3EA0, "13403 NavMeshInfoMap get/create" };
	inline constexpr Fn kF30433{ 30433, 0x4C0E00, "30433 navmesh graph build" };
	inline constexpr Fn kF13894{ 13894, 0x1C2E70, "13894 DefaultObjectManager singleton" };
	inline constexpr Fn kF36289{ 36289, 0x633170, "36289 Calendar create (if null)" };
	inline constexpr Fn kF18779{ 18779, 0x2ACAB0, "18779" };
	inline constexpr Fn kF75708{ 75708, 0xE01800, "75708 IOManager(...,5)" };
	inline constexpr Fn kF27202{ 27202, 0x43BE70, "27202 ActorValueInfo(i)" };
	inline constexpr Fn kF24787{ 24787, 0x3C1A00, "24787 NPC_ post init" };
	inline constexpr Fn kF25362{ 25362, 0x3E03C0, "25362 RACE post init" };
	inline constexpr Fn kF20544{ 20544, 0x30B180, "20544" };
	inline constexpr Fn kF35993{ 35993, 0x624D30, "35993 visitor ctor" };
	inline constexpr Fn kF35984{ 35984, 0x624880, "35984" };
	inline constexpr Fn kF18882{ 18882, 0x2B3260, "18882 interior cell init (refs)" };
	inline constexpr Fn kF68146{ 68146, 0xCC5AD0, "68146 free" };
	inline constexpr Fn kF24591{ 24591, 0x3B1560, "24591(400451)" };
	inline constexpr Fn kF20683{ 20683, 0x3119F0, "20683(401131)" };
	inline constexpr Fn kF11160{ 11160, 0x147F80, "11160" };
	inline constexpr Fn kF24527{ 24527, 0x3AE5C0, "24527" };
	inline constexpr Fn kF13796{ 13796, 0x1BFD50, "13796 RACE array sort" };
	inline constexpr Fn kF35994{ 35994, 0x624D60, "35994 visitor dtor" };
	inline constexpr Fn kF13883{ 13883, 0x1C27E0, "13883 TES4 header + master table" };
	inline constexpr Fn kF15469{ 15469, 0x208690, "15469 (if 14009)" };
	inline constexpr Fn kF13979{ 13979, 0x1C7D30, "13979 SeekNextForm" };
	inline constexpr Fn kF14617{ 14617, 0x1E01A0, "14617 LookupByID" };
	inline constexpr Fn kF13907{ 13907, 0x1C3E00, "13907 editor-ID map insert" };
	inline constexpr Fn kF13933{ 13933, 0x1C5580, "13933 CloseTES" };
	inline constexpr Fn kF13693{ 13693, 0x1B14C0, "13693 AddFormToDataHandler" };

	// Shorthands for the table below.
	inline constexpr auto kLF = Owner::kLoadFiles;
	inline constexpr auto kIP = Owner::kInitPass;
	inline constexpr auto kPL = Owner::kPluginLoop;
	inline constexpr auto kRC = Owner::kRecord;

	// Every E8 call made directly by 13753 in code order (except the three v1
	// sites 0x1B9A03 / 0x1B9A23 -> 13760 and 0x1B9A43 -> 13784, which keep their
	// v1 thunks and feed the same table), every E8 call made directly by 13784,
	// the 13760 internals worth splitting, and the 13763 new-form insert.
	// 13784 also makes six virtual InitItem calls (kVfSites) and one 3-byte
	// `call [rax+20h]` at 0x1BE2A2 (NPC_ actorData vfunc; not hookable, lands in
	// the P5 wall). The ONLY other call instructions in 13753 are the three v1
	// sites; 13753 has no indirect calls [V].
	inline constexpr std::array<TimedSite, 55> kTimedSites{ {
		// ---- 13753 LoadFiles (25 sites + 3 v1 sites) ----
		{ { 13753, 0x1B96E0, 0x06F, 0x1B974F, "LF+0x06F" }, kF13295, kLF, kLfSetup, -1, FileArg::kNone, Col::kNone },
		{ { 13753, 0x1B96E0, 0x09E, 0x1B977E, "LF+0x09E" }, kF13281, kLF, -1, -1, FileArg::kNone, Col::kNone },
		{ { 13753, 0x1B96E0, 0x0C9, 0x1B97A9, "LF+0x0C9" }, kF13936, kLF, -1, -1, FileArg::kNone, Col::kNone },
		{ { 13753, 0x1B96E0, 0x0DB, 0x1B97BB, "LF+0x0DB" }, kF13945, kLF, -1, -1, FileArg::kNone, Col::kNone },
		{ { 13753, 0x1B96E0, 0x0F3, 0x1B97D3, "LF+0x0F3 precheck" }, kF14006, kLF, -1, -1, FileArg::kNone, Col::kNone },
		{ { 13753, 0x1B96E0, 0x0FF, 0x1B97DF, "LF+0x0FF precheck" }, kF13960, kLF, -1, -1, FileArg::kNone, Col::kNone },
		{ { 13753, 0x1B96E0, 0x14E, 0x1B982E, "LF+0x14E file loop" }, kF14006, kLF, kLfFileLoop, -1, FileArg::kNone, Col::kNone },
		{ { 13753, 0x1B96E0, 0x15A, 0x1B983A, "LF+0x15A file loop" }, kF14001, kLF, kLfFileLoop, -1, FileArg::kNone, Col::kNone },
		{ { 13753, 0x1B96E0, 0x16F, 0x1B984F, "LF+0x16F file loop" }, kF13958, kLF, kLfFileLoop, -1, FileArg::kNone, Col::kNone },
		{ { 13753, 0x1B96E0, 0x177, 0x1B9857, "LF+0x177 file loop" }, kF14008, kLF, kLfFileLoop, -1, FileArg::kNone, Col::kNone },
		{ { 13753, 0x1B96E0, 0x18F, 0x1B986F, "LF+0x18F file loop" }, kF13741, kLF, kLfFileLoop, -1, FileArg::kRdx, Col::kCompileIdx },
		{ { 13753, 0x1B96E0, 0x198, 0x1B9878, "LF+0x198 file loop" }, kF453528, kLF, kLfFileLoop, -1, FileArg::kRcxName, Col::kBsaGate },
		{ { 13753, 0x1B96E0, 0x1A5, 0x1B9885, "LF+0x1A5 file loop" }, kF13786, kLF, kLfFileLoop, -1, FileArg::kRcxName, Col::kBsaLoad },
		{ { 13753, 0x1B96E0, 0x1E5, 0x1B98C5, "LF+0x1E5 activeFile" }, kF13741, kLF, kLfFileLoop, -1, FileArg::kRdx, Col::kCompileIdx },
		{ { 13753, 0x1B96E0, 0x1F1, 0x1B98D1, "LF+0x1F1 activeFile" }, kF453528, kLF, kLfFileLoop, -1, FileArg::kRcxName, Col::kBsaGate },
		{ { 13753, 0x1B96E0, 0x1FD, 0x1B98DD, "LF+0x1FD activeFile" }, kF13786, kLF, kLfFileLoop, -1, FileArg::kRcxName, Col::kBsaLoad },
		{ { 13753, 0x1B96E0, 0x23B, 0x1B991B, "LF+0x23B pass1 files" }, kF13931, kLF, kLfPass1, -1, FileArg::kRcx, Col::kPass1Open },
		{ { 13753, 0x1B96E0, 0x28B, 0x1B996B, "LF+0x28B pass1 smallFiles" }, kF13931, kLF, kLfPass1, -1, FileArg::kRcx, Col::kPass1Open },
		{ { 13753, 0x1B96E0, 0x2B8, 0x1B9998, "LF+0x2B8" }, kF13698, kLF, kLfHardcoded, -1, FileArg::kNone, Col::kNone },
		{ { 13753, 0x1B96E0, 0x2DC, 0x1B99BC, "LF+0x2DC (-3)" }, kF13767, kLF, kLfBuf1, -1, FileArg::kNone, Col::kNone },
		{ { 13753, 0x1B96E0, 0x307, 0x1B99E7, "LF+0x307 plugin loop" }, kF13964, kLF, kLfPlugins, -1, FileArg::kNone, Col::kNone },
		{ { 13753, 0x1B96E0, 0x354, 0x1B9A34, "LF+0x354 (-1)" }, kF13767, kLF, kLfBuf2, -1, FileArg::kNone, Col::kNone },
		{ { 13753, 0x1B96E0, 0x36F, 0x1B9A4F, "LF+0x36F" }, kF13403, kLF, kLfNavTail, -1, FileArg::kNone, Col::kNone },
		{ { 13753, 0x1B96E0, 0x385, 0x1B9A65, "LF+0x385 (if NAVI flag bit1)" }, kF13403, kLF, kLfNavTail, -1, FileArg::kNone, Col::kNone },
		{ { 13753, 0x1B96E0, 0x391, 0x1B9A71, "LF+0x391 (if NAVI flag bit1)" }, kF30433, kLF, kLfNavTail, -1, FileArg::kNone, Col::kNone },
		// ---- 13784 InitItem pass (22 E8 sites) ----
		{ { 13784, 0x1BE0F0, 0x021, 0x1BE111, "II+0x021 P0" }, kF13894, kIP, kIiDobj, -1, FileArg::kNone, Col::kNone },
		{ { 13784, 0x1BE0F0, 0x091, 0x1BE181, "II+0x091 P2" }, kF36289, kIP, kIiMisc, -1, FileArg::kNone, Col::kNone },
		{ { 13784, 0x1BE0F0, 0x09D, 0x1BE18D, "II+0x09D P2" }, kF18779, kIP, kIiMisc, -1, FileArg::kNone, Col::kNone },
		{ { 13784, 0x1BE0F0, 0x0A7, 0x1BE197, "II+0x0A7 P2" }, kF13894, kIP, -1, -1, FileArg::kNone, Col::kNone },
		{ { 13784, 0x1BE0F0, 0x0C1, 0x1BE1B1, "II+0x0C1 P2" }, kF18779, kIP, -1, -1, FileArg::kNone, Col::kNone },
		{ { 13784, 0x1BE0F0, 0x0D6, 0x1BE1C6, "II+0x0D6 P2 (exit -> P3)" }, kF75708, kIP, kIiMisc, kIiCore, FileArg::kNone, Col::kNone },
		{ { 13784, 0x1BE0F0, 0x152, 0x1BE242, "II+0x152 P4 x0xA4" }, kF27202, kIP, kIiAvif, -1, FileArg::kNone, Col::kNone },
		{ { 13784, 0x1BE0F0, 0x1B8, 0x1BE2A8, "II+0x1B8 P5 per NPC_" }, kF24787, kIP, kIiNpc, -1, FileArg::kNone, Col::kNone },
		{ { 13784, 0x1BE0F0, 0x1F1, 0x1BE2E1, "II+0x1F1 P6 per RACE" }, kF25362, kIP, kIiRace, -1, FileArg::kNone, Col::kNone },
		{ { 13784, 0x1BE0F0, 0x203, 0x1BE2F3, "II+0x203 P7" }, kF13403, kIP, kIiNavi, -1, FileArg::kNone, Col::kNone },
		{ { 13784, 0x1BE0F0, 0x214, 0x1BE304, "II+0x214 P7 (if map)" }, kF13403, kIP, kIiNavi, -1, FileArg::kNone, Col::kNone },
		{ { 13784, 0x1BE0F0, 0x271, 0x1BE361, "II+0x271 P9" }, kF20544, kIP, kIiCells, -1, FileArg::kNone, Col::kNone },
		{ { 13784, 0x1BE0F0, 0x27B, 0x1BE36B, "II+0x27B P9" }, kF35993, kIP, kIiCells, -1, FileArg::kNone, Col::kNone },
		{ { 13784, 0x1BE0F0, 0x286, 0x1BE376, "II+0x286 P9" }, kF35984, kIP, kIiCells, -1, FileArg::kNone, Col::kNone },
		{ { 13784, 0x1BE0F0, 0x2C5, 0x1BE3B5, "II+0x2C5 P9 per interior cell" }, kF18882, kIP, kIiCells, -1, FileArg::kNone, Col::kNone },
		{ { 13784, 0x1BE0F0, 0x2DC, 0x1BE3CC, "II+0x2DC P9" }, kF68146, kIP, kIiCells, -1, FileArg::kNone, Col::kNone },
		{ { 13784, 0x1BE0F0, 0x2FC, 0x1BE3EC, "II+0x2FC P10" }, kF24591, kIP, kIiTail, -1, FileArg::kNone, Col::kNone },
		{ { 13784, 0x1BE0F0, 0x308, 0x1BE3F8, "II+0x308 P10" }, kF20683, kIP, kIiTail, -1, FileArg::kNone, Col::kNone },
		{ { 13784, 0x1BE0F0, 0x30D, 0x1BE3FD, "II+0x30D P10" }, kF11160, kIP, kIiTail, -1, FileArg::kNone, Col::kNone },
		{ { 13784, 0x1BE0F0, 0x312, 0x1BE402, "II+0x312 P10" }, kF24527, kIP, kIiTail, -1, FileArg::kNone, Col::kNone },
		{ { 13784, 0x1BE0F0, 0x331, 0x1BE421, "II+0x331 P10 (if >1 RACE)" }, kF13796, kIP, kIiTail, -1, FileArg::kNone, Col::kNone },
		{ { 13784, 0x1BE0F0, 0x342, 0x1BE432, "II+0x342 P10" }, kF35994, kIP, kIiTail, -1, FileArg::kNone, Col::kNone },
		// ---- 13760 per-plugin loader internals (7 sites; 12920 skipped, see above) ----
		{ { 13760, 0x1BB6C0, 0x03C, 0x1BB6FC, "13760+0x03C F0 OpenTES" }, kF13931, kPL, -1, -1, FileArg::kNone, Col::kOpen2 },
		{ { 13760, 0x1BB6C0, 0x044, 0x1BB704, "13760+0x044 F0 header" }, kF13883, kPL, -1, -1, FileArg::kNone, Col::kHeader },
		{ { 13760, 0x1BB6C0, 0x073, 0x1BB733, "13760+0x073 15469" }, kF15469, kPL, -1, -1, FileArg::kNone, Col::kMisc },
		{ { 13760, 0x1BB6C0, 0x285, 0x1BB945, "13760+0x285 R7 LookupByID" }, kF14617, kPL, -1, -1, FileArg::kNone, Col::kR7Lookup },
		{ { 13760, 0x1BB6C0, 0x2DE, 0x1BB99E, "13760+0x2DE R7 editor-ID insert" }, kF13907, kPL, -1, -1, FileArg::kNone, Col::kEdidInsert },
		{ { 13760, 0x1BB6C0, 0x353, 0x1BBA13, "13760+0x353 R1 SeekNextForm" }, kF13979, kPL, -1, -1, FileArg::kNone, Col::kSeek },
		{ { 13760, 0x1BB6C0, 0x371, 0x1BBA31, "13760+0x371 F2 CloseTES" }, kF13933, kPL, -1, -1, FileArg::kNone, Col::kClose },
		// ---- 13763 default case: new form only (`test rbx,rbx; jne` skips it for an override) ----
		{ { 13763, 0x1BBAA0, 0xEB0, 0x1BC950, "13763+0xEB0 AddFormToDataHandler (new form)" }, kF13693, kRC, -1, -1, FileArg::kNone, Col::kNewForm },
	} };

	[[nodiscard]] constexpr bool TimedConsistent() noexcept
	{
		for (const auto& t : kTimedSites) {
			if (!Consistent(t.site)) {
				return false;
			}
			if (t.owner == Owner::kLoadFiles && t.site.fnId != 13753) {
				return false;
			}
			if (t.owner == Owner::kInitPass && t.site.fnId != 13784) {
				return false;
			}
			if (t.owner == Owner::kPluginLoop && t.site.fnId != 13760) {
				return false;
			}
			if (t.owner == Owner::kLoadFiles && (t.segEntry >= kLfSegCount || t.segExit >= kLfSegCount)) {
				return false;
			}
			if (t.owner == Owner::kInitPass && (t.segEntry >= kIiPhaseCount || t.segExit >= kIiPhaseCount)) {
				return false;
			}
		}
		return true;
	}
	static_assert(TimedConsistent());

	// ---- the six virtual InitItem calls in 13784 and the four ref/cell ones.
	// Every site is `FF 90 98 00 00 00` (call [rax+98h]) or `FF 92 98 00 00 00`
	// (call [rdx+98h]) = slot 0x13 InitItemImpl, and the `pre` bytes before it
	// load that vtable register from [rcx]:
	//   FF 92 sites: `mov rdx,[rax]; mov rcx,rax`         (pre = 6)
	//   FF 90 sites in 13784: `mov rcx,[rbx]; mov rax,[rcx]` (pre = 6)
	//   FF 90 sites in 18882: `mov rax,[rbx]; mov rcx,rbx` (pre = 6)
	//   FF 90 sites in 20455/20563: `mov rax,[rcx]`        (pre = 3)
	// so `vtbl == *(void**)rcx` holds at the call, and the thunk performs the
	// same call `(*(fn**)(*(char**)rcx + 0x98))(rcx, rdx, r8, r9)`. No branch
	// in the containing function targets the bytes after the window start [V].
	// The [site-pre, site+6) window is checked at install by FNV-1a 64 hash.
	// RE-VALIDATED 2026-10-19: all 10 are 6-byte `call qword ptr [rax|rdx+98h]`,
	// the pre bytes are whole instructions and load that register from [rcx],
	// no branch in the containing function targets (site-pre, site], and every
	// windowHash below was recomputed (0x306496 / 0x30CE4C were placeholders;
	// their real value is 0x12968933da5cb618, the same 9 bytes at both sites).
	// PATCH: prefer SKSE::Trampoline::write_call<6>, which writes `FF 15 disp32`
	// (call [rip+disp] -> an 8-byte slot holding the thunk), so the return
	// address stays site+6 exactly as in the original. TRAP: its return value is
	// computed as if the site were already rip-relative (site + 6 + disp32 =
	// site + 6 + 0x98 here): it is GARBAGE for these sites and must be ignored;
	// the original target is per-object, read in the thunk from *(void**)rcx.
	// Alternative: `E8 rel32` + `90` (return address site+5, the nop, still
	// inside the original instruction's bytes; unwind/EH state is unchanged).
	enum class VfKind : std::uint8_t
	{
		kDobj,          // P0  DOBJ InitItem                     -> exit enters P1
		kFlst,          // P1  formArrays[FLST]
		kCore,          // P3  the core loop
		kAvif,          // P4  ActorValueInfo x0xA4             -> the 0xA4-th return enters P5
		kNavi,          // P7  NavMeshInfoMap InitItem          -> exit enters P8
		kWrld,          // P8  formArrays[WRLD]                 -> entry enters P8
		kWrldPersistent,  // inside WRLD InitItem 20455: persistentCell (+0x88) InitItem
		kWrldChild,     // inside 20563 (called per WRLD child cell by 20455): child InitItem
		kCellRefA,      // inside 18882: refs of the cell (first list)
		kCellRefB       // inside 18882: refs of the cell (+0x80 list)
	};

	struct VfSite
	{
		CallSite      site;
		std::uint8_t  pre;
		std::uint64_t windowHash;  // FNV-1a 64 of [site - pre, site + 6)
		VfKind        kind;
		std::int8_t   phaseEntry;
		std::int8_t   phaseExit;
	};

	inline constexpr std::size_t kVfPassCount = 6;  // [0, 6) = group initPass, [6, 10) = group initRefs
	inline constexpr std::array<VfSite, 10> kVfSites{ {
		{ { 13784, 0x1BE0F0, 0x02C, 0x1BE11C, "II+0x02C P0 DOBJ" }, 6, 0x7b9b5cff0b134a26ULL, VfKind::kDobj, kIiDobj, kIiFlst },
		{ { 13784, 0x1BE0F0, 0x075, 0x1BE165, "II+0x075 P1 FLST" }, 6, 0xfb17aaa51e4d9db0ULL, VfKind::kFlst, kIiFlst, -1 },
		{ { 13784, 0x1BE0F0, 0x131, 0x1BE221, "II+0x131 P3 core" }, 6, 0xfb17aaa51e4d9db0ULL, VfKind::kCore, kIiCore, -1 },
		{ { 13784, 0x1BE0F0, 0x15D, 0x1BE24D, "II+0x15D P4 AVIF" }, 6, 0x7b9b5cff0b134a26ULL, VfKind::kAvif, kIiAvif, -1 },
		{ { 13784, 0x1BE0F0, 0x21F, 0x1BE30F, "II+0x21F P7 NAVI" }, 6, 0x7b9b5cff0b134a26ULL, VfKind::kNavi, kIiNavi, kIiWrld },
		{ { 13784, 0x1BE0F0, 0x265, 0x1BE355, "II+0x265 P8 WRLD" }, 6, 0xfb17aaa51e4d9db0ULL, VfKind::kWrld, kIiWrld, -1 },
		{ { 20455, 0x306050, 0x446, 0x306496, "20455+0x446 WRLD persistentCell" }, 3, 0x12968933da5cb618ULL, VfKind::kWrldPersistent, -1, -1 },
		{ { 20563, 0x30CE40, 0x00C, 0x30CE4C, "20563+0x00C WRLD child cell" }, 3, 0x12968933da5cb618ULL, VfKind::kWrldChild, -1, -1 },
		{ { 18882, 0x2B3260, 0x342, 0x2B35A2, "18882+0x342 cell ref (list A)" }, 6, 0x133127fc223d897aULL, VfKind::kCellRefA, -1, -1 },
		{ { 18882, 0x2B3260, 0x3FC, 0x2B365C, "18882+0x3FC cell ref (list B)" }, 6, 0x133127fc223d897aULL, VfKind::kCellRefB, -1, -1 },
	} };
	inline constexpr std::uint32_t kInitItemSlotOffset = 0x98;  // slot 0x13 * 8
	inline constexpr std::uint32_t kAvifCount = 0xA4;           // 13784 P4 loop bound [V cmp ebx,0A4h]

	[[nodiscard]] constexpr bool VfConsistent() noexcept
	{
		for (const auto& v : kVfSites) {
			if (!Consistent(v.site) || (v.pre != 3 && v.pre != 6)) {
				return false;
			}
		}
		return true;
	}
	static_assert(VfConsistent());

	// ---- DEFERRED, OFF, NOT COMPILED (LT-2b milestone 1). Kept for the record.
	// These rows validated (2026-10-19: AL ids, the E8 at 0x1E01CA -> 68233, the
	// 14617 / 68233 / 68234 16-byte prologue hashes all match) but are out of
	// this probe: the two lock functions are GLOBAL ENTRY detours on every
	// BSReadWriteLock of every thread for the whole session, and LookupByID is a
	// gameplay hot path on every thread. Re-enable only as their own INI-switched
	// group after a separate review. Nothing in Probe.cpp may reference them.
#if 0
	// ---- LookupByID counter: the E8 inside 14617 that takes allFormsMapLock
	// for read (`lea rsi,[allFormsMapLock]; mov rcx,rsi; call 68233`). Counting
	// here = one count per LookupByID call, scoped to LookupByID's own body.
	// The 16-byte entry of 14617 is hash-checked too: if another plugin has
	// replaced LookupByID (a jmp at its entry, e.g. a form-caching patch), this
	// call site is dead code and the group refuses rather than report zeros.
	inline constexpr Fn       kLockForRead{ 68233, 0xCC90C0, "BSReadWriteLock::LockForRead (68233)" };
	inline constexpr Fn       kLockForWrite{ 68234, 0xCC9140, "BSReadWriteLock::LockForWrite (68234)" };
	inline constexpr CallSite kLookupLockSite{ 14617, 0x1E01A0, 0x02A, 0x1E01CA, "LookupByID+0x2A -> LockForRead" };
	inline constexpr std::uint64_t kLookupEntryHash = 0xe3a9cdeaac0d248fULL;  // 16 bytes at 0x1E01A0
	static_assert(Consistent(kLookupLockSite));

	// ---- lock counters: ENTRY detours of the two BSReadWriteLock acquire
	// functions (used by every lock of that class, all threads). Both are
	// 16-aligned, so the 5-byte jmp lies inside one aligned qword and is
	// written with ONE atomic 8-byte store (another thread can never fetch a
	// half-written entry). Stolen bytes are whole, position-independent
	// instructions:
	//   68233: `push rdi; sub rsp,20h`  (2 + 4 = 6 bytes; byte 5 is never executed afterwards)
	//   68234: `mov [rsp+18h],rsi`       (5 bytes)
	// No rel32 branch in .text targets the first 8 bytes of either [V scan].
	// The lock word layout read by the thunk (writer thread id +0, count/flags
	// +4; write-held = 0x80000001) is the one these functions use [V].
	inline constexpr std::uint64_t kLockForReadPrologueHash = 0x37e509d3e3b6090eULL;   // 16 bytes
	inline constexpr std::uint64_t kLockForWritePrologueHash = 0x9cd2ee6912c756c1ULL;  // 16 bytes
	inline constexpr std::size_t   kLockForReadStolen = 6;
	inline constexpr std::size_t   kLockForWriteStolen = 5;
	inline constexpr Fn            kAllFormsMapLock{ 400517, 0x20FC018, "allFormsMapLock (400517)" };       // [V] lea in 14617
	inline constexpr Fn            kEditorIDMapLock{ 400518, 0x20FC020, "allFormsEditorIDMapLock (400518)" };  // [V] lea in 13760 R7
#endif
}
