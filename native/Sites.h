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
}
