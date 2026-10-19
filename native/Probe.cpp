#include "PCH.h"

#include "Probe.h"
#include "Sites.h"

// =============================================================================
// LT-2 stage-1 timing probe (PASSIVE). SkyrimSE 1.6.1170.0 only.
//
// What it answers: how the STARTUP data load (13753) splits between zlib
// inflate (14032), raw subrecord reads (13991), the per-form Load bodies
// (13690), the per-record dispatcher (13763), the per-plugin loop bookkeeping
// (13760) and the post-loop InitItem pass (13784). See Docs/LT-2-probe-howto.md.
//
// Passivity rules (Linux-Native-Tools/hook-site-verification.md):
//   * Every thunk calls the original with every argument register forwarded
//     unchanged and returns rax unchanged. No field is written. No vfunc is
//     called. Fields are only READ, and only through static_assert'ed offsets.
//   * No allocation, no lock, no file I/O inside a hot thunk. Accumulators are
//     preallocated at install and written by ONE thread (the load thread).
//   * Hook choice: CALL-SITE write_call<5> wherever the call sites are few and
//     verifiable (gate, 13760 x2, 13763 x1, 13690 x16, 14032 x3, 13784 x1).
//     That is the family's proven technique (known-hooks.md) and it scopes the
//     hook to the startup callers. The only ENTRY detour is 13991 ReadData,
//     because it has ~900 direct callers (one per form-type Load); its 5 stolen
//     bytes are one whole position-independent instruction (Sites.h).
//   * Every site is re-verified at install (Address Library offset, E8 byte,
//     rel32 target, or the full 16-byte prologue). Mismatch => that group is
//     not installed and the log says why; the game is never crashed for it.
//
// Gating: accumulation happens only between entry and exit of the 13753 call
// made by the InitTES body (the one startup call; Sites.h), and only on the
// thread that made that call. Calls from any other thread, before, during or
// after the window, are passed straight through (and counted while the probe
// is live). After the report every thunk is a pure pass-through ("unhook by
// flag"); the patched bytes stay, which is the normal SKSE practice.
// =============================================================================

// Every field the thunks read, pinned to the offsets read off the 1.6.1170
// disassembly ([V]) or the CommonLib header ([I], used only for diagnostics).
static_assert(offsetof(RE::TESFile, fileName) == 0x58);                    // [I] name, read at report time only
static_assert(offsetof(RE::TESFile, currentform) == 0x284);                // [V] 13760/14032 read +0x288/+0x28C/+0x290
static_assert(offsetof(RE::TESFile, fileOffset) == 0x2A8);                 // [I] diagnostic key only
static_assert(offsetof(RE::TESFile, decompressedFormBuffer) == 0x4A0);     // [V] 14032 writes it at 0x1C991F
static_assert(offsetof(RE::TESFile, decompressedFormBufferSize) == 0x4A8); // [V] 14032 writes it at 0x1C9926
static_assert(offsetof(RE::FORM, length) == 0x4);                          // [V] => +0x288, read by 14032
static_assert(offsetof(RE::FORM, flags) == 0x8);                           // [V] => +0x28C, ReadData tests 0x40000
static_assert(offsetof(RE::FORM, formID) == 0xC);                          // [V] => +0x290, read by 13760 R7

namespace lt::probe
{
	namespace
	{
		namespace sites = lt::sites;

		using Fn4 = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);
		using Fn5 = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);

		constexpr std::uint32_t kCompressedFlag = 0x40000;  // record flag tested by ReadData at 0x1C8674

		// ---- accumulators -------------------------------------------------------
		// Single-writer: only the load thread writes (enforced by Enter()), so a
		// plain load+store is exact, and the atomic type makes the report's
		// cross-thread read well-defined. On x64 both compile to plain movs.
		struct Acc
		{
			std::atomic<std::uint64_t> v{ 0 };
			void add(std::uint64_t a_d) noexcept { v.store(v.load(std::memory_order_relaxed) + a_d, std::memory_order_relaxed); }
			[[nodiscard]] std::uint64_t get() const noexcept { return v.load(std::memory_order_relaxed); }
		};

		// Multi-writer counter for the rare paths (foreign thread / outside window).
		struct Ctr
		{
			std::atomic<std::uint64_t> v{ 0 };
			void inc() noexcept { v.fetch_add(1, std::memory_order_relaxed); }
			[[nodiscard]] std::uint64_t get() const noexcept { return v.load(std::memory_order_relaxed); }
		};

		// One slot per plugin, in load order. Slot 0 = work inside the gate but
		// outside any 13760 call (pass 1 OpenTES, 13767, 13784, ...).
		struct Slot
		{
			std::atomic<const RE::TESFile*> file{ nullptr };
			Acc wall;        // 13760 inclusive ticks
			Acc loopEx;      // 13760 exclusive ticks (OpenTES, seek/header, R7 editor-ID, progress, CloseTES)
			Acc records;     // 13763 calls from the R6 site
			Acc compressed;  // ... whose record header carried the compressed flag
			Acc recEx;       // 13763 exclusive ticks
			Acc loadN;
			Acc loadEx;      // 13690 exclusive ticks (Load bodies minus nested reads/inflates)
			Acc readN;
			Acc readEx;      // 13991 exclusive ticks (minus nested inflate)
			Acc inflN;
			Acc inflEx;      // 14032 ticks (exclusive == inclusive unless something hooked nests in it)
			Acc inflIn;      // compressed bytes (record data size, +0x288 before the call)
			Acc inflOut;     // decompressed bytes (+0x4A8 after the call)
		};

		constexpr std::uint32_t kMaxSlots = 8192;  // > 254 full + 4096 light plugins

		enum Group : std::size_t
		{
			kGate,
			kPerPlugin,
			kRecord,
			kLoadBody,
			kRawRead,
			kInflate,
			kPostLoop,
			kGroupCount
		};

		constexpr std::array<const char*, kGroupCount> kGroupNames{
			"gate      13753 LoadFiles (startup call)",
			"perPlugin 13760 per-plugin loader",
			"record    13763 per-record dispatcher",
			"loadBody  13690 Load wrapper",
			"rawRead   13991 TESFile::ReadData",
			"inflate   14032 TESFile inflate",
			"postLoop  13784 InitItem pass",
		};

		struct GroupState
		{
			bool        requested = false;
			bool        installed = false;
			std::size_t sites = 0;
			std::string why;
			Acc         measured;  // calls measured (load thread, inside the window)
			Ctr         foreign;   // calls inside the window from another thread
			Ctr         outside;   // calls outside the window, before the report
		};

		// ---- state machine ------------------------------------------------------
		enum State : int
		{
			kIdle = 0,    // installed, startup LoadFiles not entered yet
			kArming = 1,  // gate thunk is filling the window fields
			kActive = 2,  // measuring
			kClosed = 3,  // LoadFiles returned; data frozen
			kDone = 4     // report written (or probe inactive): pure pass-through
		};

		std::atomic<int>           g_state{ kDone };  // kDone until Install succeeds
		std::atomic<std::uint32_t> g_loadTid{ 0 };
		std::atomic<bool>          g_dataLoadedSeen{ false };
		std::atomic<bool>          g_reported{ false };
		std::atomic<std::uint32_t> g_dataLoadedTid{ 0 };

		Config     g_cfg{};
		bool       g_gateInstalled = false;
		bool       g_gateChained = false;
		std::string g_inactiveWhy;
		GroupState g_grp[kGroupCount];

		// Originals (set before the site is patched; the VERIFIED target).
		std::uintptr_t g_origLoadFiles = 0;
		std::uintptr_t g_origLoadFile = 0;
		std::uintptr_t g_origLoadRecord = 0;
		std::uintptr_t g_origLoadForm = 0;
		std::uintptr_t g_origReadData = 0;  // the gateway (stolen bytes + jmp back)
		std::uintptr_t g_origInflate = 0;
		std::uintptr_t g_origInitItems = 0;

		// Load-thread-only working state (touched only after Enter() == measure).
		std::unique_ptr<Slot[]> g_slots;
		std::atomic<std::uint32_t> g_slotCount{ 1 };
		std::uint32_t g_cur = 0;     // current slot
		std::uint64_t g_child = 0;   // ticks spent in hooked children of the current scope

		// Window timing (written by the load thread before the kClosed store).
		std::uint64_t                         g_tsc0 = 0;
		std::uint64_t                         g_tsc1 = 0;
		std::chrono::steady_clock::time_point g_t0{};
		std::chrono::steady_clock::time_point g_t1{};
		Acc                                   g_loadFilesTicks;  // 13753 inclusive
		Acc                                   g_loadFilesEx;     // 13753 exclusive
		Acc                                   g_initItemsTicks;  // 13784 inclusive
		Acc                                   g_initItemsEx;     // 13784 exclusive
		Acc                                   g_slotOverflow;

		// Inflate diagnostics (LT-1 section 7 item 2).
		std::array<Acc, sites::kInflateSites.size()> g_inflBySite;
		Acc                                          g_inflPreset;       // entered with +0x4A0 already non-null
		Acc                                          g_inflRepeat;       // same (file, fileOffset, formID) as the previous inflate
		Acc                                          g_inflForeignFile;  // file != the current plugin's file
		Acc                                          g_inflNullFile;
		Acc                                          g_inflFailed;       // +0x4A0 null after the call
		const RE::TESFile*                           g_lastInflFile = nullptr;
		std::uint32_t                                g_lastInflOffset = 0;
		std::uint32_t                                g_lastInflFormID = 0;

		[[nodiscard]] inline std::uint32_t Tid() noexcept { return SKSE::WinAPI::GetCurrentThreadID(); }

		// The per-call identity check: measure only inside the window, only on
		// the thread that opened it.
		[[nodiscard]] inline bool Enter(Group a_g) noexcept
		{
			const int st = g_state.load(std::memory_order_acquire);
			if (st == kActive) {
				if (Tid() == g_loadTid.load(std::memory_order_relaxed)) {
					return true;
				}
				g_grp[a_g].foreign.inc();
				return false;
			}
			if (st != kDone) {
				g_grp[a_g].outside.inc();
			}
			return false;
		}

		// Exclusive-time scope. The parent's child accumulator is saved in the
		// C++ frame, so arbitrary nesting (ReadData -> inflate, Load -> ReadData,
		// even recursion) attributes every tick to exactly one innermost scope.
		struct Scope
		{
			std::uint64_t saved;
			std::uint64_t t0;
			Scope() noexcept :
				saved(g_child), t0(__rdtsc()) { g_child = 0; }
			// returns { inclusive, exclusive }
			std::pair<std::uint64_t, std::uint64_t> End() noexcept
			{
				const std::uint64_t dt = __rdtsc() - t0;
				const std::uint64_t ex = dt >= g_child ? dt - g_child : 0;
				g_child = saved + dt;
				return { dt, ex };
			}
		};

		[[nodiscard]] inline Slot& Cur() noexcept { return g_slots[g_cur]; }

		// ---- thunks ---------------------------------------------------------------

		// GATE. Site 36553+0x341 (0x642F11), the InitTES body's call of 13753.
		// [V] site bytes and args (rcx=dh, edx=0; the caller ignores rax).
		// [I] that the other two callers (0x6492FC, 0x942CFF) are not the
		// startup load: 36553 is the InitTES body (FEASIBILITY.md [V]); the
		// one-shot CAS below also limits the window to the FIRST call.
		// Opens the measurement window on the calling thread, closes it when
		// 13753 returns, and emits the report if kDataLoaded was already seen.
		void TryReport(const char* a_trigger);

		std::uint64_t LoadFilesThunk(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4)
		{
			const auto orig = reinterpret_cast<Fn4>(g_origLoadFiles);
			int expected = kIdle;
			if (!g_state.compare_exchange_strong(expected, kArming)) {
				return orig(a1, a2, a3, a4);  // not the first call, or the probe is off
			}
			g_loadTid.store(Tid(), std::memory_order_relaxed);
			g_cur = 0;
			g_child = 0;
			g_t0 = std::chrono::steady_clock::now();
			g_tsc0 = __rdtsc();
			g_grp[kGate].measured.add(1);
			g_state.store(kActive);  // seq_cst

			Scope s;
			const std::uint64_t r = orig(a1, a2, a3, a4);
			const auto [dt, ex] = s.End();

			g_tsc1 = __rdtsc();
			g_t1 = std::chrono::steady_clock::now();
			g_loadFilesTicks.add(dt);
			g_loadFilesEx.add(ex);
			g_state.store(kClosed);  // seq_cst; publishes every accumulator

			const auto ms = std::chrono::duration<double, std::milli>(g_t1 - g_t0).count();
			spdlog::info("[gate] startup LoadFiles returned after {:.1f} ms on thread {}; {} plugin slot(s). Window closed.",
				ms, g_loadTid.load(std::memory_order_relaxed), g_slotCount.load(std::memory_order_relaxed) - 1);
			spdlog::default_logger()->flush();

			if (g_dataLoadedSeen.load()) {  // seq_cst: pairs with OnDataLoaded (Dekker)
				TryReport("LoadFiles exit (kDataLoaded arrived while the load was running)");
			}
			return r;
		}

		// PER-PLUGIN. Sites 13753+0x323 / +0x343 (0x1B9A03 / 0x1B9A23) -> 13760.
		// [V] bytes and args (rcx=dh, rdx=TESFile*, r8b=isFirstFile). Measures the
		// wall time of each plugin's load and opens its slot.
		std::uint64_t LoadFileThunk(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4)
		{
			const auto orig = reinterpret_cast<Fn4>(g_origLoadFile);
			if (!Enter(kPerPlugin)) {
				return orig(a1, a2, a3, a4);
			}
			g_grp[kPerPlugin].measured.add(1);
			std::uint32_t idx = g_slotCount.load(std::memory_order_relaxed);
			if (idx < kMaxSlots) {
				g_slotCount.store(idx + 1, std::memory_order_relaxed);
				g_slots[idx].file.store(reinterpret_cast<const RE::TESFile*>(a2), std::memory_order_relaxed);
			} else {
				idx = 0;
				g_slotOverflow.add(1);
			}
			const std::uint32_t prev = g_cur;
			g_cur = idx;

			Scope s;
			const std::uint64_t r = orig(a1, a2, a3, a4);
			const auto [dt, ex] = s.End();

			g_slots[idx].wall.add(dt);
			g_slots[idx].loopEx.add(ex);
			g_cur = prev;
			return r;
		}

		// PER-RECORD. Site 13760+0x271 (0x1BB931) -> 13763, the R6 dispatch.
		// [V] bytes; [V] FIVE args (the 5th is a stack byte read at 0x1BC033),
		// all forwarded. Counts records per plugin, and how many carried the
		// compressed flag (the expected inflate count for LT-1 item 2).
		std::uint64_t LoadRecordThunk(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4, std::uint64_t a5)
		{
			const auto orig = reinterpret_cast<Fn5>(g_origLoadRecord);
			if (!Enter(kRecord)) {
				return orig(a1, a2, a3, a4, a5);
			}
			g_grp[kRecord].measured.add(1);
			Slot&      slot = Cur();
			const auto* file = reinterpret_cast<const RE::TESFile*>(a2);
			if (file && (file->currentform.flags & kCompressedFlag) != 0) {
				slot.compressed.add(1);
			}

			Scope s;
			const std::uint64_t r = orig(a1, a2, a3, a4, a5);
			const auto [dt, ex] = s.End();
			(void)dt;

			slot.records.add(1);
			slot.recEx.add(ex);
			return r;
		}

		// LOAD BODIES. The 16 calls of 13690 inside 13763 -> 0x1B11F0.
		// [V] bytes; [V] args rcx=form, rdx=file; returns Load's bool in eax.
		// Exclusive time = the form-type Load bodies minus nested ReadData/inflate.
		std::uint64_t LoadFormThunk(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4)
		{
			const auto orig = reinterpret_cast<Fn4>(g_origLoadForm);
			if (!Enter(kLoadBody)) {
				return orig(a1, a2, a3, a4);
			}
			g_grp[kLoadBody].measured.add(1);
			Slot& slot = Cur();

			Scope s;
			const std::uint64_t r = orig(a1, a2, a3, a4);
			const auto [dt, ex] = s.End();
			(void)dt;

			slot.loadN.add(1);
			slot.loadEx.add(ex);
			return r;
		}

		// RAW READ. ENTRY detour of 13991 TESFile::ReadData @0x1C8640.
		// [V] prologue (16 bytes compared at install); [V] args rcx=file,
		// rdx=buffer, r8d=size, no r9/stack args. The original is reached
		// through the gateway (stolen `mov [rsp+10h],rbx` + jmp entry+5).
		// Exclusive time excludes the inflate it may trigger (0x1C881A).
		std::uint64_t ReadDataThunk(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4)
		{
			const auto orig = reinterpret_cast<Fn4>(g_origReadData);
			if (!Enter(kRawRead)) {
				return orig(a1, a2, a3, a4);
			}
			g_grp[kRawRead].measured.add(1);
			Slot& slot = Cur();

			Scope s;
			const std::uint64_t r = orig(a1, a2, a3, a4);
			const auto [dt, ex] = s.End();
			(void)dt;

			slot.readN.add(1);
			slot.readEx.add(ex);
			return r;
		}

		// INFLATE. The three callers of 14032 (13991+0x1DA, 14029+0x15,
		// 14034+0x41), one template instance per site so the report can say
		// which paths inflate. [V] bytes; [V] one arg rcx=file; callers ignore rax.
		// Reads (never writes) +0x288 before and +0x4A0/+0x4A8 after.
		template <std::size_t I>
		std::uint64_t InflateThunk(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4)
		{
			const auto orig = reinterpret_cast<Fn4>(g_origInflate);
			if (!Enter(kInflate)) {
				return orig(a1, a2, a3, a4);
			}
			g_grp[kInflate].measured.add(1);
			g_inflBySite[I].add(1);
			Slot&      slot = Cur();
			const auto* file = reinterpret_cast<const RE::TESFile*>(a1);
			std::uint32_t in = 0;
			if (file) {
				in = file->currentform.length;
				if (file->decompressedFormBuffer != nullptr) {
					g_inflPreset.add(1);
				}
				const std::uint32_t off = file->fileOffset;
				const std::uint32_t fid = file->currentform.formID;
				if (file == g_lastInflFile && off == g_lastInflOffset && fid == g_lastInflFormID) {
					g_inflRepeat.add(1);
				}
				g_lastInflFile = file;
				g_lastInflOffset = off;
				g_lastInflFormID = fid;
				if (file != slot.file.load(std::memory_order_relaxed)) {
					g_inflForeignFile.add(1);
				}
			} else {
				g_inflNullFile.add(1);
			}

			Scope s;
			const std::uint64_t r = orig(a1, a2, a3, a4);
			const auto [dt, ex] = s.End();
			(void)dt;

			std::uint32_t out = 0;
			if (file) {
				out = file->decompressedFormBufferSize;
				if (file->decompressedFormBuffer == nullptr) {
					g_inflFailed.add(1);
				}
			}
			slot.inflN.add(1);
			slot.inflEx.add(ex);
			slot.inflIn.add(in);
			slot.inflOut.add(out);
			return r;
		}

		// POST-LOOP. Site 13753+0x363 (0x1B9A43) -> 13784, the InitItem pass.
		// [V] bytes; [V] one arg rcx=dh. One wall time.
		std::uint64_t InitItemsThunk(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4)
		{
			const auto orig = reinterpret_cast<Fn4>(g_origInitItems);
			if (!Enter(kPostLoop)) {
				return orig(a1, a2, a3, a4);
			}
			g_grp[kPostLoop].measured.add(1);
			const std::uint32_t prev = g_cur;
			g_cur = 0;  // InitItem work is not any one plugin's

			Scope s;
			const std::uint64_t r = orig(a1, a2, a3, a4);
			const auto [dt, ex] = s.End();

			g_initItemsTicks.add(dt);
			g_initItemsEx.add(ex);
			g_cur = prev;
			return r;
		}

		// ---- install-time verification -----------------------------------------

		std::string HexBytes(const std::uint8_t* a_p, std::size_t a_n)
		{
			std::string s;
			for (std::size_t i = 0; i < a_n; ++i) {
				s += std::format("{}{:02X}", i ? " " : "", static_cast<unsigned>(a_p[i]));
			}
			return s;
		}

		bool CheckFn(const sites::Fn& a_fn, std::uintptr_t& a_addr, std::string& a_why)
		{
			const REL::ID       id{ a_fn.id };
			const std::uintptr_t off = id.offset();
			if (off != a_fn.rva) {
				a_why = std::format("{}: the Address Library maps id {} to RVA 0x{:X}, the verified table says 0x{:X}",
					a_fn.name, a_fn.id, off, a_fn.rva);
				return false;
			}
			a_addr = id.address();
			return true;
		}

		// E8 at the site, rel32 -> a_target. a_actual receives the real target.
		bool CheckCallSite(const sites::CallSite& a_s, std::uintptr_t a_target, std::uintptr_t& a_site,
			std::uintptr_t& a_actual, std::string& a_why)
		{
			const REL::ID       id{ a_s.fnId };
			const std::uintptr_t off = id.offset();
			if (off != a_s.fnRva) {
				a_why = std::format("site {}: the Address Library maps id {} to RVA 0x{:X}, the verified table says 0x{:X}",
					a_s.name, a_s.fnId, off, a_s.fnRva);
				return false;
			}
			a_site = id.address() + a_s.off;
			std::array<std::uint8_t, 5> b{};
			std::memcpy(b.data(), reinterpret_cast<const void*>(a_site), b.size());
			std::int32_t rel = 0;
			std::memcpy(&rel, b.data() + 1, sizeof(rel));
			a_actual = static_cast<std::uintptr_t>(static_cast<std::intptr_t>(a_site) + 5 + rel);
			const std::uintptr_t base = REL::Module::get().base();
			if (g_cfg.verbose) {
				spdlog::info("[verify] {} @RVA 0x{:X}: {} -> RVA 0x{:X} (expected 0x{:X})",
					a_s.name, a_site - base, HexBytes(b.data(), b.size()), a_actual - base, a_target - base);
			}
			if (b[0] != 0xE8) {
				a_why = std::format("site {} @RVA 0x{:X}: expected E8, found {}", a_s.name, a_site - base, HexBytes(b.data(), b.size()));
				return false;
			}
			if (a_actual != a_target) {
				a_why = std::format("site {} @RVA 0x{:X}: E8 targets RVA 0x{:X}, expected 0x{:X} (another plugin patched it?)",
					a_s.name, a_site - base, a_actual - base, a_target - base);
				return false;
			}
			return true;
		}

		template <std::size_t N>
		bool CheckCallSites(const std::array<sites::CallSite, N>& a_sites, std::uintptr_t a_target,
			std::array<std::uintptr_t, N>& a_addrs, std::string& a_why)
		{
			for (std::size_t i = 0; i < N; ++i) {
				std::uintptr_t actual = 0;
				if (!CheckCallSite(a_sites[i], a_target, a_addrs[i], actual, a_why)) {
					return false;  // all-or-nothing per group: a partial group gives a wrong share
				}
			}
			return true;
		}

		void Refuse(Group a_g, std::string a_why)
		{
			g_grp[a_g].installed = false;
			g_grp[a_g].why = std::move(a_why);
			spdlog::warn("[install] {} NOT installed: {}", kGroupNames[a_g], g_grp[a_g].why);
		}

		void Patched(Group a_g, std::size_t a_sites)
		{
			g_grp[a_g].installed = true;
			g_grp[a_g].sites = a_sites;
			spdlog::info("[install] {} installed ({} site(s)).", kGroupNames[a_g], a_sites);
		}

		void CheckPrev(Group a_g, std::uintptr_t a_prev, std::uintptr_t a_verified)
		{
			if (a_prev != a_verified) {
				spdlog::error("[install] {}: the call target changed between the check and the patch (0x{:X} vs 0x{:X}); "
							  "the VERIFIED target is the one called.",
					kGroupNames[a_g], a_prev, a_verified);
			}
		}

		// ---- report ----------------------------------------------------------------

		std::string SafeName(const RE::TESFile* a_f)
		{
			if (!a_f) {
				return "(null file)";
			}
			std::string s;
			for (std::size_t i = 0; i < sizeof(a_f->fileName) && a_f->fileName[i] != '\0'; ++i) {
				const auto c = static_cast<unsigned char>(a_f->fileName[i]);
				s += (c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '?';  // ASCII only in the log
			}
			return s.empty() ? std::string("(empty name)") : s;
		}

		struct Totals
		{
			std::uint64_t wall = 0, loopEx = 0, records = 0, compressed = 0, recEx = 0;
			std::uint64_t loadN = 0, loadEx = 0, readN = 0, readEx = 0;
			std::uint64_t inflN = 0, inflEx = 0, inflIn = 0, inflOut = 0;
			void Add(const Slot& a_s)
			{
				wall += a_s.wall.get();
				loopEx += a_s.loopEx.get();
				records += a_s.records.get();
				compressed += a_s.compressed.get();
				recEx += a_s.recEx.get();
				loadN += a_s.loadN.get();
				loadEx += a_s.loadEx.get();
				readN += a_s.readN.get();
				readEx += a_s.readEx.get();
				inflN += a_s.inflN.get();
				inflEx += a_s.inflEx.get();
				inflIn += a_s.inflIn.get();
				inflOut += a_s.inflOut.get();
			}
		};

		// Cost of what every measured call adds: two rdtsc + the thread-id read.
		double MeasureProbeCostTicks()
		{
			constexpr int          kN = 200000;
			volatile std::uint64_t sink = 0;
			const std::uint64_t    t0 = __rdtsc();
			for (int i = 0; i < kN; ++i) {
				const std::uint64_t a = __rdtsc();
				sink = sink + Tid();
				const std::uint64_t b = __rdtsc();
				sink = sink + (b - a);
			}
			return static_cast<double>(__rdtsc() - t0) / kN;
		}

		void Line(const std::string& a_s) { spdlog::info("{}", a_s); }

		void WriteGroupTable()
		{
			Line("Hook groups (UNPROVEN = installed but never fired; its zeros mean nothing):");
			for (std::size_t g = 0; g < kGroupCount; ++g) {
				const auto& gs = g_grp[g];
				std::string status;
				if (!gs.requested) {
					status = "off by INI";
				} else if (!gs.installed) {
					status = "NOT HOOKED: " + gs.why;
				} else if (gs.measured.get() == 0) {
					status = std::format("installed ({} sites), UNPROVEN: 0 measured calls", gs.sites);
				} else {
					status = std::format("installed ({} sites)", gs.sites);
				}
				Line(std::format("  {:<42} measured={:<11} foreignThread={:<8} outsideWindow={:<8} {}",
					kGroupNames[g], gs.measured.get(), gs.foreign.get(), gs.outside.get(), status));
			}
		}

		void WriteReport(const char* a_trigger)
		{
			Line("==================== LoadingThreader LT-2 report ====================");
			Line(std::format("trigger: {}", a_trigger));
			if (!g_gateInstalled) {
				Line(std::format("PROBE INACTIVE: {}", g_inactiveWhy));
				WriteGroupTable();
				Line("=====================================================================");
				spdlog::default_logger()->flush();
				return;
			}
			if (g_grp[kGate].measured.get() == 0) {
				Line("UNPROVEN: the startup LoadFiles call never went through the gate; no data was collected.");
				WriteGroupTable();
				Line("=====================================================================");
				spdlog::default_logger()->flush();
				return;
			}

			const double winMs = std::chrono::duration<double, std::milli>(g_t1 - g_t0).count();
			const double tsc = static_cast<double>(g_tsc1 - g_tsc0);
			const double tpm = (winMs > 0.0 && tsc > 0.0) ? tsc / winMs : 0.0;  // TSC ticks per ms
			const auto   ms = [tpm](std::uint64_t a_t) { return tpm > 0.0 ? static_cast<double>(a_t) / tpm : 0.0; };
			const double lf = ms(g_loadFilesTicks.get());
			const auto   pct = [lf](double a_ms) { return lf > 0.0 ? 100.0 * a_ms / lf : 0.0; };

			const std::uint32_t n = g_slotCount.load(std::memory_order_relaxed);
			Totals              all;
			for (std::uint32_t i = 0; i < n; ++i) {
				all.Add(g_slots[i]);
			}

			Line(std::format("load thread id: {}   kDataLoaded thread id: {}   gate chained to a foreign patch: {}",
				g_loadTid.load(), g_dataLoadedTid.load(), g_gateChained ? "YES (LoadFiles ms includes the interposer)" : "no"));
			Line(std::format("LoadFiles (13753) total: {:.1f} ms (steady_clock), {:.1f} ms (TSC); TSC = {:.0f} ticks/ms",
				winMs, lf, tpm));
			Line(std::format("plugins measured: {} (slot overflow: {})", n - 1, g_slotOverflow.get()));
			WriteGroupTable();

			const double costTicks = MeasureProbeCostTicks();
			std::uint64_t calls = 0;
			for (std::size_t g = 0; g < kGroupCount; ++g) {
				calls += g_grp[g].measured.get();
			}
			Line(std::format("probe cost estimate: {} measured calls x {:.0f} ticks = {:.1f} ms of the total (excludes stub jumps)",
				calls, costTicks, ms(static_cast<std::uint64_t>(costTicks * static_cast<double>(calls)))));

			// ---- global split (exclusive times; they sum to LoadFiles) ----
			const double inflMs = ms(all.inflEx);
			const double readMs = ms(all.readEx);
			const double loadMs = ms(all.loadEx);
			const double recMs = ms(all.recEx);
			const double loopMs = ms(all.loopEx);
			const double postMs = ms(g_initItemsTicks.get());
			const double postExMs = ms(g_initItemsEx.get());
			const double restMs = ms(g_loadFilesEx.get());
			Line("Global split of LoadFiles (exclusive ms, % of LoadFiles):");
			Line(std::format("  inflate   14032          {:>10.1f} ms  {:>5.1f} %", inflMs, pct(inflMs)));
			Line(std::format("  raw read  13991 (excl)   {:>10.1f} ms  {:>5.1f} %", readMs, pct(readMs)));
			Line(std::format("  Load bodies 13690 (excl) {:>10.1f} ms  {:>5.1f} %", loadMs, pct(loadMs)));
			Line(std::format("  record dispatch 13763 ex {:>10.1f} ms  {:>5.1f} %", recMs, pct(recMs)));
			Line(std::format("  per-plugin loop 13760 ex {:>10.1f} ms  {:>5.1f} %  (OpenTES, seek/header, editor-ID R7, progress, CloseTES)", loopMs, pct(loopMs)));
			Line(std::format("  post-loop 13784 (incl)   {:>10.1f} ms  {:>5.1f} %  (exclusive {:.1f} ms)", postMs, pct(postMs), postExMs));
			Line(std::format("  LoadFiles rest 13753 ex  {:>10.1f} ms  {:>5.1f} %  (pass 1, 13767, 13403, 30433, ...)", restMs, pct(restMs)));
			Line(std::format("  sum of plugin walls      {:>10.1f} ms  {:>5.1f} %", ms(all.wall), pct(ms(all.wall))));
			Line(std::format("SHARES: inflate {:.1f} %, raw read {:.1f} %, Load bodies {:.1f} %, post-loop {:.1f} %",
				pct(inflMs), pct(readMs), pct(loadMs), pct(postMs)));

			// ---- decision rule (Docs/LT-2-probe-howto.md) ----
			if (!g_grp[kInflate].installed || g_grp[kInflate].measured.get() == 0) {
				Line("DECISION: UNPROVEN -- the inflate group did not measure anything.");
			} else if (pct(inflMs) > 15.0) {
				Line(std::format("DECISION: inflate share {:.1f} % > 15 %: stage 2 (decompress-ahead pool + RETURN hook at 14032) IS worth building.", pct(inflMs)));
			} else if (pct(inflMs) < 5.0) {
				Line(std::format("DECISION: inflate share {:.1f} % < 5 %: stage 2 is NOT worth building.", pct(inflMs)));
			} else {
				Line(std::format("DECISION: inflate share {:.1f} % is in the 5-15 % grey zone: marginal; weigh against the other shares.", pct(inflMs)));
			}

			// ---- LT-1 section 7 item 2 ----
			Line("Inflate diagnostics (LT-1 7.2):");
			Line(std::format("  inflates {}  in {} bytes  out {} bytes  ratio {:.2f}", all.inflN, all.inflIn, all.inflOut,
				all.inflIn ? static_cast<double>(all.inflOut) / static_cast<double>(all.inflIn) : 0.0));
			for (std::size_t i = 0; i < sites::kInflateSites.size(); ++i) {
				Line(std::format("  via {:<40} {}", sites::kInflateSites[i].name, g_inflBySite[i].get()));
			}
			Line(std::format("  records dispatched {}  of which compressed-flag {}  (expect inflates == compressed if each is inflated once)",
				all.records, all.compressed));
			Line(std::format("  entered with +0x4A0 already set: {}   same record inflated twice in a row: {}   failed (+0x4A0 null after): {}",
				g_inflPreset.get(), g_inflRepeat.get(), g_inflFailed.get()));
			Line(std::format("  file != current plugin: {}   null file: {}", g_inflForeignFile.get(), g_inflNullFile.get()));

			// ---- tables ----
			const auto row = [&](std::uint32_t a_i) {
				const Slot& s = g_slots[a_i];
				return std::format("  {:>5} {:>9.1f} {:>9} {:>8} {:>9.1f} {:>9.1f} {:>8} {:>11} {:>11} {:>8.1f}  {}",
					a_i, ms(s.wall.get()), s.records.get(), s.compressed.get(), ms(s.loadEx.get()), ms(s.readEx.get()),
					s.inflN.get(), s.inflIn.get(), s.inflOut.get(), ms(s.inflEx.get()),
					a_i == 0 ? std::string("(inside LoadFiles, outside any plugin)") : SafeName(s.file.load()));
			};
			const std::string header = "  slot    wall_ms   records compress   load_ms   read_ms  infl_n    infl_in_B   infl_out_B  infl_ms  plugin";

			std::vector<std::uint32_t> order;
			order.reserve(n);
			for (std::uint32_t i = 1; i < n; ++i) {
				order.push_back(i);
			}
			std::sort(order.begin(), order.end(), [](std::uint32_t a, std::uint32_t b) {
				return g_slots[a].wall.get() > g_slots[b].wall.get();
			});
			const std::size_t top = std::min<std::size_t>(order.size(), static_cast<std::size_t>(std::max(0, g_cfg.topN)));
			Line(std::format("Top {} plugins by wall time:", top));
			Line(header);
			for (std::size_t k = 0; k < top; ++k) {
				Line(row(order[k]));
			}

			if (g_cfg.fullTable) {
				Line("Per-plugin table (load order; slot 0 = work inside LoadFiles but outside any plugin):");
				Line(header);
				for (std::uint32_t i = 0; i < n; ++i) {
					Line(row(i));
				}
			}
			Line("=====================================================================");
			spdlog::default_logger()->flush();
		}

		void TryReport(const char* a_trigger)
		{
			if (g_state.load() != kClosed) {
				return;
			}
			bool expected = false;
			if (!g_reported.compare_exchange_strong(expected, true)) {
				return;
			}
			WriteReport(a_trigger);
			g_state.store(kDone);  // every thunk is a pure pass-through from here on
			spdlog::info("[probe] report written; all hooks are now pass-through for the rest of the session.");
			spdlog::default_logger()->flush();
		}
	}

	void Install(const Config& a_config)
	{
		g_cfg = a_config;
		g_grp[kGate].requested = true;
		g_grp[kPerPlugin].requested = a_config.perPlugin;
		g_grp[kRecord].requested = a_config.record;
		g_grp[kLoadBody].requested = a_config.loadBody;
		g_grp[kRawRead].requested = a_config.rawRead;
		g_grp[kInflate].requested = a_config.inflate;
		g_grp[kPostLoop].requested = a_config.postLoop;

		const auto inactive = [](std::string a_why) {
			g_inactiveWhy = std::move(a_why);
			for (std::size_t g = 0; g < kGroupCount; ++g) {
				if (g_grp[g].requested && g_grp[g].why.empty()) {
					g_grp[g].why = "probe inactive";
				}
			}
			spdlog::warn("[install] PROBE INACTIVE, no hook installed: {}", g_inactiveWhy);
		};

		if (!a_config.enabled) {
			for (auto& g : g_grp) {
				g.requested = false;
			}
			inactive("[General] bEnabled=0 (kill-switch)");
			return;
		}
		// Layer 1 (hook-site-verification.md): refuse every runtime whose bytes
		// were not read. Nothing below resolves an id before this check.
		if (REL::Module::IsVR()) {
			inactive("VR runtime (offsets were read off 1.6.1170 SE/AE only)");
			return;
		}
		if (REL::Module::get().version() != REL::Version(1, 6, 1170, 0)) {
			inactive(std::format("runtime {} is not 1.6.1170.0 (the only verified build)", REL::Module::get().version().string()));
			return;
		}

		std::string why;

		// ---- callees ----
		std::uintptr_t aLoadFiles = 0, aLoadFile = 0, aLoadRecord = 0, aLoadForm = 0, aReadData = 0, aInflate = 0, aInitItems = 0;
		if (!CheckFn(sites::kLoadFiles, aLoadFiles, why)) {
			Refuse(kGate, why);
			inactive("the gate callee failed the address check");
			return;
		}

		// ---- gate (verified first: without it nothing else may be installed) ----
		std::uintptr_t gateSite = 0, gateActual = 0;
		if (!CheckCallSite(sites::kGateSite, aLoadFiles, gateSite, gateActual, why)) {
			const bool isE8 = gateSite != 0 && *reinterpret_cast<const std::uint8_t*>(gateSite) == 0xE8;
			if (a_config.allowPatchedGate && isE8 && gateActual != 0) {
				spdlog::warn("[install] gate: {}. [Advanced] bAllowPatchedGate=1: chaining to the existing target.", why);
				g_gateChained = true;
			} else {
				Refuse(kGate, why);
				inactive("the gate site failed verification (see the line above)");
				return;
			}
		}
		g_slots = std::make_unique<Slot[]>(kMaxSlots);  // preallocated: no allocation in any thunk

		// ---- verify every other group before patching anything ----
		std::array<std::uintptr_t, sites::kPerPluginSites.size()> perPluginAddrs{};
		std::uintptr_t                                            recordAddr = 0;
		std::array<std::uintptr_t, sites::kLoadFormSites.size()>  loadFormAddrs{};
		std::array<std::uintptr_t, sites::kInflateSites.size()>   inflateAddrs{};
		std::uintptr_t                                            initItemsAddr = 0;

		bool doPerPlugin = false, doRecord = false, doLoadBody = false, doRawRead = false, doInflate = false, doPostLoop = false;

		if (a_config.perPlugin) {
			if (CheckFn(sites::kLoadFile, aLoadFile, why) && CheckCallSites(sites::kPerPluginSites, aLoadFile, perPluginAddrs, why)) {
				doPerPlugin = true;
			} else {
				Refuse(kPerPlugin, why);
			}
		}
		if (a_config.record) {
			std::uintptr_t actual = 0;
			if (CheckFn(sites::kLoadRecord, aLoadRecord, why) && CheckCallSite(sites::kRecordSite, aLoadRecord, recordAddr, actual, why)) {
				doRecord = true;
			} else {
				Refuse(kRecord, why);
			}
		}
		if (a_config.loadBody) {
			if (CheckFn(sites::kLoadForm, aLoadForm, why) && CheckCallSites(sites::kLoadFormSites, aLoadForm, loadFormAddrs, why)) {
				doLoadBody = true;
			} else {
				Refuse(kLoadBody, why);
			}
		}
		if (a_config.rawRead) {
			if (CheckFn(sites::kReadData, aReadData, why)) {
				const auto* p = reinterpret_cast<const std::uint8_t*>(aReadData);
				if (g_cfg.verbose) {
					spdlog::info("[verify] ReadData prologue @RVA 0x{:X}: {}", sites::kReadData.rva, HexBytes(p, sites::kReadDataPrologue.size()));
				}
				if (std::memcmp(p, sites::kReadDataPrologue.data(), sites::kReadDataPrologue.size()) == 0) {
					doRawRead = true;
				} else {
					Refuse(kRawRead, std::format("ReadData prologue mismatch (another detour?): found {}, expected {}",
										 HexBytes(p, sites::kReadDataPrologue.size()),
										 HexBytes(sites::kReadDataPrologue.data(), sites::kReadDataPrologue.size())));
				}
			} else {
				Refuse(kRawRead, why);
			}
		}
		if (a_config.inflate) {
			if (CheckFn(sites::kInflate, aInflate, why) && CheckCallSites(sites::kInflateSites, aInflate, inflateAddrs, why)) {
				doInflate = true;
			} else {
				Refuse(kInflate, why);
			}
		}
		if (a_config.postLoop) {
			std::uintptr_t actual = 0;
			if (CheckFn(sites::kInitItems, aInitItems, why) && CheckCallSite(sites::kInitItemsSite, aInitItems, initItemsAddr, actual, why)) {
				doPostLoop = true;
			} else {
				Refuse(kPostLoop, why);
			}
		}

		// ---- patch. Originals are stored BEFORE each patch (the thunk can run the
		// instant the E8 is rewritten) and are the VERIFIED targets. ----
		// 9 distinct thunks x 14-byte stubs + a 19-byte gateway; 512 is headroom.
		SKSE::AllocTrampoline(512);
		auto& tr = SKSE::GetTrampoline();

		if (doPerPlugin) {
			g_origLoadFile = aLoadFile;
			for (const auto a : perPluginAddrs) {
				CheckPrev(kPerPlugin, tr.write_call<5>(a, &LoadFileThunk), aLoadFile);
			}
			Patched(kPerPlugin, perPluginAddrs.size());
		}
		if (doRecord) {
			g_origLoadRecord = aLoadRecord;
			CheckPrev(kRecord, tr.write_call<5>(recordAddr, &LoadRecordThunk), aLoadRecord);
			Patched(kRecord, 1);
		}
		if (doLoadBody) {
			g_origLoadForm = aLoadForm;
			for (const auto a : loadFormAddrs) {
				CheckPrev(kLoadBody, tr.write_call<5>(a, &LoadFormThunk), aLoadForm);
			}
			Patched(kLoadBody, loadFormAddrs.size());
		}
		if (doRawRead) {
			// Gateway: the stolen instruction, then `jmp qword ptr [rip+0]` to entry+5.
			constexpr std::size_t kStolen = sites::kReadDataStolen;
			auto* gw = static_cast<std::uint8_t*>(tr.allocate(kStolen + 14));
			std::memcpy(gw, reinterpret_cast<const void*>(aReadData), kStolen);
			gw[kStolen + 0] = 0xFF;
			gw[kStolen + 1] = 0x25;
			const std::int32_t zero = 0;
			std::memcpy(gw + kStolen + 2, &zero, sizeof(zero));
			const std::uint64_t back = aReadData + kStolen;
			std::memcpy(gw + kStolen + 6, &back, sizeof(back));
			g_origReadData = reinterpret_cast<std::uintptr_t>(gw);
			// kStolen == 5 == the branch size, so no byte of a split instruction is left behind.
			static_assert(sites::kReadDataStolen == 5);
			(void)tr.write_branch<5>(aReadData, &ReadDataThunk);
			Patched(kRawRead, 1);
		}
		if (doInflate) {
			static_assert(sites::kInflateSites.size() == 3);
			g_origInflate = aInflate;
			CheckPrev(kInflate, tr.write_call<5>(inflateAddrs[0], &InflateThunk<0>), aInflate);
			CheckPrev(kInflate, tr.write_call<5>(inflateAddrs[1], &InflateThunk<1>), aInflate);
			CheckPrev(kInflate, tr.write_call<5>(inflateAddrs[2], &InflateThunk<2>), aInflate);
			Patched(kInflate, inflateAddrs.size());
		}
		if (doPostLoop) {
			g_origInitItems = aInitItems;
			CheckPrev(kPostLoop, tr.write_call<5>(initItemsAddr, &InitItemsThunk), aInitItems);
			Patched(kPostLoop, 1);
		}

		// Gate last: nothing is measured until every other seat is in place.
		g_origLoadFiles = gateActual;  // == aLoadFiles unless bAllowPatchedGate chained
		g_state.store(kIdle);
		const std::uintptr_t prevGate = tr.write_call<5>(gateSite, &LoadFilesThunk);
		CheckPrev(kGate, prevGate, gateActual);
		g_gateInstalled = true;
		Patched(kGate, 1);
		spdlog::info("[install] probe armed: measuring the next startup LoadFiles (13753) call. Trampoline {} / {} bytes used.",
			tr.allocated_size(), tr.capacity());
	}

	void OnDataLoaded()
	{
		g_dataLoadedTid.store(Tid());
		g_dataLoadedSeen.store(true);  // seq_cst: pairs with LoadFilesThunk (Dekker)

		if (!g_gateInstalled) {
			bool expected = false;
			if (g_reported.compare_exchange_strong(expected, true)) {
				WriteReport("kDataLoaded");
			}
			return;
		}
		int st = g_state.load();
		if (st == kIdle) {
			if (g_state.compare_exchange_strong(st, kDone)) {
				bool expected = false;
				if (g_reported.compare_exchange_strong(expected, true)) {
					WriteReport("kDataLoaded (startup LoadFiles never entered)");
				}
				return;
			}
			st = g_state.load();
		}
		if (st == kClosed) {
			TryReport("kDataLoaded");
		} else if (st == kArming || st == kActive) {
			spdlog::warn("[probe] kDataLoaded arrived on thread {} while LoadFiles is still running; the report will be "
						 "written when LoadFiles returns.",
				g_dataLoadedTid.load());
		}
	}
}
