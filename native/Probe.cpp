#include "PCH.h"

#include "Probe.h"
#include "ProbeCore.h"
#include "Sites.h"

// =============================================================================
// LT-2 / LT-2b timing probe (PASSIVE). SkyrimSE 1.6.1170.0 only.
//
// What it answers: how the startup data load (13753) splits between zlib
// inflate (14032), raw subrecord reads (13991), the per-form Load bodies
// (13690), the per-record dispatcher (13763), the per-plugin loop bookkeeping
// (13760) and the post-loop InitItem pass (13784) -- and, in v2, how each of
// those splits further (13753's callees, 13784's phases P0..P10, the per-form-
// type InitItem table, Load bodies per record signature) and what the same
// hooked code costs while the Loading Menu is open at runtime.
// See Docs/LT-2-probe-howto.md and Docs/LT-2b-sites-validated.md.
//
// Passivity rules (Linux-Native-Tools/hook-site-verification.md):
//   * Every thunk calls the original with every argument register forwarded
//     unchanged and returns rax unchanged. No field is written. No vfunc is
//     called by the probe itself (the virtual-call thunks perform exactly the
//     call the patched instruction made). Fields are only READ.
//   * No allocation, no lock, no file I/O inside a hot thunk. Accumulators are
//     preallocated at install and written by ONE thread each (thread-local
//     blocks, ProbeCore.h).
//   * Hook choice: CALL-SITE write_call<5> for E8 sites, write_call<6> for the
//     6-byte virtual InitItem calls (the thunk reads the vtable slot at call
//     time), one ENTRY detour (13991 ReadData, ~900 callers).
//   * Every site is re-verified at install (Address Library offset, E8 byte and
//     rel32 target, or the FNV-1a hash of the virtual-call window). Mismatch =>
//     that group is not installed and the log says why; the game is never
//     crashed for it.
//
// Gating: a thunk measures only while an EPISODE is open (g_curEp). Episode 0 is
// the startup LoadFiles call made by the InitTES body (Sites.h gate), measured
// on the thread that made that call only. Runtime episodes are the Loading Menu
// open..close and measure on any thread. With no episode open every thunk is a
// load + branch + the original call.
// =============================================================================

// Every field the thunks read, pinned to the offsets read off the 1.6.1170
// disassembly ([V]) or the CommonLib header ([I], used only for diagnostics).
static_assert(offsetof(RE::TESFile, fileName) == 0x58);                    // [I] name, read at report time only
static_assert(offsetof(RE::TESFile, currentform) == 0x284);                // [V] 13760/14032 read +0x288/+0x28C/+0x290
static_assert(offsetof(RE::TESFile, fileOffset) == 0x2A8);                 // [I] diagnostic key only
static_assert(offsetof(RE::TESFile, decompressedFormBuffer) == 0x4A0);     // [V] 14032 writes it at 0x1C991F
static_assert(offsetof(RE::TESFile, decompressedFormBufferSize) == 0x4A8); // [V] 14032 writes it at 0x1C9926
static_assert(offsetof(RE::FORM, form) == 0x0);                            // [I] record signature dword, read by the Load-body thunk
static_assert(offsetof(RE::FORM, length) == 0x4);                          // [V] => +0x288, read by 14032
static_assert(offsetof(RE::FORM, flags) == 0x8);                           // [V] => +0x28C, ReadData tests 0x40000
static_assert(offsetof(RE::FORM, formID) == 0xC);                          // [V] => +0x290, read by 13760 R7

namespace lt::probe
{
	namespace
	{
		using namespace core;

		// Originals (set before the site is patched; the VERIFIED target).
		std::uintptr_t g_origLoadFiles = 0;
		std::uintptr_t g_origLoadFile = 0;
		std::uintptr_t g_origLoadRecord = 0;
		std::uintptr_t g_origLoadForm = 0;
		std::uintptr_t g_origReadData = 0;  // the gateway (stolen bytes + jmp back)
		std::uintptr_t g_origInflate = 0;
		std::uintptr_t g_origInitItems = 0;
		std::array<std::uintptr_t, kTimedCount> g_timedOrig{};  // the verified callee of each kTimedSites row

		// ---- block pool ---------------------------------------------------------
		Block* ClaimBlock(const Episode& a_ep) noexcept
		{
			const std::uint32_t i = g_blockNext.fetch_add(1, std::memory_order_relaxed);
			if (i >= kMaxBlocks || !g_blocks) {
				return nullptr;
			}
			Block& b = g_blocks[i];
			b.episode.store(a_ep.index, std::memory_order_relaxed);
			b.tid.store(Tid(), std::memory_order_relaxed);
			b.startup = a_ep.startup;
			if (a_ep.startup) {
				b.slots = g_slots.get();
				b.slotCap = kMaxSlots;
			} else {
				b.slots = &b.rt;
				b.slotCap = 1;
			}
			return &b;
		}

		// A thread seen for the first time in this episode.
		void EnterSlow(const Episode* a_ep, Tls& a_t) noexcept
		{
			a_t.ep = a_ep;
			a_t.blk = nullptr;
			a_t.child = 0;
			a_t.exhausted = false;
			if (a_ep->startup && Tid() != a_ep->loadTid.load(std::memory_order_relaxed)) {
				return;  // startup measures the load thread only
			}
			Block* b = ClaimBlock(*a_ep);
			if (b) {
				a_t.blk = b;
			} else {
				a_t.exhausted = true;
			}
		}

		// Cold: a call on a thread the startup episode does not measure.
		void NoteForeign(Group a_g) noexcept
		{
			g_grp[a_g].foreign.inc();
			const std::uint32_t id = Tid();
			g_foreignTids.note(id);
			const int ph = g_pubIi.load(std::memory_order_relaxed);
			if (ph >= 0) {
				g_iiTids[static_cast<std::size_t>(ph)].note(id);
			}
			const int sg = g_pubLf.load(std::memory_order_relaxed);
			if (sg >= 0) {
				g_lfTids[static_cast<std::size_t>(sg)].note(id);
			}
		}

		// The per-call gate. null => do not measure (no episode open, a foreign thread
		// during startup, or the block pool is exhausted). Zero overhead when idle.
		[[nodiscard]] inline Block* Enter(Group a_g) noexcept
		{
			const Episode* e = g_curEp.load(std::memory_order_acquire);
			if (!e) {
				return nullptr;
			}
			Tls& t = t_tls;
			if (t.ep != e) {
				EnterSlow(e, t);
			}
			if (t.blk) {
				return t.blk;
			}
			if (t.exhausted) {
				g_blockDrops.inc();
			} else {
				NoteForeign(a_g);
			}
			return nullptr;
		}

		// Exclusive-time scope. The parent's child accumulator is saved in the
		// C++ frame, so arbitrary nesting (ReadData -> inflate, Load -> ReadData,
		// even recursion) attributes every tick to exactly one innermost scope.
		struct Scope
		{
			std::uint64_t saved;
			std::uint64_t t0;
			Scope() noexcept :
				saved(t_tls.child), t0(__rdtsc()) { t_tls.child = 0; }
			// returns { inclusive, exclusive }
			std::pair<std::uint64_t, std::uint64_t> End() noexcept
			{
				const std::uint64_t dt = __rdtsc() - t0;
				const std::uint64_t ex = dt >= t_tls.child ? dt - t_tls.child : 0;
				t_tls.child = saved + dt;
				return { dt, ex };
			}
		};

		// ---- phase / segment markers (startup block only) ----------------------------
		// Monotonic "last hit wins" (Docs/LT-2b-sites-validated.md section 2). A phase
		// starts at the first marker that fires for it; an empty array skips its marker
		// and the time then lands in the previous phase. Passing -1 closes the open one.
		inline void SetPhase(Block& a_b, std::int8_t a_ph) noexcept
		{
			if (!a_b.startup || a_b.iiPhase == a_ph) {
				return;
			}
			const std::uint64_t now = __rdtsc();
			const CpuTimes cpu = ThreadCpu();
			if (a_b.iiPhase >= 0) {
				PhaseRow& r = a_b.ii[static_cast<std::size_t>(a_b.iiPhase)];
				r.wall.add(now - a_b.iiStart);
				r.kern.add(cpu.kern >= a_b.iiCpu0.kern ? cpu.kern - a_b.iiCpu0.kern : 0);
				r.user.add(cpu.user >= a_b.iiCpu0.user ? cpu.user - a_b.iiCpu0.user : 0);
			}
			a_b.iiPhase = a_ph;
			a_b.iiStart = now;
			a_b.iiCpu0 = cpu;
			if (a_ph >= 0) {
				a_b.ii[static_cast<std::size_t>(a_ph)].entries.add(1);
				g_iiTids[static_cast<std::size_t>(a_ph)].note(Tid());
			}
			g_pubIi.store(a_ph, std::memory_order_relaxed);
		}

		inline void SetSeg(Block& a_b, std::int8_t a_seg) noexcept
		{
			if (!a_b.startup || a_b.lfSeg == a_seg) {
				return;
			}
			const std::uint64_t now = __rdtsc();
			const CpuTimes cpu = ThreadCpu();
			if (a_b.lfSeg >= 0) {
				PhaseRow& r = a_b.lf[static_cast<std::size_t>(a_b.lfSeg)];
				r.wall.add(now - a_b.lfStart);
				r.kern.add(cpu.kern >= a_b.lfCpu0.kern ? cpu.kern - a_b.lfCpu0.kern : 0);
				r.user.add(cpu.user >= a_b.lfCpu0.user ? cpu.user - a_b.lfCpu0.user : 0);
			}
			a_b.lfSeg = a_seg;
			a_b.lfStart = now;
			a_b.lfCpu0 = cpu;
			if (a_seg >= 0) {
				a_b.lf[static_cast<std::size_t>(a_seg)].entries.add(1);
				g_lfTids[static_cast<std::size_t>(a_seg)].note(Tid());
			}
			g_pubLf.store(a_seg, std::memory_order_relaxed);
		}

		// ---- small tables -------------------------------------------------------------
		inline SigRow* FindSig(Block& a_b, std::uint32_t a_key) noexcept
		{
			const std::uint32_t key = a_key != 0 ? a_key : 0xFFFFFFFFu;
			std::size_t         h = static_cast<std::size_t>((key * 2654435761u) >> 8) & (kSigSlots - 1);
			for (std::size_t i = 0; i < kSigSlots; ++i) {
				SigRow&             row = a_b.sig[(h + i) & (kSigSlots - 1)];
				const std::uint32_t k = row.key.get();
				if (k == key) {
					return &row;
				}
				if (k == 0) {
					row.key.set(key);
					return &row;
				}
			}
			a_b.sigOverflow.add(1);
			return nullptr;
		}

		inline void NoteHeavy(Block& a_b, std::uint64_t a_dt, std::uint32_t a_formID, std::uint32_t a_sig, const RE::TESFile* a_file) noexcept
		{
			if (a_dt <= a_b.heavyMin) {
				return;
			}
			HeavyRow& r = a_b.heavy[a_b.heavyMinIdx];
			r.ticks.set(a_dt);
			r.formID.set(a_formID);
			r.sig.set(a_sig);
			r.file.store(a_file, std::memory_order_relaxed);
			std::uint64_t mn = ~0ULL;
			std::uint32_t mi = 0;
			for (std::uint32_t i = 0; i < kTopHeavy; ++i) {
				const std::uint64_t t = a_b.heavy[i].ticks.get();
				if (t < mn) {
					mn = t;
					mi = i;
				}
			}
			a_b.heavyMin = mn;
			a_b.heavyMinIdx = mi;
		}

		inline FileRow* FindFile(std::uint64_t a_ptr) noexcept
		{
			if (!g_files || a_ptr == 0) {
				return nullptr;
			}
			const std::size_t h = static_cast<std::size_t>(((a_ptr >> 4) * 0x9E3779B97F4A7C15ULL) >> 40) & (kFileRows - 1);
			const void*       key = reinterpret_cast<const void*>(a_ptr);
			for (std::size_t i = 0; i < kFileRows; ++i) {
				FileRow&    r = g_files[(h + i) & (kFileRows - 1)];
				const void* k = r.file.load(std::memory_order_relaxed);
				if (k == key) {
					return &r;
				}
				if (!k) {
					r.file.store(key, std::memory_order_relaxed);
					return &r;
				}
			}
			g_fileRowDrops.inc();
			return nullptr;
		}

		constexpr std::size_t FileColIdx(sites::Col a_c) noexcept
		{
			switch (a_c) {
			case sites::Col::kCompileIdx:
				return 0;
			case sites::Col::kBsaGate:
				return 1;
			case sites::Col::kBsaLoad:
				return 2;
			default:
				return 3;  // kPass1Open
			}
		}

		constexpr Group GroupOf(sites::Owner a_o) noexcept
		{
			switch (a_o) {
			case sites::Owner::kLoadFiles:
				return kLfCallees;
			case sites::Owner::kInitPass:
				return kInitPass;
			case sites::Owner::kPluginLoop:
				return kLoopSplit;
			default:
				return kNewForms;
			}
		}

		constexpr Group VfGroup(std::size_t a_i) noexcept
		{
			return sites::kVfSites[a_i].kind == sites::VfKind::kCore ? kPerForm :
			       (a_i < sites::kVfPassCount ? kInitPass : kInitRefs);
		}

		// ---- thunks ---------------------------------------------------------------

		// GATE. Site 36553+0x341 (0x642F11), the InitTES body's call of 13753.
		// [V] site bytes and args (rcx=dh, edx=0; the caller ignores rax).
		// [I] that the other two callers (0x6492FC, 0x942CFF) are not the
		// startup load: 36553 is the InitTES body (FEASIBILITY.md [V]); the
		// one-shot CAS below also limits the window to the FIRST call.
		// Opens episode 0 on the calling thread, closes it when 13753 returns, and
		// emits the report if kDataLoaded was already seen.
		void TryReport(const char* a_trigger);

		std::uint64_t LoadFilesThunk(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4)
		{
			const auto orig = reinterpret_cast<Fn4>(g_origLoadFiles);
			int        expected = kIdle;
			if (!g_state.compare_exchange_strong(expected, kArming)) {
				return orig(a1, a2, a3, a4);  // not the first call, or the probe is off
			}
			Episode& e = g_eps[0];
			e.loadTid.store(Tid(), std::memory_order_relaxed);
			g_loadTid.store(Tid(), std::memory_order_relaxed);
			e.openTid = Tid();
			e.t0 = std::chrono::steady_clock::now();
			e.tsc0 = __rdtsc();
			e.procCpu0 = ProcessCpu();

			// The load thread's block is claimed here and installed in its TLS, so the first
			// hooked call inside the window takes the fast path.
			Block* b = ClaimBlock(e);
			t_tls.ep = &e;
			t_tls.blk = b;
			t_tls.child = 0;
			t_tls.exhausted = (b == nullptr);
			if (b) {
				b->measured[kGate].add(1);
				SetSeg(*b, sites::kLfSetup);
			}
			g_curEp.store(&e, std::memory_order_seq_cst);
			g_state.store(kActive);  // seq_cst

			Scope s;
			const std::uint64_t r = orig(a1, a2, a3, a4);
			const auto [dt, ex] = s.End();

			e.tsc1 = __rdtsc();
			e.t1 = std::chrono::steady_clock::now();
			e.procCpu1 = ProcessCpu();
			e.closeTid = Tid();
			g_curEp.store(nullptr, std::memory_order_seq_cst);
			if (b) {
				SetSeg(*b, -1);
				SetPhase(*b, -1);
				b->loadFilesTicks.add(dt);
				b->loadFilesEx.add(ex);
			}
			e.closed.store(true);
			g_state.store(kClosed);  // seq_cst; publishes every accumulator

			const auto ms = std::chrono::duration<double, std::milli>(e.t1 - e.t0).count();
			spdlog::info("[gate] startup LoadFiles returned after {:.1f} ms on thread {}; {} plugin slot(s). Episode '{}' closed.",
				ms, g_loadTid.load(std::memory_order_relaxed), b ? b->slotCount.load(std::memory_order_relaxed) - 1 : 0u, e.name);
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
			Block*     b = Enter(kPerPlugin);
			if (!b) {
				return orig(a1, a2, a3, a4);
			}
			b->measured[kPerPlugin].add(1);
			std::uint32_t idx = b->slotCount.load(std::memory_order_relaxed);
			if (idx < b->slotCap) {
				b->slotCount.store(idx + 1, std::memory_order_relaxed);
				b->slots[idx].file.store(reinterpret_cast<const RE::TESFile*>(a2), std::memory_order_relaxed);
			} else {
				idx = 0;
				b->slotOverflow.add(1);
			}
			const std::uint32_t prev = b->cur;
			b->cur = idx;

			Scope s;
			const std::uint64_t r = orig(a1, a2, a3, a4);
			const auto [dt, ex] = s.End();

			b->slots[idx].wall.add(dt);
			b->slots[idx].loopEx.add(ex);
			b->cur = prev;
			return r;
		}

		// PER-RECORD. Site 13760+0x271 (0x1BB931) -> 13763, the R6 dispatch.
		// [V] bytes; [V] FIVE args (the 5th is a stack byte read at 0x1BC033),
		// all forwarded. Counts records per plugin, and how many carried the
		// compressed flag (the expected inflate count for LT-1 item 2).
		std::uint64_t LoadRecordThunk(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4, std::uint64_t a5)
		{
			const auto orig = reinterpret_cast<Fn5>(g_origLoadRecord);
			Block*     b = Enter(kRecord);
			if (!b) {
				return orig(a1, a2, a3, a4, a5);
			}
			b->measured[kRecord].add(1);
			Slot&      slot = b->slots[b->cur];
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
		// The record signature, data size, flags and FormID are the header fields
		// 13763 has already put in file->currentform (read before the call).
		std::uint64_t LoadFormThunk(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4)
		{
			const auto orig = reinterpret_cast<Fn4>(g_origLoadForm);
			Block*     b = Enter(kLoadBody);
			if (!b) {
				return orig(a1, a2, a3, a4);
			}
			b->measured[kLoadBody].add(1);
			Slot&         slot = b->slots[b->cur];
			const auto*   file = reinterpret_cast<const RE::TESFile*>(a2);
			std::uint32_t sig = 0, len = 0, flags = 0, fid = 0;
			if (file) {
				sig = file->currentform.form;
				len = file->currentform.length;
				flags = file->currentform.flags;
				fid = file->currentform.formID;
			}

			Scope s;
			const std::uint64_t r = orig(a1, a2, a3, a4);
			const auto [dt, ex] = s.End();

			slot.loadN.add(1);
			slot.loadEx.add(ex);
			if (SigRow* row = FindSig(*b, sig)) {
				row->count.add(1);
				row->ticks.add(dt);
				row->exTicks.add(ex);
				row->bytes.add(len);
				if ((flags & kCompressedFlag) != 0) {
					row->compressed.add(1);
				}
			}
			NoteHeavy(*b, dt, fid, sig, file);
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
			Block*     b = Enter(kRawRead);
			if (!b) {
				return orig(a1, a2, a3, a4);
			}
			b->measured[kRawRead].add(1);
			Slot& slot = b->slots[b->cur];

			Scope s;
			const std::uint64_t r = orig(a1, a2, a3, a4);
			const auto [dt, ex] = s.End();
			(void)dt;

			slot.readN.add(1);
			slot.readEx.add(ex);
			b->readBytes.add(static_cast<std::uint32_t>(a3));  // r8d = size
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
			Block*     b = Enter(kInflate);
			if (!b) {
				return orig(a1, a2, a3, a4);
			}
			b->measured[kInflate].add(1);
			b->inflBySite[I].add(1);
			Slot&         slot = b->slots[b->cur];
			const auto*   file = reinterpret_cast<const RE::TESFile*>(a1);
			std::uint32_t in = 0;
			if (file) {
				in = file->currentform.length;
				if (file->decompressedFormBuffer != nullptr) {
					b->inflPreset.add(1);
				}
				const std::uint32_t off = file->fileOffset;
				const std::uint32_t fid = file->currentform.formID;
				if (file == b->lastInflFile && off == b->lastInflOffset && fid == b->lastInflFormID) {
					b->inflRepeat.add(1);
				}
				b->lastInflFile = file;
				b->lastInflOffset = off;
				b->lastInflFormID = fid;
				if (file != slot.file.load(std::memory_order_relaxed)) {
					b->inflForeignFile.add(1);
				}
			} else {
				b->inflNullFile.add(1);
			}

			Scope s;
			const std::uint64_t r = orig(a1, a2, a3, a4);
			const auto [dt, ex] = s.End();
			(void)dt;

			std::uint32_t out = 0;
			if (file) {
				out = file->decompressedFormBufferSize;
				if (file->decompressedFormBuffer == nullptr) {
					b->inflFailed.add(1);
				}
			}
			slot.inflN.add(1);
			slot.inflEx.add(ex);
			slot.inflIn.add(in);
			slot.inflOut.add(out);
			return r;
		}

		// POST-LOOP. Site 13753+0x363 (0x1B9A43) -> 13784, the InitItem pass.
		// [V] bytes; [V] one arg rcx=dh. Wall time, and P0 starts here (phase markers).
		std::uint64_t InitItemsThunk(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4)
		{
			const auto orig = reinterpret_cast<Fn4>(g_origInitItems);
			Block*     b = Enter(kPostLoop);
			if (!b) {
				return orig(a1, a2, a3, a4);
			}
			b->measured[kPostLoop].add(1);
			const std::uint32_t prev = b->cur;
			b->cur = 0;  // InitItem work is not any one plugin's
			b->avifHits = 0;
			SetSeg(*b, sites::kLfInitItems);
			SetPhase(*b, sites::kIiDobj);

			Scope s;
			const std::uint64_t r = orig(a1, a2, a3, a4);
			const auto [dt, ex] = s.End();

			SetPhase(*b, -1);
			b->initItemsTicks.add(dt);
			b->initItemsEx.add(ex);
			b->cur = prev;
			return r;
		}

		// ---- v2: the 55 E8 sites (13753 / 13784 / 13760 / 13763 callees) ---------------
		// One template instance per kTimedSites row, so the segment markers, the column
		// and the owner are compile-time constants. [V] Docs/LT-2b-sites-validated.md:
		// no callee reads a stack (5th) argument or an xmm argument, so the generic
		// 4-register form is exact. The original is the row's verified callee.
		template <std::size_t I>
		std::uint64_t TimedThunk(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4)
		{
			constexpr const sites::TimedSite& S = sites::kTimedSites[I];
			constexpr Group                   G = GroupOf(S.owner);
			const auto                        orig = reinterpret_cast<Fn4>(g_timedOrig[I]);
			Block*                            b = Enter(G);
			if (!b) {
				return orig(a1, a2, a3, a4);
			}
			b->measured[G].add(1);
			if constexpr (S.owner == sites::Owner::kLoadFiles) {
				if constexpr (S.segEntry >= 0) {
					SetSeg(*b, S.segEntry);
				}
			} else if constexpr (S.owner == sites::Owner::kInitPass) {
				if constexpr (S.segEntry >= 0) {
					SetPhase(*b, S.segEntry);
				}
			}
			std::size_t newType = kTypeCount;
			if constexpr (S.col == sites::Col::kNewForm) {
				if (a2 != 0) {
					newType = TypeIdx(FormTypeByte(a2));  // rdx = the new form (read-only)
				}
			}

			// wall time only: kernel/user is sampled at the segment / phase markers (SetSeg / SetPhase),
			// not per call (these rows repeat per plugin file / per form; GetThreadTimes is a wineserver call)
			Scope s;
			const std::uint64_t r = orig(a1, a2, a3, a4);
			const auto [dt, ex] = s.End();

			if constexpr (S.owner == sites::Owner::kInitPass && S.segExit >= 0) {
				SetPhase(*b, S.segExit);
			}
			CalleeRow& row = b->callee[I];
			row.n.add(1);
			row.ticks.add(dt);
			row.ex.add(ex);

			if constexpr (S.col == sites::Col::kNewForm) {
				b->newForms[newType].add(1);
				b->newFormTicks[newType].add(dt);
			} else if constexpr (S.file != sites::FileArg::kNone) {
				if (b->startup) {
					const std::uint64_t fp = (S.file == sites::FileArg::kRcx) ? a1 :
					                         (S.file == sites::FileArg::kRdx) ? a2 :
					                                                            a1 - 0x58;
					if (FileRow* fr = FindFile(fp)) {
						fr->t[FileColIdx(S.col)].add(ex);
						if constexpr (S.col == sites::Col::kBsaGate) {
							if ((r & 0xFF) != 0) {
								fr->gateTrue.add(1);
							}
						}
					}
				}
			} else if constexpr (S.col != sites::Col::kNone) {
				Slot& sl = b->slots[b->cur];
				sl.colT[static_cast<std::size_t>(S.col)].add(ex);
				sl.colN[static_cast<std::size_t>(S.col)].add(1);
			}
			return r;
		}

		template <std::size_t... Is>
		constexpr std::array<Fn4, sizeof...(Is)> MakeTimedThunks(std::index_sequence<Is...>) noexcept
		{
			return { &TimedThunk<Is>... };
		}

		// ---- v2: the 10 virtual InitItem calls (6-byte `call [rax|rdx+98h]`) ---------------
		// Patched with write_call<6> (FF 15 disp32 -> an 8-byte trampoline slot), so the
		// return address stays site+6 exactly as in the original. The original target is
		// per object: the thunk reads the vtable slot at call time, (*(fn**)(*(char**)rcx + 0x98)),
		// forwards rcx/rdx/r8/r9 unchanged and returns rax untouched (InitItem is void; rax is
		// whatever the callee left). write_call<6>'s own return value is garbage for these
		// sites and is ignored. [V] Sites.h comment block above kVfSites.
		template <std::size_t I>
		std::uint64_t VfThunk(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4)
		{
			constexpr const sites::VfSite& S = sites::kVfSites[I];
			constexpr Group                G = VfGroup(I);
			const auto fn = *reinterpret_cast<const Fn4*>(*reinterpret_cast<const std::uintptr_t*>(a1) + sites::kInitItemSlotOffset);
			Block*     b = Enter(G);
			if (!b) {
				return fn(a1, a2, a3, a4);
			}
			b->measured[G].add(1);
			if constexpr (S.phaseEntry >= 0) {
				SetPhase(*b, S.phaseEntry);
			}
			std::uint8_t  type = 0;
			std::uint32_t formID = 0;
			if constexpr (S.kind == sites::VfKind::kCore) {
				type = FormTypeByte(a1);  // rcx = the form; the type index t equals formType [I] (see report note)
				formID = FormIdOf(a1);
			}

			Scope s;
			const std::uint64_t r = fn(a1, a2, a3, a4);
			const auto [dt, ex] = s.End();

			if constexpr (S.phaseExit >= 0) {
				SetPhase(*b, S.phaseExit);
			}
			if constexpr (S.kind == sites::VfKind::kAvif) {
				b->avifHits += 1;
				if (b->avifHits == sites::kAvifCount) {
					SetPhase(*b, sites::kIiNpc);  // P5 starts at the return of the 0xA4-th AVIF InitItem
				}
			}
			CalleeRow& row = b->vf[I];
			row.n.add(1);
			row.ticks.add(dt);
			row.ex.add(ex);
			if constexpr (S.kind == sites::VfKind::kCore) {
				TypeRow& t = b->type[TypeIdx(type)];
				t.count.add(1);
				t.ticks.add(dt);
				if (dt > t.maxTicks.get()) {
					t.maxTicks.set(dt);
					t.maxForm.set(formID);
				}
				t.hist[HistBucket(dt)].add(1);
			}
			return r;
		}

		template <std::size_t... Is>
		constexpr std::array<Fn4, sizeof...(Is)> MakeVfThunks(std::index_sequence<Is...>) noexcept
		{
			return { &VfThunk<Is>... };
		}

		constexpr auto kTimedThunks = MakeTimedThunks(std::make_index_sequence<kTimedCount>{});
		constexpr auto kVfThunks = MakeVfThunks(std::make_index_sequence<kVfCount>{});

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

		// 6-byte virtual call: FF 90|92 98 00 00 00 (call [rax|rdx+98h]) at the site, and the
		// FNV-1a 64 hash of [site-pre, site+6) equals the validated window hash (the pre bytes
		// load the vtable register from [rcx], which the thunk relies on).
		bool CheckVfSite(const sites::VfSite& a_v, std::uintptr_t& a_site, std::string& a_why)
		{
			const REL::ID       id{ a_v.site.fnId };
			const std::uintptr_t off = id.offset();
			if (off != a_v.site.fnRva) {
				a_why = std::format("site {}: the Address Library maps id {} to RVA 0x{:X}, the verified table says 0x{:X}",
					a_v.site.name, a_v.site.fnId, off, a_v.site.fnRva);
				return false;
			}
			a_site = id.address() + a_v.site.off;
			const std::uintptr_t base = REL::Module::get().base();
			const std::size_t    len = static_cast<std::size_t>(a_v.pre) + 6;
			std::array<std::uint8_t, 12> w{};
			std::memcpy(w.data(), reinterpret_cast<const void*>(a_site - a_v.pre), len);
			const std::uint8_t* call = w.data() + a_v.pre;
			std::int32_t        disp = 0;
			std::memcpy(&disp, call + 2, sizeof(disp));
			const std::uint64_t hash = sites::Fnv1a64(w.data(), len);
			if (g_cfg.verbose) {
				spdlog::info("[verify] {} @RVA 0x{:X}: window {} hash 0x{:016X} (expected 0x{:016X})",
					a_v.site.name, a_site - base, HexBytes(w.data(), len), hash, a_v.windowHash);
			}
			if (call[0] != 0xFF || (call[1] != 0x90 && call[1] != 0x92) || disp != static_cast<std::int32_t>(sites::kInitItemSlotOffset)) {
				a_why = std::format("site {} @RVA 0x{:X}: expected FF 90|92 98 00 00 00, found {}", a_v.site.name, a_site - base,
					HexBytes(call, 6));
				return false;
			}
			if (hash != a_v.windowHash) {
				a_why = std::format("site {} @RVA 0x{:X}: window hash 0x{:016X} != validated 0x{:016X} (another plugin patched the code?) bytes {}",
					a_v.site.name, a_site - base, hash, a_v.windowHash, HexBytes(w.data(), len));
				return false;
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

		void ResolveOsFunctions()
		{
			const auto k32 = REX::W32::GetModuleHandleW(L"kernel32.dll");
			if (!k32) {
				return;
			}
			g_getThreadTimes = reinterpret_cast<decltype(g_getThreadTimes)>(REX::W32::GetProcAddress(k32, "GetThreadTimes"));
			g_getProcessTimes = reinterpret_cast<decltype(g_getProcessTimes)>(REX::W32::GetProcAddress(k32, "GetProcessTimes"));
		}

		// ---- runtime episodes: the Loading Menu -------------------------------------------
		// READ-ONLY event sink on UI's MenuOpenCloseEvent source. It writes nothing into the
		// engine and calls no engine function; it only opens/closes an episode.
		// n-th comma-separated entry of [Episodes] sLabels (CSV/ASCII safe), or "" past the end.
		std::string LabelFor(std::size_t a_n)
		{
			std::size_t start = 0, idx = 0;
			const std::string& l = g_cfg.episodeLabels;
			while (start <= l.size()) {
				std::size_t end = l.find(',', start);
				if (end == std::string::npos) {
					end = l.size();
				}
				if (idx == a_n) {
					std::string out;
					for (std::size_t i = start; i < end; ++i) {
						const auto c = static_cast<unsigned char>(l[i]);
						if (c > 0x20 && c < 0x7F && c != '"') {
							out += static_cast<char>(c);
						}
					}
					return out;
				}
				++idx;
				start = end + 1;
			}
			return std::string();
		}

		void OpenRuntimeEpisode()
		{
			if (!g_dataLoadedSeen.load()) {
				return;
			}
			if (g_curEp.load(std::memory_order_acquire) != nullptr) {
				g_epSkipped.inc();  // the startup episode, or a previous loading screen, is still open
				return;
			}
			const std::uint32_t n = g_epOpened.load(std::memory_order_relaxed);
			if (n >= kMaxRuntimeEpisodes) {
				g_epDropped.inc();
				return;
			}
			Episode& e = g_eps[1 + n];
			e.index = 1 + n;
			e.startup = false;
			e.name = std::format("runtime-loadscreen-{}", n + 1);
			e.label = LabelFor(n);
			e.openTid = Tid();
			e.t0 = std::chrono::steady_clock::now();
			e.tsc0 = __rdtsc();
			e.procCpu0 = ProcessCpu();
			g_epOpened.store(n + 1, std::memory_order_relaxed);
			g_curEp.store(&e, std::memory_order_seq_cst);
		}

		void CloseRuntimeEpisode()
		{
			Episode* e = g_curEp.load(std::memory_order_acquire);
			if (!e || e->startup) {
				return;
			}
			g_curEp.store(nullptr, std::memory_order_seq_cst);
			e->tsc1 = __rdtsc();
			e->t1 = std::chrono::steady_clock::now();
			e->procCpu1 = ProcessCpu();
			e->closeTid = Tid();
			e->closed.store(true);
			WriteRuntimeReport(*e);
		}

		class LoadingMenuSink final : public RE::BSTEventSink<RE::MenuOpenCloseEvent>
		{
		public:
			RE::BSEventNotifyControl ProcessEvent(const RE::MenuOpenCloseEvent* a_event, RE::BSTEventSource<RE::MenuOpenCloseEvent>*) override
			{
				if (a_event && a_event->menuName == "Loading Menu"sv) {
					if (a_event->opening) {
						OpenRuntimeEpisode();
					} else {
						CloseRuntimeEpisode();
					}
				}
				return RE::BSEventNotifyControl::kContinue;
			}
		};
		LoadingMenuSink g_sink;

		void TryReport(const char* a_trigger)
		{
			if (g_state.load() != kClosed) {
				return;
			}
			bool expected = false;
			if (!g_reported.compare_exchange_strong(expected, true)) {
				return;
			}
			WriteStartupReport(a_trigger);
			g_state.store(kDone);  // the startup episode is finished
			spdlog::info("[probe] startup report written.{}", g_grp[kRuntime].installed ?
				" Runtime Loading Menu episodes are reported as they close." :
				" No runtime episodes (off, or the sink is not registered); all hooks are idle pass-through now.");
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
		g_grp[kLfCallees].requested = a_config.lfCallees;
		g_grp[kInitPass].requested = a_config.initPass;
		g_grp[kPerForm].requested = a_config.perForm;
		g_grp[kInitRefs].requested = a_config.initRefs;
		g_grp[kLoopSplit].requested = a_config.loopSplit;
		g_grp[kNewForms].requested = a_config.newForms;
		g_grp[kRuntime].requested = a_config.runtimeEpisodes;

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

		// Preallocated state: no allocation in any thunk.
		ResolveOsFunctions();
		g_eps = std::make_unique<Episode[]>(kMaxEpisodes);
		g_eps[0].index = 0;
		g_eps[0].startup = true;
		g_eps[0].name = "startup";
		g_eps[0].label = "launch";
		g_blocks = std::make_unique<Block[]>(kMaxBlocks);
		g_slots = std::make_unique<Slot[]>(kMaxSlots);
		g_files = std::make_unique<FileRow[]>(kFileRows);

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
					spdlog::info("[verify] ReadData prologue @RVA 0x{:X}: {}", sites::kReadData.rva, HexBytes(p, sites::kReadDataPrologueLen));
				}
				const auto found = sites::Fnv1a64(p, sites::kReadDataPrologueLen);
				if (found == sites::kReadDataPrologueHash) {
					doRawRead = true;
				} else {
					Refuse(kRawRead, std::format("ReadData prologue mismatch (another detour?): found {} (hash 0x{:016X}), expected hash 0x{:016X}",
										 HexBytes(p, sites::kReadDataPrologueLen), found, sites::kReadDataPrologueHash));
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

		// ---- v2 E8 groups: all-or-nothing per owner ----
		std::array<std::uintptr_t, kTimedCount> timedCallee{}, timedSite{};
		const auto verifyOwner = [&](sites::Owner a_owner, Group a_g, bool a_requested) -> bool {
			if (!a_requested) {
				return false;
			}
			std::string w;
			for (std::size_t i = 0; i < kTimedCount; ++i) {
				const auto&    s = sites::kTimedSites[i];
				std::uintptr_t actual = 0;
				if (s.owner != a_owner) {
					continue;
				}
				if (!CheckFn(s.callee, timedCallee[i], w) || !CheckCallSite(s.site, timedCallee[i], timedSite[i], actual, w)) {
					Refuse(a_g, w);
					return false;
				}
			}
			return true;
		};
		const bool doLf = verifyOwner(sites::Owner::kLoadFiles, kLfCallees, a_config.lfCallees);
		const bool doIp = verifyOwner(sites::Owner::kInitPass, kInitPass, a_config.initPass);
		const bool doLoop = verifyOwner(sites::Owner::kPluginLoop, kLoopSplit, a_config.loopSplit);
		const bool doNew = verifyOwner(sites::Owner::kRecord, kNewForms, a_config.newForms);

		// ---- v2 virtual sites: all-or-nothing per group ----
		std::array<std::uintptr_t, kVfCount> vfSite{};
		const auto                           verifyVf = [&](Group a_g, bool a_requested) -> bool {
            if (!a_requested) {
                return false;
            }
            std::string w;
            for (std::size_t i = 0; i < kVfCount; ++i) {
                if (VfGroup(i) != a_g) {
                    continue;
                }
                if (!CheckVfSite(sites::kVfSites[i], vfSite[i], w)) {
                    Refuse(a_g, w);
                    return false;
                }
            }
            return true;
		};
		const bool doVfPass = verifyVf(kInitPass, a_config.initPass);
		const bool doVfCore = verifyVf(kPerForm, a_config.perForm);
		const bool doVfRefs = verifyVf(kInitRefs, a_config.initRefs);

		// ---- patch. Originals are stored BEFORE each patch (the thunk can run the
		// instant the E8 is rewritten) and are the VERIFIED targets. ----
		// v1: 9 distinct thunks x 14-byte stubs + a 19-byte gateway. v2: up to 55 E8
		// thunks (14 bytes each) + 10 virtual thunks (8-byte slots). 4 KiB is headroom
		// (the validation doc asks for at least 2 KiB).
		SKSE::AllocTrampoline(4096);
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

		const auto patchOwner = [&](sites::Owner a_owner, Group a_g) {
			std::size_t n = 0;
			for (std::size_t i = 0; i < kTimedCount; ++i) {
				if (sites::kTimedSites[i].owner != a_owner) {
					continue;
				}
				g_timedOrig[i] = timedCallee[i];
				CheckPrev(a_g, tr.write_call<5>(timedSite[i], kTimedThunks[i]), timedCallee[i]);
				++n;
			}
			Patched(a_g, n);
		};
		if (doLf) {
			patchOwner(sites::Owner::kLoadFiles, kLfCallees);
		}
		if (doLoop) {
			patchOwner(sites::Owner::kPluginLoop, kLoopSplit);
		}
		if (doNew) {
			patchOwner(sites::Owner::kRecord, kNewForms);
		}
		// initPass = the 22 E8 rows AND its 5 virtual rows, all-or-nothing together.
		const bool doInitPass = doIp && doVfPass;
		if (doInitPass) {
			patchOwner(sites::Owner::kInitPass, kInitPass);
		}

		// The 6-byte virtual sites. write_call<6>'s return value is garbage for these sites
		// (it assumes the original was rip-relative); it is deliberately ignored.
		const auto patchVf = [&](Group a_g) {
			std::size_t n = 0;
			for (std::size_t i = 0; i < kVfCount; ++i) {
				if (VfGroup(i) != a_g) {
					continue;
				}
				(void)tr.write_call<6>(vfSite[i], kVfThunks[i]);
				++n;
			}
			// the group counter of kInitPass covers the E8 rows too: report the virtual rows added
			g_grp[a_g].installed = true;
			g_grp[a_g].sites += n;
			spdlog::info("[install] {}: {} virtual-call site(s) patched.", kGroupNames[a_g], n);
		};
		if (doInitPass) {
			patchVf(kInitPass);
		}
		if (doVfCore) {
			patchVf(kPerForm);
		}
		if (doVfRefs) {
			patchVf(kInitRefs);
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

		// Runtime episodes: a read-only sink on the main thread (kDataLoaded is posted there).
		if (g_gateInstalled && g_cfg.runtimeEpisodes && !g_grp[kRuntime].installed) {
			if (auto* ui = RE::UI::GetSingleton()) {
				ui->AddEventSink<RE::MenuOpenCloseEvent>(&g_sink);
				g_grp[kRuntime].installed = true;
				spdlog::info("[install] {} registered (menu 'Loading Menu'; up to {} episodes).", kGroupNames[kRuntime], kMaxRuntimeEpisodes);
			} else {
				g_grp[kRuntime].why = "RE::UI singleton not available at kDataLoaded";
				spdlog::warn("[install] {} NOT registered: {}", kGroupNames[kRuntime], g_grp[kRuntime].why);
			}
		}

		if (!g_gateInstalled) {
			bool expected = false;
			if (g_reported.compare_exchange_strong(expected, true)) {
				WriteStartupReport("kDataLoaded");
			}
			return;
		}
		int st = g_state.load();
		if (st == kIdle) {
			if (g_state.compare_exchange_strong(st, kDone)) {
				bool expected = false;
				if (g_reported.compare_exchange_strong(expected, true)) {
					WriteStartupReport("kDataLoaded (startup LoadFiles never entered)");
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
