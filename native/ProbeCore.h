#pragma once

// Internal data model of the LT-2b probe, shared by Probe.cpp (hooks, install,
// episodes) and Report.cpp (text report, CSV). Not a public API.
//
// EPISODES. An episode is a bounded loading event with its own tables:
//   episode 0              "startup"                  the startup LoadFiles (13753) call (the gate)
//   episodes 1..N          "runtime-loadscreen-<n>"   the Loading Menu open..close
// At most ONE episode is open at a time (g_curEp). A hot thunk loads g_curEp;
// null means "no episode open" and the thunk returns straight into the original
// (that is the zero-overhead gate). Later episodes (e.g. an exterior-streaming
// episode) are added by adding hook sites and an open/close trigger; the tables,
// the report and the CSV already key every row by episode.
//
// SINGLE-WRITER BLOCKS. Each (thread, episode) pair claims one preallocated
// Block on its first hooked call; only that thread writes it, so a plain
// load+store is exact and no atomic read-modify-write is needed on the hot path.
// The report merges the blocks of an episode.

#include "Probe.h"
#include "Sites.h"

#include <array>
#include <atomic>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace lt::probe::core
{
	namespace sites = lt::sites;

	using Fn4 = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);
	using Fn5 = std::uint64_t (*)(std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);

	inline constexpr std::uint32_t kCompressedFlag = 0x40000;  // record flag tested by ReadData at 0x1C8674

	// formArrays[] / FormType::Max. The per-type tables have one extra "OTHER" bucket.
	inline constexpr std::size_t kTypeCount = 0x8A;
	inline constexpr std::size_t kTypeSlots = kTypeCount + 1;
	static_assert(static_cast<std::size_t>(std::to_underlying(RE::FormType::Max)) == kTypeCount);

	// TESForm layout read by the thunks, from the CommonLib header (sizeof(TESForm) == 0x20):
	// formFlags +0x10, formID +0x14, formType +0x1A. Read as raw bytes (TESForm is polymorphic,
	// so offsetof is not usable); the LT-1b doc [I] says InitItem's loop type index equals this byte.
	inline constexpr std::uintptr_t kFormFlagsOff = 0x10;
	inline constexpr std::uintptr_t kFormIdOff = 0x14;
	inline constexpr std::uintptr_t kFormTypeOff = 0x1A;

	[[nodiscard]] inline std::uint8_t FormTypeByte(std::uint64_t a_form) noexcept
	{
		return *reinterpret_cast<const std::uint8_t*>(a_form + kFormTypeOff);
	}
	[[nodiscard]] inline std::uint32_t FormIdOf(std::uint64_t a_form) noexcept
	{
		return *reinterpret_cast<const std::uint32_t*>(a_form + kFormIdOff);
	}
	[[nodiscard]] inline std::size_t TypeIdx(std::uint8_t a_type) noexcept
	{
		return a_type < kTypeCount ? static_cast<std::size_t>(a_type) : kTypeCount;
	}

	inline constexpr std::size_t kHistBuckets = 24;   // bucket b = floor(log2(ticks)) - kHistMinLog2, clamped
	inline constexpr unsigned    kHistMinLog2 = 6;    // bucket 0 = < 128 ticks
	inline constexpr std::size_t kTopHeavy = 25;
	inline constexpr std::size_t kSigSlots = 256;     // distinct record signatures per block (power of two)
	inline constexpr std::uint32_t kMaxSlots = 8192;  // > 254 full + 4096 light plugins
	inline constexpr std::size_t kMaxRuntimeEpisodes = 48;
	inline constexpr std::size_t kMaxEpisodes = 1 + kMaxRuntimeEpisodes;
	inline constexpr std::uint32_t kMaxBlocks = 160;  // one per (thread, episode)
	inline constexpr std::size_t kFileRows = 16384;   // per-file column table (power of two)

	inline constexpr std::size_t kTimedCount = sites::kTimedSites.size();
	inline constexpr std::size_t kVfCount = sites::kVfSites.size();
	inline constexpr std::size_t kColCount = static_cast<std::size_t>(sites::Col::kNewForm) + 1;

	[[nodiscard]] inline std::size_t HistBucket(std::uint64_t a_ticks) noexcept
	{
		if (a_ticks < (1ULL << (kHistMinLog2 + 1))) {
			return 0;
		}
		const unsigned lg = 63u - static_cast<unsigned>(std::countl_zero(a_ticks));
		const std::size_t b = lg - kHistMinLog2;
		return b < kHistBuckets ? b : kHistBuckets - 1;
	}

	// ---- accumulators -------------------------------------------------------
	// Single-writer: a plain load+store is exact, and the atomic type makes the
	// report's cross-thread read well-defined. On x64 both compile to plain movs.
	struct Acc
	{
		std::atomic<std::uint64_t> v{ 0 };
		void add(std::uint64_t a_d) noexcept { v.store(v.load(std::memory_order_relaxed) + a_d, std::memory_order_relaxed); }
		void set(std::uint64_t a_d) noexcept { v.store(a_d, std::memory_order_relaxed); }
		[[nodiscard]] std::uint64_t get() const noexcept { return v.load(std::memory_order_relaxed); }
	};

	struct Acc32
	{
		std::atomic<std::uint32_t> v{ 0 };
		void add(std::uint32_t a_d) noexcept { v.store(v.load(std::memory_order_relaxed) + a_d, std::memory_order_relaxed); }
		void set(std::uint32_t a_d) noexcept { v.store(a_d, std::memory_order_relaxed); }
		[[nodiscard]] std::uint32_t get() const noexcept { return v.load(std::memory_order_relaxed); }
	};

	// Multi-writer counter for the rare paths (foreign thread, exhausted pool).
	struct Ctr
	{
		std::atomic<std::uint64_t> v{ 0 };
		void inc() noexcept { v.fetch_add(1, std::memory_order_relaxed); }
		[[nodiscard]] std::uint64_t get() const noexcept { return v.load(std::memory_order_relaxed); }
	};

	// A tiny lock-free set of thread ids (no allocation, bounded).
	struct TidSet
	{
		std::array<std::atomic<std::uint32_t>, 8> t{};
		std::atomic<std::uint32_t>                over{ 0 };
		void note(std::uint32_t a_id) noexcept
		{
			for (auto& s : t) {
				std::uint32_t v = s.load(std::memory_order_relaxed);
				if (v == a_id) {
					return;
				}
				if (v == 0) {
					std::uint32_t expected = 0;
					if (s.compare_exchange_strong(expected, a_id, std::memory_order_relaxed) || expected == a_id) {
						return;
					}
				}
			}
			over.fetch_add(1, std::memory_order_relaxed);
		}
	};

	// ---- groups -------------------------------------------------------------
	enum Group : std::size_t
	{
		kGate,
		kPerPlugin,
		kRecord,
		kLoadBody,
		kRawRead,
		kInflate,
		kPostLoop,
		kLfCallees,
		kInitPass,
		kPerForm,
		kInitRefs,
		kLoopSplit,
		kNewForms,
		kRuntime,
		kGroupCount
	};

	inline constexpr std::array<const char*, kGroupCount> kGroupNames{
		"gate      13753 LoadFiles (startup call)",
		"perPlugin 13760 per-plugin loader",
		"record    13763 per-record dispatcher",
		"loadBody  13690 Load wrapper",
		"rawRead   13991 TESFile::ReadData",
		"inflate   14032 TESFile inflate",
		"postLoop  13784 InitItem pass",
		"lfCallees 13753 direct callees (25 E8 sites)",
		"initPass  13784 callees + phase markers",
		"perForm   13784 per-form InitItem (type table)",
		"initRefs  WRLD/cell/ref InitItem (20455,20563,18882)",
		"loopSplit 13760 internals (7 E8 sites)",
		"newForms  13763 -> 13693 AddFormToDataHandler",
		"runtime   Loading Menu episodes (UI sink, no hook)",
	};

	struct GroupState
	{
		bool        requested = false;
		bool        installed = false;
		std::size_t sites = 0;
		std::string why;
		Ctr         foreign;  // calls on a thread the startup episode does not measure
	};

	// ---- per-plugin slots (startup) / the single totals slot (runtime) ----------
	// Slot 0 = work inside the episode but outside any 13760 call.
	struct Slot
	{
		std::atomic<const RE::TESFile*> file{ nullptr };
		Acc wall;        // 13760 inclusive ticks
		Acc loopEx;      // 13760 exclusive ticks
		Acc records;     // 13763 calls from the R6 site
		Acc compressed;  // ... whose record header carried the compressed flag
		Acc recEx;       // 13763 exclusive ticks
		Acc loadN;
		Acc loadEx;      // 13690 exclusive ticks
		Acc readN;
		Acc readEx;      // 13991 exclusive ticks (minus nested inflate)
		Acc inflN;
		Acc inflEx;      // 14032 ticks
		Acc inflIn;      // compressed bytes
		Acc inflOut;     // decompressed bytes
		std::array<Acc, kColCount> colT;  // 13760-internal columns: exclusive ticks (loopSplit)
		std::array<Acc, kColCount> colN;
	};

	// Per-file columns of the 13753 file loop / pass 1 (load thread only, startup only).
	struct FileRow
	{
		std::atomic<const void*> file{ nullptr };
		std::array<Acc, 4>       t;  // 0 compile index, 1 BSA name gate, 2 BSA auto-load, 3 pass-1 OpenTES (exclusive ticks)
		Acc                      gateTrue;  // 453528 returned al != 0
	};

	// ---- per-block tables --------------------------------------------------------
	struct SigRow
	{
		Acc32 key;  // record signature as the little-endian dword; 0 = empty
		Acc   count;
		Acc   ticks;       // Load inclusive
		Acc   exTicks;     // Load exclusive (minus nested read/inflate)
		Acc   bytes;       // record data size (header length field) summed
		Acc   compressed;  // records with the compressed flag
	};

	struct TypeRow
	{
		Acc   count;
		Acc   ticks;  // inclusive of recursive un-hooked inits (LT-2b doc section 5.5)
		Acc   maxTicks;
		Acc32 maxForm;
		std::array<Acc32, kHistBuckets> hist;
	};

	struct CalleeRow
	{
		Acc n;
		Acc ticks;
		Acc ex;
		Acc kern;  // kernel / user thread time (100 ns) across the call; only filled for the
		Acc user;  // 13753 and 13784 E8 rows (call counts are small enough for a GetThreadTimes pair)
	};

	struct HeavyRow
	{
		Acc                             ticks;
		Acc32                           formID;
		Acc32                           sig;
		std::atomic<const RE::TESFile*> file{ nullptr };
	};

	// Thread CPU time pair (declared before Block, which stores two of them).
	struct CpuTimes
	{
		std::uint64_t kern = 0;  // 100 ns units
		std::uint64_t user = 0;
	};

	struct PhaseRow
	{
		Acc wall;     // TSC ticks
		Acc kern;     // thread KERNEL time, 100 ns units, 0 if unavailable
		Acc user;     // thread USER time, 100 ns units, 0 if unavailable
		Acc entries;  // how many times the phase was entered
	};

	struct Block
	{
		std::atomic<std::uint32_t> episode{ 0xFFFFFFFFu };
		std::atomic<std::uint32_t> tid{ 0 };
		bool                       startup = false;  // owner-only: phase/segment markers and per-file columns are active

		Slot*                      slots = nullptr;  // g_slots (startup) or &rt (runtime)
		std::uint32_t              slotCap = 1;
		std::atomic<std::uint32_t> slotCount{ 1 };
		Acc                        slotOverflow;
		std::uint32_t              cur = 0;  // owner-only: current slot

		std::array<Acc, kGroupCount> measured;

		// owner-only marker state
		std::int8_t   iiPhase = -1;
		std::int8_t   lfSeg = -1;
		std::uint32_t avifHits = 0;
		std::uint64_t iiStart = 0, lfStart = 0;
		CpuTimes      iiCpu0, lfCpu0;
		std::array<PhaseRow, sites::kIiPhaseCount> ii;
		std::array<PhaseRow, sites::kLfSegCount>   lf;

		std::array<CalleeRow, kTimedCount> callee;
		std::array<CalleeRow, kVfCount>    vf;

		std::array<SigRow, kSigSlots> sig;
		Acc                           sigOverflow;
		std::array<TypeRow, kTypeSlots> type;
		std::array<Acc, kTypeSlots>     newForms;
		std::array<Acc, kTypeSlots>     newFormTicks;

		std::array<HeavyRow, kTopHeavy> heavy;
		std::uint64_t                   heavyMin = 0;  // owner-only
		std::uint32_t                   heavyMinIdx = 0;

		Acc readBytes;
		Acc loadFilesTicks, loadFilesEx;    // 13753 (startup gate)
		Acc initItemsTicks, initItemsEx;    // 13784 (v1 site)

		// inflate diagnostics (LT-1 section 7 item 2)
		std::array<Acc, sites::kInflateSites.size()> inflBySite;
		Acc                                          inflPreset, inflRepeat, inflForeignFile, inflNullFile, inflFailed;
		const RE::TESFile*                           lastInflFile = nullptr;  // owner-only
		std::uint32_t                                lastInflOffset = 0;
		std::uint32_t                                lastInflFormID = 0;

		Slot rt;  // totals slot of a runtime episode block
	};

	// ---- episodes ------------------------------------------------------------------
	struct Episode
	{
		std::uint32_t index = 0;
		bool          startup = false;
		std::string   name;
		std::atomic<std::uint32_t> loadTid{ 0 };  // startup: the only measured thread
		std::string   label;  // free text for matching the tester's routine to episodes by order (INI [Episodes] sLabels)
		std::uint32_t openTid = 0, closeTid = 0;
		std::chrono::steady_clock::time_point t0{}, t1{};
		std::uint64_t tsc0 = 0, tsc1 = 0;
		std::uint64_t procCpu0 = 0, procCpu1 = 0;  // whole-process CPU, 100 ns units
		std::atomic<bool> closed{ false };
	};

	struct Tls
	{
		const Episode* ep = nullptr;
		Block*         blk = nullptr;
		std::uint64_t  child = 0;  // ticks spent in hooked children of the current scope
		bool           exhausted = false;
	};
	inline thread_local Tls t_tls;

	// ---- startup state machine --------------------------------------------------------
	enum State : int
	{
		kIdle = 0,    // installed, startup LoadFiles not entered yet
		kArming = 1,  // gate thunk is filling the window fields
		kActive = 2,  // measuring
		kClosed = 3,  // LoadFiles returned; data frozen
		kDone = 4     // startup report written (or probe inactive)
	};

	// ---- globals (inline: one definition across the two TUs) ------------------------------
	inline std::atomic<Episode*>       g_curEp{ nullptr };
	inline std::atomic<int>            g_state{ kDone };  // kDone until Install succeeds
	inline std::atomic<std::uint32_t>  g_loadTid{ 0 };
	inline std::atomic<bool>           g_dataLoadedSeen{ false };
	inline std::atomic<bool>           g_reported{ false };
	inline std::atomic<std::uint32_t>  g_dataLoadedTid{ 0 };

	inline Config      g_cfg{};
	inline bool        g_gateInstalled = false;
	inline bool        g_gateChained = false;
	inline std::string g_inactiveWhy;
	inline GroupState  g_grp[kGroupCount];

	inline std::unique_ptr<Episode[]>  g_eps;     // [0] = startup
	inline std::unique_ptr<Block[]>    g_blocks;
	inline std::atomic<std::uint32_t>  g_blockNext{ 0 };
	inline Ctr                         g_blockDrops;     // calls dropped because the block pool was exhausted
	inline std::unique_ptr<Slot[]>     g_slots;          // startup per-plugin slots
	inline std::unique_ptr<FileRow[]>  g_files;          // startup per-file columns
	inline Ctr                         g_fileRowDrops;
	inline std::atomic<std::uint32_t>  g_epOpened{ 0 };  // runtime episodes opened so far
	inline Ctr                         g_epDropped;      // loading screens past kMaxRuntimeEpisodes
	inline Ctr                         g_epSkipped;      // loading screens that opened while another episode was open

	// thread-id sets: startup phases/segments, and every foreign thread seen by the gate
	inline std::array<TidSet, sites::kIiPhaseCount> g_iiTids;
	inline std::array<TidSet, sites::kLfSegCount>   g_lfTids;
	inline TidSet                                   g_foreignTids;
	inline std::atomic<int>                         g_pubIi{ -1 };  // load thread's current phase / segment, for foreign-thread attribution
	inline std::atomic<int>                         g_pubLf{ -1 };

	// Resolved at install (never in a hot path). Null if the OS does not export them.
	struct FileTime
	{
		std::uint32_t lo;
		std::uint32_t hi;
	};
	inline int (*g_getThreadTimes)(void*, FileTime*, FileTime*, FileTime*, FileTime*) = nullptr;
	inline int (*g_getProcessTimes)(void*, FileTime*, FileTime*, FileTime*, FileTime*) = nullptr;

	// The MIT fork has no SKSE::WinAPI (that was the pre-fork NG API); REX::W32 is its Win32 layer.
	[[nodiscard]] inline std::uint32_t Tid() noexcept { return REX::W32::GetCurrentThreadId(); }

	[[nodiscard]] inline std::uint64_t Ft64(const FileTime& a_f) noexcept
	{
		return static_cast<std::uint64_t>(a_f.lo) | (static_cast<std::uint64_t>(a_f.hi) << 32);
	}

	// Calling thread's kernel and user time SEPARATELY, 100 ns units; zeros if unavailable.
	[[nodiscard]] inline CpuTimes ThreadCpu() noexcept
	{
		CpuTimes r;
		if (!g_getThreadTimes) {
			return r;
		}
		FileTime c{}, e{}, k{}, u{};
		if (g_getThreadTimes(reinterpret_cast<void*>(static_cast<std::intptr_t>(-2)), &c, &e, &k, &u) == 0) {
			return r;
		}
		r.kern = Ft64(k);
		r.user = Ft64(u);
		return r;
	}

	// Whole-process CPU time (kernel + user), 100 ns units; 0 if unavailable.
	[[nodiscard]] inline std::uint64_t ProcessCpu() noexcept
	{
		if (!g_getProcessTimes) {
			return 0;
		}
		FileTime c{}, e{}, k{}, u{};
		if (g_getProcessTimes(reinterpret_cast<void*>(static_cast<std::intptr_t>(-1)), &c, &e, &k, &u) == 0) {
			return 0;
		}
		return Ft64(k) + Ft64(u);
	}

	// ---- implemented in Report.cpp ---------------------------------------------------------
	// Startup report (text + CSV). Called once, from the thread that wins g_reported.
	void WriteStartupReport(const char* a_trigger);
	// Runtime episode report (text + CSV append). Called on the thread that closed the episode.
	void WriteRuntimeReport(const Episode& a_ep);
}
