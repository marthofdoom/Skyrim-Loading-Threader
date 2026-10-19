#include "PCH.h"

#include "Oracle.h"
#include "ProbeCore.h"
#include "Sites.h"

#include <fstream>
#include <map>
#include <thread>
#include <unordered_map>

// =============================================================================
// Report: the human-readable log report and the sectioned CSV
// (LoadingThreader-v2.csv next to the log). Every table is built once as a
// `Table` and emitted twice: aligned text into the log, and a CSV section
// whose first column is always `episode`.
//
// Runs on the thread that closes an episode (startup: kDataLoaded / the
// LoadFiles exit; runtime: the main thread at Loading Menu close). It reads
// the single-writer blocks with relaxed loads; a thread still inside a thunk
// when its episode closes can add a last call after the merge (documented).
// =============================================================================

namespace lt::probe::core
{
	namespace
	{
		// ---- names -----------------------------------------------------------
		constexpr std::array<const char*, sites::kIiPhaseCount> kIiNames{
			"P0 DOBJ", "P1 FLST", "P2 misc", "P3 core", "P4 AVIF", "P5 NPC_", "P6 RACE", "P7 NAVI", "P8 WRLD", "P9 cells", "P10 tail"
		};
		constexpr std::array<const char*, sites::kLfSegCount> kLfNames{
			"setup", "file loop", "pass-1 OpenTES", "hard-coded forms", "buffer -3", "plugin loop", "buffer -1", "InitItem pass", "navmesh tail"
		};
		constexpr std::array<const char*, kColCount> kColNames{
			"-", "compile index", "BSA name gate", "BSA auto-load", "pass-1 OpenTES", "OpenTES (2nd open)", "TES4 header + masters",
			"15469 misc", "SeekNextForm", "R7 LookupByID", "R7 editor-ID insert", "CloseTES", "new form insert"
		};
		constexpr std::array<const char*, kVfCount> kVfNames{
			"DOBJ", "FLST", "core per-form", "AVIF", "NAVI", "WRLD", "WRLD persistentCell", "WRLD child cell", "cell ref (list A)", "cell ref (list B)"
		};

		// ---- formatting helpers ------------------------------------------------
		template <class T>
		std::string S(const T& a_v)
		{
			return std::format("{}", a_v);
		}
		std::string F1(double a_v) { return std::format("{:.1f}", a_v); }
		std::string F2(double a_v) { return std::format("{:.2f}", a_v); }
		std::string F3(double a_v) { return std::format("{:.3f}", a_v); }
		std::string Hex32(std::uint32_t a_v) { return std::format("{:08X}", a_v); }
		std::string Hex64(std::uint64_t a_v) { return std::format("0x{:016X}", a_v); }

		std::string SafeName(const RE::TESFile* a_f)
		{
			if (!a_f) {
				return "(null file)";
			}
			std::string s;
			for (std::size_t i = 0; i < sizeof(a_f->fileName) && a_f->fileName[i] != '\0'; ++i) {
				const auto c = static_cast<unsigned char>(a_f->fileName[i]);
				s += (c >= 0x20 && c < 0x7F && c != ',' && c != '"') ? static_cast<char>(c) : '?';  // ASCII only, CSV-safe
			}
			return s.empty() ? std::string("(empty name)") : s;
		}

		std::string SigName(std::uint32_t a_sig)
		{
			std::string s;
			for (int i = 0; i < 4; ++i) {
				const auto c = static_cast<unsigned char>((a_sig >> (8 * i)) & 0xFF);
				s += (c >= 0x20 && c < 0x7F && c != ',' && c != '"') ? static_cast<char>(c) : '?';
			}
			return s;
		}

		std::string TypeName(std::size_t a_t)
		{
			if (a_t >= kTypeCount) {
				return "OTHER";
			}
			const auto sv = RE::FormTypeToString(static_cast<RE::FormType>(a_t));
			if (sv.empty() || sv == "NONE") {
				return std::format("T{:02X}", a_t);
			}
			return std::string(sv);
		}

		std::string TidList(const TidSet& a_s)
		{
			std::string s;
			for (const auto& t : a_s.t) {
				const auto v = t.load(std::memory_order_relaxed);
				if (v != 0) {
					s += std::format("{}{}", s.empty() ? "" : "|", v);
				}
			}
			if (const auto o = a_s.over.load(std::memory_order_relaxed)) {
				s += std::format("|+{}more", o);
			}
			return s.empty() ? std::string("-") : s;
		}

		std::string CsvCell(std::string a_s)
		{
			for (auto& c : a_s) {
				if (c == ',' || c == '"' || c == '\n' || c == '\r') {
					c = '_';
				}
			}
			return a_s;
		}

		// ---- table / output ------------------------------------------------------
		struct Table
		{
			std::string                           name;   // CSV section name
			std::string                           title;  // text heading
			std::string                           align;  // one of 'l'/'r' per column (default r)
			std::vector<std::string>              cols;
			std::vector<std::vector<std::string>> rows;
			std::size_t                           textRows = static_cast<std::size_t>(-1);  // text shows at most this many; CSV all
			bool                                  csvBlankNa = false;  // CSV writes "n/a" cells as empty
			std::vector<std::string>              csvExtraCols;                           // CSV-only trailing columns
			std::vector<std::vector<std::string>> csvExtra;                               // parallel to rows
		};

		struct Out
		{
			std::string episode;
			bool        wantCsv = false;
			std::string csv;

			void Line(const std::string& a_s) { spdlog::info("{}", a_s); }

			void Tab(const Table& a_t)
			{
				// ---- text ----
				const std::size_t shown = std::min(a_t.rows.size(), a_t.textRows);
				if (a_t.rows.empty()) {
					Line(std::format("{}: (no rows)", a_t.title));
				} else {
					std::vector<std::size_t> w(a_t.cols.size(), 0);
					for (std::size_t c = 0; c < a_t.cols.size(); ++c) {
						w[c] = a_t.cols[c].size();
					}
					for (std::size_t r = 0; r < shown; ++r) {
						for (std::size_t c = 0; c < a_t.cols.size() && c < a_t.rows[r].size(); ++c) {
							w[c] = std::max(w[c], a_t.rows[r][c].size());
						}
					}
					const auto fmtRow = [&](const std::vector<std::string>& a_r) {
						std::string s = " ";
						for (std::size_t c = 0; c < a_t.cols.size(); ++c) {
							const std::string& cell = c < a_r.size() ? a_r[c] : std::string();
							const bool         left = c < a_t.align.size() && a_t.align[c] == 'l';
							const std::size_t  pad = w[c] > cell.size() ? w[c] - cell.size() : 0;
							s += ' ';
							if (left) {
								s += cell;
								if (c + 1 < a_t.cols.size()) {
									s.append(pad, ' ');
								}
							} else {
								s.append(pad, ' ');
								s += cell;
							}
						}
						return s;
					};
					Line(a_t.title);
					Line(fmtRow(a_t.cols));
					for (std::size_t r = 0; r < shown; ++r) {
						Line(fmtRow(a_t.rows[r]));
					}
					if (shown < a_t.rows.size()) {
						Line(std::format("  ... {} more row(s) in the CSV", a_t.rows.size() - shown));
					}
				}
				// ---- csv ----
				if (!wantCsv) {
					return;
				}
				csv += "# section: " + a_t.name + "\n";
				csv += "episode";
				for (const auto& c : a_t.cols) {
					csv += "," + CsvCell(c);
				}
				for (const auto& c : a_t.csvExtraCols) {
					csv += "," + CsvCell(c);
				}
				csv += "\n";
				for (std::size_t r = 0; r < a_t.rows.size(); ++r) {
					csv += CsvCell(episode);
					for (const auto& cell : a_t.rows[r]) {
						csv += "," + ((a_t.csvBlankNa && cell == "n/a") ? std::string() : CsvCell(cell));
					}
					if (r < a_t.csvExtra.size()) {
						for (const auto& cell : a_t.csvExtra[r]) {
							csv += "," + CsvCell(cell);
						}
					}
					csv += "\n";
				}
				csv += "\n";
			}
		};

		std::filesystem::path CsvPath()
		{
			if (auto dir = SKSE::log::log_directory()) {
				return *dir / "LoadingThreader-v2.csv";
			}
			return std::filesystem::path("Data/SKSE/Plugins/LoadingThreader-v2.csv");
		}

		bool g_csvStarted = false;

		void FlushCsv(const Out& a_o)
		{
			if (!a_o.wantCsv || a_o.csv.empty()) {
				return;
			}
			const auto path = CsvPath();
			std::ofstream f(path, std::ios::binary | (g_csvStarted ? std::ios::app : std::ios::trunc));
			if (!f) {
				spdlog::warn("[report] could not open the CSV for writing; text report only.");
				return;
			}
			f << a_o.csv;
			g_csvStarted = true;
		}

		// ---- merged episode data ---------------------------------------------------
		struct Totals
		{
			std::uint64_t wall = 0, loopEx = 0, records = 0, compressed = 0, recEx = 0;
			std::uint64_t loadN = 0, loadEx = 0, readN = 0, readEx = 0;
			std::uint64_t inflN = 0, inflEx = 0, inflIn = 0, inflOut = 0;
			std::array<std::uint64_t, kColCount> colT{}, colN{};
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
				for (std::size_t c = 0; c < kColCount; ++c) {
					colT[c] += a_s.colT[c].get();
					colN[c] += a_s.colN[c].get();
				}
			}
		};

		struct PhaseSum
		{
			std::uint64_t wall = 0, kern = 0, user = 0, entries = 0;
		};
		struct CalleeSum
		{
			std::uint64_t n = 0, ticks = 0, ex = 0;
		};
		struct SigSum
		{
			std::uint32_t key = 0;
			std::uint64_t count = 0, ticks = 0, ex = 0, bytes = 0, compressed = 0;
		};
		struct TypeSum
		{
			std::uint64_t count = 0, ticks = 0, maxTicks = 0;
			std::uint32_t maxForm = 0;
			std::array<std::uint64_t, kHistBuckets> hist{};
		};
		struct HeavySum
		{
			std::uint64_t        ticks = 0;
			std::uint32_t        formID = 0, sig = 0;
			const RE::TESFile*   file = nullptr;
		};

		struct Merged
		{
			Totals                                    tot;
			std::uint32_t                             blocks = 0;
			std::vector<std::uint32_t>                tids;
			std::array<std::uint64_t, kGroupCount>    measured{};
			std::array<PhaseSum, sites::kIiPhaseCount> ii;
			std::array<PhaseSum, sites::kLfSegCount>  lf;
			std::array<CalleeSum, kTimedCount>        callee;
			std::array<CalleeSum, kVfCount>           vf;
			std::map<std::uint32_t, SigSum>           sig;
			std::array<TypeSum, kTypeSlots>           type;
			std::array<std::uint64_t, kTypeSlots>     newForms{}, newFormTicks{};
			std::vector<HeavySum>                     heavy;
			std::uint64_t readBytes = 0, loadFilesTicks = 0, loadFilesEx = 0, initItemsTicks = 0, initItemsEx = 0;
			std::uint64_t slotOverflow = 0, sigOverflow = 0;
			std::array<std::uint64_t, sites::kInflateSites.size()> inflBySite{};
			std::uint64_t inflPreset = 0, inflRepeat = 0, inflForeignFile = 0, inflNullFile = 0, inflFailed = 0;
			std::uint32_t startupSlotCount = 0;  // slots of the startup block (incl. slot 0)
		};

		std::unique_ptr<Merged> Merge(const Episode& a_e)
		{
			auto m = std::make_unique<Merged>();
			const std::uint32_t nb = std::min<std::uint32_t>(g_blockNext.load(), kMaxBlocks);
			for (std::uint32_t bi = 0; bi < nb; ++bi) {
				const Block& b = g_blocks[bi];
				if (b.episode.load(std::memory_order_relaxed) != a_e.index || !b.slots) {
					continue;
				}
				++m->blocks;
				m->tids.push_back(b.tid.load(std::memory_order_relaxed));
				const std::uint32_t sc = std::min<std::uint32_t>(b.slotCount.load(std::memory_order_relaxed), b.slotCap);
				for (std::uint32_t s = 0; s < sc; ++s) {
					m->tot.Add(b.slots[s]);
				}
				if (b.startup) {
					m->startupSlotCount = sc;
				}
				m->slotOverflow += b.slotOverflow.get();
				m->sigOverflow += b.sigOverflow.get();
				for (std::size_t g = 0; g < kGroupCount; ++g) {
					m->measured[g] += b.measured[g].get();
				}
				for (std::size_t i = 0; i < sites::kIiPhaseCount; ++i) {
					m->ii[i].wall += b.ii[i].wall.get();
					m->ii[i].kern += b.ii[i].kern.get();
					m->ii[i].user += b.ii[i].user.get();
					m->ii[i].entries += b.ii[i].entries.get();
				}
				for (std::size_t i = 0; i < sites::kLfSegCount; ++i) {
					m->lf[i].wall += b.lf[i].wall.get();
					m->lf[i].kern += b.lf[i].kern.get();
					m->lf[i].user += b.lf[i].user.get();
					m->lf[i].entries += b.lf[i].entries.get();
				}
				for (std::size_t i = 0; i < kTimedCount; ++i) {
					m->callee[i].n += b.callee[i].n.get();
					m->callee[i].ticks += b.callee[i].ticks.get();
					m->callee[i].ex += b.callee[i].ex.get();
				}
				for (std::size_t i = 0; i < kVfCount; ++i) {
					m->vf[i].n += b.vf[i].n.get();
					m->vf[i].ticks += b.vf[i].ticks.get();
					m->vf[i].ex += b.vf[i].ex.get();
				}
				for (const auto& r : b.sig) {
					const std::uint32_t k = r.key.get();
					if (k == 0) {
						continue;
					}
					SigSum& d = m->sig[k];
					d.key = k;
					d.count += r.count.get();
					d.ticks += r.ticks.get();
					d.ex += r.exTicks.get();
					d.bytes += r.bytes.get();
					d.compressed += r.compressed.get();
				}
				for (std::size_t t = 0; t < kTypeSlots; ++t) {
					TypeSum& d = m->type[t];
					const TypeRow& r = b.type[t];
					d.count += r.count.get();
					d.ticks += r.ticks.get();
					if (r.maxTicks.get() > d.maxTicks) {
						d.maxTicks = r.maxTicks.get();
						d.maxForm = r.maxForm.get();
					}
					for (std::size_t h = 0; h < kHistBuckets; ++h) {
						d.hist[h] += r.hist[h].get();
					}
					m->newForms[t] += b.newForms[t].get();
					m->newFormTicks[t] += b.newFormTicks[t].get();
				}
				for (const auto& h : b.heavy) {
					if (h.ticks.get() != 0) {
						m->heavy.push_back({ h.ticks.get(), h.formID.get(), h.sig.get(), h.file.load(std::memory_order_relaxed) });
					}
				}
				m->readBytes += b.readBytes.get();
				m->loadFilesTicks += b.loadFilesTicks.get();
				m->loadFilesEx += b.loadFilesEx.get();
				m->initItemsTicks += b.initItemsTicks.get();
				m->initItemsEx += b.initItemsEx.get();
				for (std::size_t i = 0; i < sites::kInflateSites.size(); ++i) {
					m->inflBySite[i] += b.inflBySite[i].get();
				}
				m->inflPreset += b.inflPreset.get();
				m->inflRepeat += b.inflRepeat.get();
				m->inflForeignFile += b.inflForeignFile.get();
				m->inflNullFile += b.inflNullFile.get();
				m->inflFailed += b.inflFailed.get();
			}
			std::sort(m->heavy.begin(), m->heavy.end(), [](const HeavySum& a, const HeavySum& b) { return a.ticks > b.ticks; });
			if (m->heavy.size() > kTopHeavy) {
				m->heavy.resize(kTopHeavy);
			}
			return m;
		}

		std::string Ut(std::uint64_t a_100ns) { return F1(static_cast<double>(a_100ns) / 10000.0); }

		struct Clk
		{
			double winMs = 0.0;
			double tpm = 0.0;  // TSC ticks per ms
			double cpuMs = 0.0;
			[[nodiscard]] double Ms(std::uint64_t a_t) const { return tpm > 0.0 ? static_cast<double>(a_t) / tpm : 0.0; }
			[[nodiscard]] double Pct(double a_ms, double a_of) const { return a_of > 0.0 ? 100.0 * a_ms / a_of : 0.0; }
		};

		Clk MakeClk(const Episode& a_e)
		{
			Clk c;
			c.winMs = std::chrono::duration<double, std::milli>(a_e.t1 - a_e.t0).count();
			const double tsc = static_cast<double>(a_e.tsc1 - a_e.tsc0);
			c.tpm = (c.winMs > 0.0 && tsc > 0.0) ? tsc / c.winMs : 0.0;
			c.cpuMs = a_e.procCpu1 >= a_e.procCpu0 ? static_cast<double>(a_e.procCpu1 - a_e.procCpu0) / 10000.0 : 0.0;
			return c;
		}

		// Cost of what every measured call adds: two rdtsc + the thread-id read (like v1).
		double MeasureProbeCostTicks()
		{
			static double s_cached = 0.0;
			if (s_cached > 0.0) {
				return s_cached;
			}
			constexpr int          kN = 200000;
			volatile std::uint64_t sink = 0;
			const std::uint64_t    t0 = __rdtsc();
			for (int i = 0; i < kN; ++i) {
				const std::uint64_t a = __rdtsc();
				sink = sink + Tid();
				const std::uint64_t b = __rdtsc();
				sink = sink + (b - a);
			}
			s_cached = static_cast<double>(__rdtsc() - t0) / kN;
			return s_cached;
		}

		// ---- system header ---------------------------------------------------------------
		struct SysInfo
		{
			unsigned    cores = 0;
			std::string wine;      // wine_get_version() or ""
			bool        protonHint = false;
		};

		SysInfo ReadSysInfo()
		{
			SysInfo s;
			s.cores = std::thread::hardware_concurrency();
			if (const auto nt = REX::W32::GetModuleHandleW(L"ntdll.dll")) {
				using WineVer = const char* (*)();
				if (const auto p = reinterpret_cast<WineVer>(REX::W32::GetProcAddress(nt, "wine_get_version"))) {
					const char* v = p();
					if (v) {
						for (std::size_t i = 0; v[i] != '\0' && i < 64; ++i) {
							const auto c = static_cast<unsigned char>(v[i]);
							s.wine += (c >= 0x20 && c < 0x7F && c != ',' && c != '"') ? static_cast<char>(c) : '?';
						}
					}
				}
			}
			char buf[4] = {};
			s.protonHint = REX::W32::GetEnvironmentVariableA("STEAM_COMPAT_DATA_PATH", buf, sizeof(buf)) != 0;
			return s;
		}

		// ---- common tables ------------------------------------------------------------------
		void GroupsTable(Out& a_o, const Merged* a_m, bool a_startup, const Clk& a_c)
		{
			Table t;
			t.name = "groups";
			t.title = "Hook groups (UNPROVEN = installed but never fired in the startup episode; its zeros mean nothing):";
			t.align = "lllrrrrr";
			t.cols = { "group", "requested", "status", "sites", "measured", "foreign_thread", "est_cost_ms", "est_cost_pct" };
			const double cost = MeasureProbeCostTicks();
			for (std::size_t g = 0; g < kGroupCount; ++g) {
				const auto&        gs = g_grp[g];
				const std::uint64_t meas = a_m ? a_m->measured[g] : 0;
				std::string        status;
				if (!gs.requested) {
					status = "off by INI";
				} else if (!gs.installed) {
					status = "NOT HOOKED: " + (gs.why.empty() ? std::string("unknown") : gs.why);
				} else if (g == kRuntime) {
					status = "registered";
				} else if (a_startup && meas == 0) {
					status = "installed, UNPROVEN: 0 measured calls";
				} else {
					status = "installed";
				}
				const double costMs = a_c.Ms(static_cast<std::uint64_t>(cost * static_cast<double>(meas)));
				t.rows.push_back({ kGroupNames[g], gs.requested ? "yes" : "no", status, S(gs.sites), S(meas), S(gs.foreign.get()),
					F1(costMs), F2(a_c.Pct(costMs, a_c.winMs)) });
			}
			a_o.Tab(t);
		}

		std::string ThreadsOf(const Merged& a_m)
		{
			std::string s;
			for (const auto id : a_m.tids) {
				s += std::format("{}{}", s.empty() ? "" : "|", id);
			}
			return s.empty() ? std::string("-") : s;
		}

		void EpisodeTable(Out& a_o, const Episode& a_e, const Merged& a_m, const Clk& a_c)
		{
			Table t;
			t.name = "episode";
			t.title = "Episode:";
			t.align = "lllrrrrrrrrl";
			t.cols = { "name", "label", "kind", "wall_ms", "tsc_ticks_per_ms", "process_cpu_ms", "cpu_over_wall", "open_tid", "close_tid", "blocks", "block_pool_drops", "threads" };
			t.rows.push_back({ a_e.name, a_e.label.empty() ? std::string("-") : a_e.label, a_e.startup ? "startup" : "runtime", F1(a_c.winMs), F1(a_c.tpm), F1(a_c.cpuMs),
				F2(a_c.winMs > 0.0 ? a_c.cpuMs / a_c.winMs : 0.0), S(a_e.openTid), S(a_e.closeTid), S(a_m.blocks), S(g_blockDrops.get()),
				ThreadsOf(a_m) });
			a_o.Tab(t);
		}

		void SplitSection(Out& a_o, const Episode& a_e, const Merged& a_m, const Clk& a_c)
		{
			const Totals& tot = a_m.tot;
			const double  base = a_e.startup ? a_c.Ms(a_m.loadFilesTicks) : a_c.winMs;
			const double  inflMs = a_c.Ms(tot.inflEx), readMs = a_c.Ms(tot.readEx), loadMs = a_c.Ms(tot.loadEx);
			const double  recMs = a_c.Ms(tot.recEx), loopMs = a_c.Ms(tot.loopEx);
			const double  postMs = a_c.Ms(a_m.initItemsTicks), postExMs = a_c.Ms(a_m.initItemsEx);
			const double  restMs = a_c.Ms(a_m.loadFilesEx);
			Table t;
			t.name = "split";
			t.title = a_e.startup ? "Global split of LoadFiles (exclusive ms, % of LoadFiles):" :
			                        "Hooked work inside the episode (exclusive ms summed over all threads; % of episode wall, may exceed 100):";
			t.align = "lrr";
			t.cols = { "bucket", "ms", "pct" };
			const auto add = [&](const char* a_n, double a_ms) { t.rows.push_back({ a_n, F1(a_ms), F1(a_c.Pct(a_ms, base)) }); };
			add("inflate 14032", inflMs);
			add("raw read 13991 (excl)", readMs);
			add("Load bodies 13690 (excl)", loadMs);
			add("record dispatch 13763 (excl)", recMs);
			add("per-plugin loop 13760 (excl)", loopMs);
			if (a_e.startup) {
				add("post-loop 13784 (incl)", postMs);
				add("LoadFiles rest 13753 (excl; see the callee table)", restMs);
				add("sum of plugin walls 13760 (incl)", a_c.Ms(tot.wall));
			}
			a_o.Tab(t);
			if (a_e.startup) {
				a_o.Line(std::format("  13784 exclusive {:.1f} ms. SHARES: inflate {:.1f} %, raw read {:.1f} %, Load bodies {:.1f} %, post-loop {:.1f} %",
					postExMs, a_c.Pct(inflMs, base), a_c.Pct(readMs, base), a_c.Pct(loadMs, base), a_c.Pct(postMs, base)));
				// ---- decision rule (Docs/LT-2-probe-howto.md) ----
				if (!g_grp[kInflate].installed || a_m.measured[kInflate] == 0) {
					a_o.Line("DECISION: UNPROVEN -- the inflate group did not measure anything.");
				} else if (a_c.Pct(inflMs, base) > 15.0) {
					a_o.Line(std::format("DECISION: inflate share {:.1f} % > 15 %: stage 2 (decompress-ahead pool + RETURN hook at 14032) IS worth building.", a_c.Pct(inflMs, base)));
				} else if (a_c.Pct(inflMs, base) < 5.0) {
					a_o.Line(std::format("DECISION: inflate share {:.1f} % < 5 %: stage 2 is NOT worth building.", a_c.Pct(inflMs, base)));
				} else {
					a_o.Line(std::format("DECISION: inflate share {:.1f} % is in the 5-15 % grey zone: marginal; weigh against the other shares.", a_c.Pct(inflMs, base)));
				}
			}
		}

		void InflateSection(Out& a_o, const Merged& a_m)
		{
			const Totals& tot = a_m.tot;
			Table t;
			t.name = "inflate";
			t.title = "Inflate diagnostics (LT-1 7.2):";
			t.align = "lr";
			t.cols = { "metric", "value" };
			t.rows.push_back({ "inflates", S(tot.inflN) });
			t.rows.push_back({ "bytes_in", S(tot.inflIn) });
			t.rows.push_back({ "bytes_out", S(tot.inflOut) });
			t.rows.push_back({ "ratio_out_over_in", F2(tot.inflIn ? static_cast<double>(tot.inflOut) / static_cast<double>(tot.inflIn) : 0.0) });
			for (std::size_t i = 0; i < sites::kInflateSites.size(); ++i) {
				t.rows.push_back({ std::string("via ") + sites::kInflateSites[i].name, S(a_m.inflBySite[i]) });
			}
			t.rows.push_back({ "records_dispatched_13763", S(tot.records) });
			t.rows.push_back({ "records_with_compressed_flag", S(tot.compressed) });
			t.rows.push_back({ "entered_with_4A0_already_set", S(a_m.inflPreset) });
			t.rows.push_back({ "same_record_inflated_twice_in_a_row", S(a_m.inflRepeat) });
			t.rows.push_back({ "failed_4A0_null_after", S(a_m.inflFailed) });
			t.rows.push_back({ "file_not_current_plugin", S(a_m.inflForeignFile) });
			t.rows.push_back({ "null_file", S(a_m.inflNullFile) });
			a_o.Tab(t);
		}

		void IoSection(Out& a_o, const Episode& a_e, const Merged& a_m, const Clk& a_c)
		{
			const double mb = static_cast<double>(a_m.readBytes) / 1048576.0;
			const double readMs = a_c.Ms(a_m.tot.readEx);
			Table t;
			t.name = "io_indicator";
			t.title = "Warm/cold indicator (raw-read ms per MB; compare runs of the same list, a cold file cache raises it):";
			t.align = "lr";
			t.cols = { "metric", "value" };
			t.rows.push_back({ "raw_read_calls", S(a_m.tot.readN) });
			t.rows.push_back({ "raw_read_bytes", S(a_m.readBytes) });
			t.rows.push_back({ "raw_read_excl_ms", F1(readMs) });
			t.rows.push_back({ "raw_read_ms_per_MB", mb > 0.0 ? F3(readMs / mb) : std::string("n/a") });
			if (a_e.startup && g_files) {
				std::uint64_t ticks = 0, files = 0;
				for (std::size_t i = 0; i < kFileRows; ++i) {
					if (g_files[i].file.load(std::memory_order_relaxed) != nullptr && g_files[i].t[3].get() != 0) {
						ticks += g_files[i].t[3].get();
						++files;
					}
				}
				t.rows.push_back({ "pass1_OpenTES_files", S(files) });
				t.rows.push_back({ "pass1_OpenTES_total_ms", F1(a_c.Ms(ticks)) });
				t.rows.push_back({ "pass1_OpenTES_ms_per_file", files ? F3(a_c.Ms(ticks) / static_cast<double>(files)) : std::string("n/a") });
			}
			a_o.Tab(t);
		}

		void LfSections(Out& a_o, const Merged& a_m, const Clk& a_c)
		{
			const double lfMs = a_c.Ms(a_m.loadFilesTicks);
			{
				Table t;
				t.name = "lf_segments";
				t.title = "LoadFiles (13753) segments (monotonic markers; wall sums to the LoadFiles total):";
				t.align = "lrrrrrl";
				t.cols = { "segment", "wall_ms", "kernel_ms", "user_ms", "pct_of_13753", "entries", "threads" };
				std::uint64_t sum = 0;
				for (std::size_t i = 0; i < sites::kLfSegCount; ++i) {
					const auto& p = a_m.lf[i];
					sum += p.wall;
					t.rows.push_back({ kLfNames[i], F1(a_c.Ms(p.wall)), Ut(p.kern), Ut(p.user),
						F1(a_c.Pct(a_c.Ms(p.wall), lfMs)), S(p.entries), TidList(g_lfTids[i]) });
				}
				a_o.Tab(t);
				a_o.Line(std::format("  segments sum {:.1f} ms of LoadFiles {:.1f} ms (a mismatch means a marker group was off)", a_c.Ms(sum), lfMs));
			}
			{
				struct Row
				{
					std::uintptr_t rva;
					std::string    name;
					std::uint64_t  n, ticks, ex;
					std::string    kern, user;
				};
				std::vector<Row> rows;
				for (std::size_t i = 0; i < kTimedCount; ++i) {
					const auto& s = sites::kTimedSites[i];
					if (s.owner != sites::Owner::kLoadFiles) {
						continue;
					}
					rows.push_back({ s.site.siteRva, std::format("{} -> {}", s.site.name, s.callee.name), a_m.callee[i].n, a_m.callee[i].ticks, a_m.callee[i].ex,
						"n/a", "n/a" });
				}
				// the three v1 direct callees, in code order with the rest
				std::uint64_t plugins = a_m.startupSlotCount > 0 ? a_m.startupSlotCount - 1 : 0;
				rows.push_back({ 0x1B9A03, "LF+0x323/+0x343 -> 13760 per-plugin loader (both sites)", plugins, a_m.tot.wall, a_m.tot.loopEx, "-", "-" });
				rows.push_back({ sites::kInitItemsSite.siteRva, "LF+0x363 -> 13784 InitItem pass", a_m.measured[kPostLoop], a_m.initItemsTicks, a_m.initItemsEx, "-", "-" });
				std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) { return a.rva < b.rva; });
				Table t;
				t.name = "lf_callees";
				t.csvBlankNa = true;
				t.title = "13753 direct callees in code order (incl/excl ms; 'excl' for 13760 = its own bookkeeping outside the hooked callees):";
				t.align = "rlrrrrrr";
				t.cols = { "site_rva", "site -> callee", "calls", "incl_ms", "excl_ms", "kernel_ms", "user_ms", "pct_of_13753" };
				for (const auto& r : rows) {
					t.rows.push_back({ std::format("0x{:X}", r.rva), r.name, S(r.n), F1(a_c.Ms(r.ticks)), F1(a_c.Ms(r.ex)), r.kern, r.user, F1(a_c.Pct(a_c.Ms(r.ticks), lfMs)) });
				}
				const double resid = a_c.Ms(a_m.loadFilesEx);
				t.rows.push_back({ "-", "RESIDUAL unattributed (13753 inline code: loops, flag stores)", "-", F1(resid), F1(resid), "-", "-", F1(a_c.Pct(resid, lfMs)) });
				t.rows.push_back({ "-", "13753 inclusive total", "1", F1(lfMs), F1(resid), "-", "-", "100.0" });
				a_o.Tab(t);
				a_o.Line("  NOTE: callee rows show wall time only (kernel/user n/a): they repeat per plugin file / per form, and a GetThreadTimes pair around each is costly and noisy under Wine; "
						 "kernel/user is sampled only at segment and phase boundaries.");
				if (!g_grp[kLfCallees].installed) {
					a_o.Line("  NOTE: the lfCallees group is not installed, so the residual above includes every callee it would have named.");
				}
			}
		}

		void IiSections(Out& a_o, const Merged& a_m, const Clk& a_c, bool a_startup)
		{
			const double iiMs = a_c.Ms(a_m.initItemsTicks);
			if (a_startup) {
				Table t;
				t.name = "ii_phases";
				t.title = "13784 InitItem pass phases P0..P10 (last-hit-wins markers; an empty array skips its marker and its time lands in the previous phase):";
				t.align = "lrrrrrl";
				t.cols = { "phase", "wall_ms", "kernel_ms", "user_ms", "pct_of_13784", "entries", "threads" };
				std::uint64_t sum = 0;
				for (std::size_t i = 0; i < sites::kIiPhaseCount; ++i) {
					const auto& p = a_m.ii[i];
					sum += p.wall;
					t.rows.push_back({ kIiNames[i], F1(a_c.Ms(p.wall)), Ut(p.kern), Ut(p.user),
						F1(a_c.Pct(a_c.Ms(p.wall), iiMs)), S(p.entries), TidList(g_iiTids[i]) });
				}
				a_o.Tab(t);
				a_o.Line(std::format("  phases sum {:.1f} ms of 13784 {:.1f} ms; P5 includes the un-hooked 3-byte NPC_ actorData vfunc at 0x1BE2A2", a_c.Ms(sum), iiMs));
			}
			struct Row
			{
				std::uintptr_t rva;
				std::string    kind, name;
				std::uint64_t  n, ticks, ex;
				std::string    kern, user;
			};
			std::vector<Row> rows;
			for (std::size_t i = 0; i < kTimedCount; ++i) {
				const auto& s = sites::kTimedSites[i];
				if (s.owner != sites::Owner::kInitPass || (!a_startup && a_m.callee[i].n == 0)) {
					continue;
				}
				rows.push_back({ s.site.siteRva, "E8", std::format("{} -> {}", s.site.name, s.callee.name), a_m.callee[i].n, a_m.callee[i].ticks, a_m.callee[i].ex,
					"n/a", "n/a" });
			}
			for (std::size_t i = 0; i < kVfCount; ++i) {
				const auto& s = sites::kVfSites[i];
				if (!a_startup && a_m.vf[i].n == 0) {
					continue;
				}
				rows.push_back({ s.site.siteRva, "vf", std::format("{} [{}]", s.site.name, kVfNames[i]), a_m.vf[i].n, a_m.vf[i].ticks, a_m.vf[i].ex, "-", "-" });
			}
			std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) { return a.rva < b.rva; });
			Table t;
			t.name = "ii_sites";
			t.csvBlankNa = true;
			t.title = a_startup ? "13784 callees (22 E8 + 6 virtual) and the WRLD/cell/ref virtual sites in code order (virtual rows are INCLUSIVE of recursive un-hooked inits):" :
			                      "InitItem sites that fired in this episode (virtual rows are inclusive of recursive un-hooked inits):";
			t.align = "rllrrrrr";
			t.cols = { "site_rva", "kind", "site", "calls", "incl_ms", "excl_ms", "kernel_ms", "user_ms" };
			for (const auto& r : rows) {
				t.rows.push_back({ std::format("0x{:X}", r.rva), r.kind, r.name, S(r.n), F1(a_c.Ms(r.ticks)), F1(a_c.Ms(r.ex)), r.kern, r.user });
			}
			if (a_startup) {
				t.rows.push_back({ "-", "-", "RESIDUAL unattributed (13784 inline code + the un-hooked 0x1BE2A2 vfunc)", "-", F1(iiMs), F1(a_c.Ms(a_m.initItemsEx)), "-", "-" });
			}
			a_o.Tab(t);
			a_o.Line("  NOTE: callee rows show wall time only (kernel/user n/a); kernel/user is sampled only at phase boundaries (see ii_phases).");
		}

		void TypesSection(Out& a_o, const Merged& a_m, const Clk& a_c)
		{
			std::vector<std::size_t> order;
			std::uint64_t            total = 0;
			for (std::size_t i = 0; i < kTypeSlots; ++i) {
				if (a_m.type[i].count != 0) {
					order.push_back(i);
					total += a_m.type[i].ticks;
				}
			}
			std::sort(order.begin(), order.end(), [&](std::size_t a, std::size_t b) { return a_m.type[a].ticks > a_m.type[b].ticks; });
			Table t;
			t.name = "types";
			t.title = "Per-form-type InitItem time (core loop at 0x1BE221; type = the form's formType byte [I]; inclusive of recursive un-hooked inits; hist = count per log2(ticks) bucket):";
			t.align = "rllrrrrrl";
			t.cols = { "type_idx", "type", "forms", "total_ms", "pct_of_types", "mean_us", "max_ms", "max_formid", "hist(log2 ticks:count)" };
			for (std::size_t c = 0; c < kHistBuckets; ++c) {
				t.csvExtraCols.push_back(std::format("h_log2t_{}", kHistMinLog2 + c));
			}
			t.textRows = 60;
			for (const auto i : order) {
				const auto&  ty = a_m.type[i];
				const double ms = a_c.Ms(ty.ticks);
				std::string  hist;
				std::vector<std::string> extra;
				for (std::size_t h = 0; h < kHistBuckets; ++h) {
					if (ty.hist[h] != 0) {
						hist += std::format("{}{}:{}", hist.empty() ? "" : " ", kHistMinLog2 + h, ty.hist[h]);
					}
					extra.push_back(S(ty.hist[h]));
				}
				t.rows.push_back({ S(i), TypeName(i), S(ty.count), F1(ms), F1(a_c.Pct(ms, a_c.Ms(total))),
					F2(ty.count ? ms * 1000.0 / static_cast<double>(ty.count) : 0.0), F3(a_c.Ms(ty.maxTicks)), Hex32(ty.maxForm), hist });
				t.csvExtra.push_back(std::move(extra));
			}
			a_o.Tab(t);
			a_o.Line(std::format("  per-form total {:.1f} ms; histogram bucket k = forms whose InitItem took [2^k, 2^(k+1)) TSC ticks (k=6 also holds everything smaller; TSC = {:.0f} ticks/ms)",
				a_c.Ms(total), a_c.tpm));
		}

		void SigSections(Out& a_o, const Merged& a_m, const Clk& a_c)
		{
			std::vector<const SigSum*> order;
			std::uint64_t              recs = 0, comp = 0;
			for (const auto& [k, v] : a_m.sig) {
				order.push_back(&v);
				recs += v.count;
				comp += v.compressed;
			}
			std::sort(order.begin(), order.end(), [](const SigSum* a, const SigSum* b) { return a->ticks > b->ticks; });
			std::map<std::string, std::uint64_t> newByName;
			std::uint64_t                        newTotal = 0;
			for (std::size_t i = 0; i < kTypeSlots; ++i) {
				if (a_m.newForms[i] != 0) {
					newByName[TypeName(i)] += a_m.newForms[i];
					newTotal += a_m.newForms[i];
				}
			}
			{
				Table t;
				t.name = "load_by_sig";
				t.title = "Load bodies (13690) per record signature: records, inclusive/exclusive time, record data bytes, compressed records, forms created (13693):";
				t.align = "lrrrrrrrr";
				t.cols = { "sig", "records", "incl_ms", "excl_ms", "mean_us", "data_bytes", "compressed", "new_forms", "pct_of_load" };
				t.textRows = 60;
				std::uint64_t all = 0;
				for (const auto* p : order) {
					all += p->ticks;
				}
				for (const auto* p : order) {
					const std::string nm = SigName(p->key);
					const auto        nf = newByName.find(nm);
					const double      ms = a_c.Ms(p->ticks);
					t.rows.push_back({ nm, S(p->count), F1(ms), F1(a_c.Ms(p->ex)), F2(p->count ? ms * 1000.0 / static_cast<double>(p->count) : 0.0),
						S(p->bytes), S(p->compressed), nf != newByName.end() ? S(nf->second) : std::string("0"), F1(a_c.Pct(ms, a_c.Ms(all))) });
				}
				a_o.Tab(t);
				a_o.Line("  NOTE: kernel/user time is recorded per phase and segment only, NOT per callee or signature (a GetThreadTimes pair around repeated calls would distort them). "
						 "Load bodies run inside the 'plugin loop' segment: read its kernel_ms vs user_ms.");
				if (a_m.sigOverflow != 0) {
					a_o.Line(std::format("  WARNING: {} Load call(s) hit a full signature table and are not in the table.", a_m.sigOverflow));
				}
			}
			{
				Table t;
				t.name = "heaviest_records";
				t.title = std::format("Top {} heaviest single records by Load time (inclusive of the reads and inflate inside it):", kTopHeavy);
				t.align = "rlrlr";
				t.cols = { "rank", "plugin", "formid", "sig", "incl_ms" };
				for (std::size_t i = 0; i < a_m.heavy.size(); ++i) {
					const auto& h = a_m.heavy[i];
					t.rows.push_back({ S(i + 1), SafeName(h.file), Hex32(h.formID), SigName(h.sig), F3(a_c.Ms(h.ticks)) });
				}
				a_o.Tab(t);
			}
			{
				Table t;
				t.name = "new_forms";
				t.title = "Forms created per type (13763 -> 13693 AddFormToDataHandler, new forms only; ms = the insert call itself):";
				t.align = "lrr";
				t.cols = { "type", "new_forms", "insert_ms" };
				std::vector<std::size_t> o2;
				for (std::size_t i = 0; i < kTypeSlots; ++i) {
					if (a_m.newForms[i] != 0) {
						o2.push_back(i);
					}
				}
				std::sort(o2.begin(), o2.end(), [&](std::size_t a, std::size_t b) { return a_m.newForms[a] > a_m.newForms[b]; });
				t.textRows = 40;
				for (const auto i : o2) {
					t.rows.push_back({ TypeName(i), S(a_m.newForms[i]), F2(a_c.Ms(a_m.newFormTicks[i])) });
				}
				a_o.Tab(t);
			}
			{
				Table t;
				t.name = "composition";
				t.title = "Record composition:";
				t.align = "lr";
				t.cols = { "metric", "value" };
				t.rows.push_back({ "records_loaded_13690_calls", S(recs) });
				t.rows.push_back({ "distinct_signatures", S(order.size()) });
				t.rows.push_back({ "compressed_records", S(comp) });
				t.rows.push_back({ "new_forms_13693", S(newTotal) });
				t.rows.push_back({ "loads_without_a_new_form", S(recs >= newTotal ? recs - newTotal : 0) });
				a_o.Tab(t);
			}
		}

		void PluginKindsSection(Out& a_o)
		{
			auto* dh = RE::TESDataHandler::GetSingleton();
			if (!dh) {
				return;
			}
			const auto& fc = REL::RelocateMember<const RE::TESFileCollection>(dh, 0xD70, 0);
			std::uint64_t full = fc.files.size(), light = fc.smallFiles.size(), esm = 0, lightEsm = 0;
			for (std::uint32_t i = 0; i < fc.files.size(); ++i) {
				const RE::TESFile* f = fc.files[i];
				if (f && f->recordFlags.all(RE::TESFile::RecordFlag::kMaster)) {
					++esm;
				}
			}
			for (std::uint32_t i = 0; i < fc.smallFiles.size(); ++i) {
				const RE::TESFile* f = fc.smallFiles[i];
				if (f && f->recordFlags.all(RE::TESFile::RecordFlag::kMaster)) {
					++lightEsm;
				}
			}
			Table t;
			t.name = "plugin_kinds";
			t.title = "Plugin kinds (compiled file collection):";
			t.align = "lr";
			t.cols = { "metric", "value" };
			t.rows.push_back({ "full_slot_plugins", S(full) });
			t.rows.push_back({ "of_which_master_flag", S(esm) });
			t.rows.push_back({ "light_plugins", S(light) });
			t.rows.push_back({ "of_which_master_flag_light", S(lightEsm) });
			t.rows.push_back({ "total", S(full + light) });
			a_o.Tab(t);
		}

		void LoopSplitSection(Out& a_o, const Merged& a_m, const Clk& a_c)
		{
			Table t;
			t.name = "loop_split";
			t.title = "13760 internals (exclusive ms summed over plugins):";
			t.align = "lrr";
			t.cols = { "column", "calls", "excl_ms" };
			for (std::size_t c = static_cast<std::size_t>(sites::Col::kOpen2); c <= static_cast<std::size_t>(sites::Col::kClose); ++c) {
				if (a_m.tot.colN[c] != 0) {
					t.rows.push_back({ kColNames[c], S(a_m.tot.colN[c]), F1(a_c.Ms(a_m.tot.colT[c])) });
				}
			}
			if (t.rows.empty() && !g_grp[kLoopSplit].installed) {
				return;
			}
			a_o.Tab(t);
		}

		void FilesSection(Out& a_o, const Clk& a_c)
		{
			if (!g_files) {
				return;
			}
			struct Row
			{
				const RE::TESFile* f;
				std::array<std::uint64_t, 4> t;
				std::uint64_t gate;
				std::uint64_t sum;
			};
			std::vector<Row> rows;
			for (std::size_t i = 0; i < kFileRows; ++i) {
				const void* k = g_files[i].file.load(std::memory_order_relaxed);
				if (!k) {
					continue;
				}
				Row r{ static_cast<const RE::TESFile*>(k), {}, g_files[i].gateTrue.get(), 0 };
				for (std::size_t c = 0; c < 4; ++c) {
					r.t[c] = g_files[i].t[c].get();
					r.sum += r.t[c];
				}
				rows.push_back(r);
			}
			if (rows.empty()) {
				return;
			}
			std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) { return a.sum > b.sum; });
			Table t;
			t.name = "files";
			t.title = std::format("Per-file work in 13753's file loop and pass 1 ({} files; top {} by total):", rows.size(), std::max(0, g_cfg.topN));
			t.align = "lrrrrr";
			t.cols = { "plugin", "compile_idx_ms", "bsa_gate_ms", "bsa_gate_true", "bsa_autoload_ms", "pass1_open_ms" };
			t.textRows = static_cast<std::size_t>(std::max(0, g_cfg.topN));
			for (const auto& r : rows) {
				t.rows.push_back({ SafeName(r.f), F3(a_c.Ms(r.t[0])), F3(a_c.Ms(r.t[1])), S(r.gate), F3(a_c.Ms(r.t[2])), F3(a_c.Ms(r.t[3])) });
			}
			a_o.Tab(t);
			if (g_fileRowDrops.get() != 0) {
				a_o.Line(std::format("  WARNING: {} file row(s) dropped (table full).", g_fileRowDrops.get()));
			}
		}

		void PluginsSection(Out& a_o, const Merged& a_m, const Clk& a_c)
		{
			const std::uint32_t n = a_m.startupSlotCount;
			if (n == 0 || !g_slots) {
				return;
			}
			const auto row = [&](std::uint32_t a_i) {
				const Slot& s = g_slots[a_i];
				std::vector<std::string> r{ S(a_i), a_i == 0 ? std::string("(inside LoadFiles, outside any plugin)") : SafeName(s.file.load()),
					F1(a_c.Ms(s.wall.get())), S(s.records.get()), S(s.compressed.get()), F1(a_c.Ms(s.loadEx.get())), F1(a_c.Ms(s.readEx.get())),
					S(s.inflN.get()), S(s.inflIn.get()), S(s.inflOut.get()), F1(a_c.Ms(s.inflEx.get())) };
				for (std::size_t c = static_cast<std::size_t>(sites::Col::kOpen2); c <= static_cast<std::size_t>(sites::Col::kClose); ++c) {
					r.push_back(F2(a_c.Ms(s.colT[c].get())));
				}
				return r;
			};
			std::vector<std::string> cols{ "slot", "plugin", "wall_ms", "records", "compressed", "load_ms", "read_ms", "infl_n", "infl_in_B", "infl_out_B", "infl_ms" };
			for (std::size_t c = static_cast<std::size_t>(sites::Col::kOpen2); c <= static_cast<std::size_t>(sites::Col::kClose); ++c) {
				cols.push_back(std::string(kColNames[c]) + "_ms");
			}
			std::vector<std::uint32_t> order;
			for (std::uint32_t i = 1; i < n; ++i) {
				order.push_back(i);
			}
			std::sort(order.begin(), order.end(), [](std::uint32_t a, std::uint32_t b) { return g_slots[a].wall.get() > g_slots[b].wall.get(); });
			const std::size_t top = std::min<std::size_t>(order.size(), static_cast<std::size_t>(std::max(0, g_cfg.topN)));
			{
				Table t;
				t.name = "plugins_top";
				t.title = std::format("Top {} plugins by wall time:", top);
				t.align = "rlrrrrrrrrrrrrrrrrr";
				t.cols = cols;
				for (std::size_t k = 0; k < top; ++k) {
					t.rows.push_back(row(order[k]));
				}
				a_o.Tab(t);
			}
			{
				Table t;
				t.name = "plugins";
				t.title = "Per-plugin table (load order; slot 0 = work inside LoadFiles but outside any plugin):";
				t.align = "rlrrrrrrrrrrrrrrrrr";
				t.cols = cols;
				t.textRows = g_cfg.fullTable ? static_cast<std::size_t>(-1) : 0;
				for (std::uint32_t i = 0; i < n; ++i) {
					t.rows.push_back(row(i));
				}
				// the top-N table above already went to the CSV as plugins_top; here only the full list
				if (!g_cfg.fullTable) {
					a_o.Line("Per-plugin table: text suppressed ([Report] bFullTable=0); the CSV section 'plugins' has every plugin.");
				}
				a_o.Tab(t);
			}
			if (a_m.slotOverflow != 0) {
				a_o.Line(std::format("  WARNING: slot overflow: {} plugin(s) past the slot table.", a_m.slotOverflow));
			}
		}

		void OracleSection(Out& a_o)
		{
			if (!g_cfg.formDigest) {
				a_o.Line("Identity oracle: off ([Oracle] bFormDigest=0).");
				return;
			}
			const auto r = oracle::Run();
			if (!r.ran) {
				a_o.Line(std::format("Identity oracle: NOT RUN: {}", r.why));
				return;
			}
			a_o.Line(std::format("Identity oracle (read-only, allForms read lock, {:.1f} ms): forms={} null entries={} formArray elements={}",
				r.ms, r.forms, r.nullEntries, r.arraysTotal));
			a_o.Line("  unordered digest = sum mod 2^64 of FNV-1a-64(formID u32 LE, formType u8, formFlags u32 LE) over every form in allForms");
			a_o.Line("  ordered digest   = FNV-1a-64 over (type u8, length u64 LE, per-array FormID-sequence digest u64 LE) for formArrays[0..0x89]");
			a_o.Line(oracle::MachineLine(r));
			{
				Table t;
				t.name = "oracle";
				t.title = "Identity oracle summary:";
				t.align = "lr";
				t.cols = { "key", "value" };
				t.rows.push_back({ "forms", S(r.forms) });
				t.rows.push_back({ "null_entries", S(r.nullEntries) });
				t.rows.push_back({ "unordered_digest", Hex64(r.unordered) });
				t.rows.push_back({ "ordered_digest", Hex64(r.ordered) });
				t.rows.push_back({ "formarray_elements", S(r.arraysTotal) });
				t.rows.push_back({ "oracle_ms", F1(r.ms) });
				a_o.Tab(t);
			}
			{
				Table t;
				t.name = "oracle_types";
				t.title = "Identity oracle per type (map count, formArray length, formArray FormID-sequence digest):";
				t.align = "rlrrl";
				t.cols = { "type_idx", "type", "map_count", "array_len", "array_digest" };
				t.textRows = 60;
				for (std::size_t i = 0; i < oracle::kTypes; ++i) {
					if (r.mapByType[i] != 0 || r.arrayLen[i] != 0) {
						t.rows.push_back({ S(i), TypeName(i), S(r.mapByType[i]), S(r.arrayLen[i]), Hex64(r.arrayDigest[i]) });
					}
				}
				a_o.Tab(t);
			}
		}

		void SystemSection(Out& a_o, const Episode& a_e)
		{
			const auto si = ReadSysInfo();
			const auto* plugin = SKSE::PluginDeclaration::GetSingleton();
			const auto  ver = plugin->GetVersion();
			Table t;
			t.name = "system";
			t.title = "System:";
			t.align = "ll";
			t.cols = { "key", "value" };
			t.rows.push_back({ "probe_version", std::format("{}.{}.{}", ver.major(), ver.minor(), ver.patch()) });
			t.rows.push_back({ "game_version", REL::Module::get().version().string() });
			t.rows.push_back({ "logical_cores", S(si.cores) });
			t.rows.push_back({ "load_thread_id", S(g_loadTid.load()) });
			t.rows.push_back({ "kDataLoaded_thread_id", S(g_dataLoadedTid.load()) });
			t.rows.push_back({ "wine", si.wine.empty() ? std::string("no (ntdll has no wine_get_version)") : "yes, wine " + si.wine });
			t.rows.push_back({ "proton_env_hint", si.protonHint ? "STEAM_COMPAT_DATA_PATH is set" : "not set" });
			t.rows.push_back({ "gate_chained_to_a_foreign_patch", g_gateChained ? "YES (LoadFiles ms includes the interposer)" : "no" });
			t.rows.push_back({ "foreign_threads_seen_by_gate", TidList(g_foreignTids) });
			t.rows.push_back({ "startup_episode", a_e.name });
			a_o.Tab(t);
		}

		void FinishText(Out& a_o)
		{
			a_o.Line("=====================================================================");
			spdlog::default_logger()->flush();
		}
	}

	// =========================================================================
	void WriteStartupReport(const char* a_trigger)
	{
		Out o;
		o.episode = "startup";
		o.wantCsv = g_cfg.csv;

		o.Line("==================== LoadingThreader LT-2b report ====================");
		o.Line(std::format("trigger: {}", a_trigger));
		if (!g_gateInstalled || !g_eps) {
			o.Line(std::format("PROBE INACTIVE: {}", g_inactiveWhy));
			Clk none;
			GroupsTable(o, nullptr, true, none);
			FinishText(o);
			FlushCsv(o);
			return;
		}
		const Episode& e = g_eps[0];
		if (!e.closed.load()) {
			o.Line("UNPROVEN: the startup LoadFiles call never went through the gate (or has not returned); no data was collected.");
			Clk none;
			GroupsTable(o, nullptr, true, none);
			FinishText(o);
			FlushCsv(o);
			return;
		}

		const auto m = Merge(e);
		const Clk  clk = MakeClk(e);

		SystemSection(o, e);
		EpisodeTable(o, e, *m, clk);
		o.Line(std::format("LoadFiles (13753) total: {:.1f} ms (steady_clock), {:.1f} ms (TSC); TSC = {:.0f} ticks/ms; plugins measured: {} (slot overflow: {})",
			clk.winMs, clk.Ms(m->loadFilesTicks), clk.tpm, m->startupSlotCount > 0 ? m->startupSlotCount - 1 : 0, m->slotOverflow));
		GroupsTable(o, m.get(), true, clk);

		std::uint64_t calls = 0;
		for (std::size_t g = 0; g < kGroupCount; ++g) {
			calls += m->measured[g];
		}
		const double costTicks = MeasureProbeCostTicks();
		o.Line(std::format("probe cost estimate: {} measured calls x {:.0f} ticks = {:.1f} ms of the total (excludes stub jumps; per group in the table above)",
			calls, costTicks, clk.Ms(static_cast<std::uint64_t>(costTicks * static_cast<double>(calls)))));

		SplitSection(o, e, *m, clk);
		InflateSection(o, *m);
		IoSection(o, e, *m, clk);
		LfSections(o, *m, clk);
		IiSections(o, *m, clk, true);
		TypesSection(o, *m, clk);
		SigSections(o, *m, clk);
		PluginKindsSection(o);
		LoopSplitSection(o, *m, clk);
		FilesSection(o, clk);
		PluginsSection(o, *m, clk);
		OracleSection(o);
		FinishText(o);
		FlushCsv(o);
	}

	void WriteRuntimeReport(const Episode& a_e)
	{
		Out o;
		o.episode = a_e.name;
		o.wantCsv = g_cfg.csv;

		const auto m = Merge(a_e);
		const Clk  clk = MakeClk(a_e);
		o.Line(std::format("==================== LoadingThreader LT-2b episode '{}' ====================", a_e.name));
		o.Line(std::format("Loading Menu open..close: {:.1f} ms wall, {:.1f} ms process CPU; {} thread block(s); hooked-work tables below",
			clk.winMs, clk.cpuMs, m->blocks));
		if (g_epDropped.get() != 0 || g_epSkipped.get() != 0) {
			o.Line(std::format("  loading screens not recorded so far: {} past the {}-episode cap, {} opened while another episode was open",
				g_epDropped.get(), kMaxRuntimeEpisodes, g_epSkipped.get()));
		}
		EpisodeTable(o, a_e, *m, clk);
		GroupsTable(o, m.get(), false, clk);
		SplitSection(o, a_e, *m, clk);
		InflateSection(o, *m);
		IoSection(o, a_e, *m, clk);
		// 13753 / 13784 callee rows only if they fired in this episode
		{
			bool lf = false;
			for (std::size_t i = 0; i < kTimedCount && !lf; ++i) {
				lf = sites::kTimedSites[i].owner == sites::Owner::kLoadFiles && m->callee[i].n != 0;
			}
			if (lf) {
				Table t;
				t.name = "lf_callees";
				t.title = "13753 callees that fired in this episode:";
				t.align = "rlrrr";
				t.cols = { "site_rva", "site -> callee", "calls", "incl_ms", "excl_ms" };
				for (std::size_t i = 0; i < kTimedCount; ++i) {
					const auto& s = sites::kTimedSites[i];
					if (s.owner == sites::Owner::kLoadFiles && m->callee[i].n != 0) {
						t.rows.push_back({ std::format("0x{:X}", s.site.siteRva), std::format("{} -> {}", s.site.name, s.callee.name), S(m->callee[i].n),
							F1(clk.Ms(m->callee[i].ticks)), F1(clk.Ms(m->callee[i].ex)) });
					}
				}
				o.Tab(t);
			}
		}
		IiSections(o, *m, clk, false);
		TypesSection(o, *m, clk);
		SigSections(o, *m, clk);
		LoopSplitSection(o, *m, clk);
		FinishText(o);
		FlushCsv(o);
	}
}
