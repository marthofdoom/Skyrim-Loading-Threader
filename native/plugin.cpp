#include "PCH.h"

#include "Probe.h"

// LoadingThreader -- LT-2 stage-1: a PASSIVE timing probe of the startup data
// load. It changes no behaviour: every hook chains the original with the same
// arguments and returns its result. No co-save record, no persisted state, no
// hotkeys, no Papyrus. See Docs/LT-2-probe-howto.md and native/Probe.cpp.

namespace
{
	// Relative to the game root; MO2's VFS maps Data/. A path with a separator
	// is resolved against the current directory, not the Windows directory.
	constexpr const char* kIni = "Data/SKSE/Plugins/LoadingThreader.ini";

	// The INI actually read: next to this DLL if there is one (the DLL's own directory, so a
	// mod-manager virtual layout cannot hide it), else the game-root-relative kIni.
	std::filesystem::path g_iniPath = kIni;
	bool                  g_iniBesideDll = false;

	std::filesystem::path ResolveIni()
	{
		const auto k32 = REX::W32::GetModuleHandleW(L"kernel32.dll");
		if (k32) {
			using GetModuleHandleExW_t = int (*)(unsigned long, const void*, REX::W32::HMODULE*);
			const auto fn = reinterpret_cast<GetModuleHandleExW_t>(REX::W32::GetProcAddress(k32, "GetModuleHandleExW"));
			REX::W32::HMODULE self = nullptr;
			constexpr unsigned long kFromAddressUnchangedRefcount = 0x00000004 | 0x00000002;  // GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | _UNCHANGED_REFCOUNT
			if (fn && fn(kFromAddressUnchangedRefcount, reinterpret_cast<const void*>(&ResolveIni), &self) != 0 && self) {
				std::array<wchar_t, 1024> buf{};
				const auto                n = REX::W32::GetModuleFileNameW(self, buf.data(), static_cast<std::uint32_t>(buf.size()));
				if (n > 0 && n < buf.size()) {
					std::filesystem::path p{ std::wstring(buf.data(), n) };
					p.replace_filename(L"LoadingThreader.ini");
					std::error_code ec;
					if (std::filesystem::exists(p, ec)) {
						g_iniBesideDll = true;
						return p;
					}
				}
			}
		}
		return std::filesystem::path(kIni);
	}

	// The SKSE log directory (Documents/My Games/Skyrim Special Edition/SKSE/)
	// first, as LT-2 asks; the game-root-relative Data/SKSE/Plugins (which MO2
	// redirects into overwrite/) only if that directory is unavailable.
	void SetupLog()
	{
		std::shared_ptr<spdlog::sinks::basic_file_sink_mt> sink;
		if (auto dir = SKSE::log::log_directory()) {
			try {
				sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>((*dir / "LoadingThreader.log").string(), true);
			} catch (const spdlog::spdlog_ex&) {
				sink.reset();
			}
		}
		if (!sink) {
			try {
				sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>("Data/SKSE/Plugins/LoadingThreader.log", true);
			} catch (const spdlog::spdlog_ex&) {
				return;  // no log is survivable; a crash here is not
			}
		}
		auto log = std::make_shared<spdlog::logger>("global", std::move(sink));
		log->set_level(spdlog::level::info);
		log->flush_on(spdlog::level::warn);
		spdlog::set_default_logger(std::move(log));
		spdlog::set_pattern("[%H:%M:%S.%e] [%l] %v");
		spdlog::flush_every(std::chrono::seconds(1));
	}

	// ASCII rendering of a path for the log. NOT path::string(): MSVC's narrow conversion
	// throws std::system_error for a character the ANSI code page cannot map, and an
	// exception escaping SKSEPluginLoad takes the game down.
	std::string AsciiPath(const std::filesystem::path& a_p)
	{
		std::string s;
		for (const wchar_t c : a_p.native()) {
			s += (c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '?';
		}
		return s;
	}

	// Wide read (the path may be non-ASCII); section/key names are ASCII literals.
	long IniInt(const char* a_section, const char* a_key, long a_default)
	{
		const std::wstring sec(a_section, a_section + std::strlen(a_section));
		const std::wstring key(a_key, a_key + std::strlen(a_key));
		wchar_t            out[32] = {};
		const auto         n = REX::W32::GetPrivateProfileStringW(sec.c_str(), key.c_str(), L"", out, 32, g_iniPath.c_str());
		if (n == 0) {
			return a_default;
		}
		wchar_t*   end = nullptr;
		const long v = std::wcstol(out, &end, 10);
		return end == out ? a_default : v;
	}

	bool IniBool(const char* a_section, const char* a_key, bool a_default)
	{
		return IniInt(a_section, a_key, a_default ? 1 : 0) != 0;
	}

	lt::probe::Config ReadConfig()
	{
		lt::probe::Config c;
		c.enabled = IniBool("General", "bEnabled", c.enabled);
		c.verbose = IniBool("General", "bVerboseLog", c.verbose);
		c.perPlugin = IniBool("Hooks", "bPerPlugin", c.perPlugin);
		c.record = IniBool("Hooks", "bRecord", c.record);
		c.loadBody = IniBool("Hooks", "bLoadBody", c.loadBody);
		c.rawRead = IniBool("Hooks", "bRawRead", c.rawRead);
		c.inflate = IniBool("Hooks", "bInflate", c.inflate);
		c.postLoop = IniBool("Hooks", "bPostLoop", c.postLoop);
		c.lfCallees = IniBool("Hooks", "bLfCallees", c.lfCallees);
		c.initPass = IniBool("Hooks", "bInitPass", c.initPass);
		c.perForm = IniBool("Hooks", "bPerForm", c.perForm);
		c.initRefs = IniBool("Hooks", "bInitRefs", c.initRefs);
		c.loopSplit = IniBool("Hooks", "bLoopSplit", c.loopSplit);
		c.newForms = IniBool("Hooks", "bNewForms", c.newForms);
		c.runtimeEpisodes = IniBool("Episodes", "bRuntimeLoadScreens", c.runtimeEpisodes);
		c.formDigest = IniBool("Oracle", "bFormDigest", c.formDigest);
		c.csv = IniBool("Report", "bCsv", c.csv);
		{
			wchar_t out[256] = {};
			if (REX::W32::GetPrivateProfileStringW(L"Episodes", L"sLabels", L"", out, 256, g_iniPath.c_str()) > 0) {
				std::string v;
				for (const wchar_t* p = out; *p; ++p) {
					v += (*p > 0x20 && *p < 0x7F) ? static_cast<char>(*p) : '_';
				}
				c.episodeLabels = v;
			}
		}
		c.allowPatchedGate = IniBool("Advanced", "bAllowPatchedGate", c.allowPatchedGate);
		c.topN = static_cast<int>(IniInt("Report", "iTopN", c.topN));
		c.fullTable = IniBool("Report", "bFullTable", c.fullTable);
		return c;
	}

	void OnMessage(SKSE::MessagingInterface::Message* a_msg)
	{
		if (a_msg && a_msg->type == SKSE::MessagingInterface::kDataLoaded) {
			lt::probe::OnDataLoaded();
		}
	}
}

SKSEPluginLoad(const SKSE::LoadInterface* a_skse)
{
	SKSE::Init(a_skse);
	SetupLog();

	const auto* plugin = SKSE::PluginDeclaration::GetSingleton();
	const auto  ver = plugin->GetVersion();
	// A stale binary voids every test: this banner is the first line, and the
	// DLL's sha256 (not this string) is the proof of which build ran.
	spdlog::info("=== LoadingThreader {}.{}.{} (LT-2b passive timing probe) -- game {} ===",
		ver.major(), ver.minor(), ver.patch(), REL::Module::get().version().string());

	g_iniPath = ResolveIni();
	std::error_code ec;
	const bool      iniFound = std::filesystem::exists(g_iniPath, ec);
	const auto      cfg = ReadConfig();
	spdlog::info("[config] {} {}: bEnabled={} bVerboseLog={} bPerPlugin={} bRecord={} bLoadBody={} bRawRead={} "
				 "bInflate={} bPostLoop={} bAllowPatchedGate={} iTopN={} bFullTable={}",
		AsciiPath(g_iniPath), iniFound ? (g_iniBesideDll ? "found beside the DLL" : "found (relative fallback)") : "NOT FOUND (defaults)", cfg.enabled, cfg.verbose, cfg.perPlugin, cfg.record,
		cfg.loadBody, cfg.rawRead, cfg.inflate, cfg.postLoop, cfg.allowPatchedGate, cfg.topN, cfg.fullTable);
	spdlog::info("[config] v2: bLfCallees={} bInitPass={} bPerForm={} bInitRefs={} bLoopSplit={} bNewForms={} "
				 "bRuntimeLoadScreens={} bFormDigest={} bCsv={}",
		cfg.lfCallees, cfg.initPass, cfg.perForm, cfg.initRefs, cfg.loopSplit, cfg.newForms, cfg.runtimeEpisodes,
		cfg.formDigest, cfg.csv);

	// Install now: SKSE loads plugins before the engine starts the InitTES
	// thread, so no hooked function can be running while we patch.
	lt::probe::Install(cfg);

	SKSE::GetMessagingInterface()->RegisterListener(OnMessage);

	// NO SetUniqueID / save / load / revert callbacks ON PURPOSE: the probe
	// writes nothing into the co-save and holds no persisted state.
	spdlog::default_logger()->flush();
	return true;
}
