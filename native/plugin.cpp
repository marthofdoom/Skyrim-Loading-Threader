#include "PCH.h"

#include "Probe.h"

// LoadingThreader -- LT-2 stage-1: a PASSIVE timing probe of the startup data
// load. It changes no behaviour: every hook chains the original with the same
// arguments and returns its result. No co-save record, no persisted state, no
// hotkeys, no Papyrus. See Docs/LT-2-probe-howto.md and native/Probe.cpp.

// Win32 INI read, declared by hand: the CommonLib PCH does not pull in
// <Windows.h> (same declaration as APMF core/EquipSink.cpp).
extern "C" __declspec(dllimport) unsigned long __stdcall GetPrivateProfileIntA(
	const char* a_appName, const char* a_keyName, long a_default, const char* a_fileName);

namespace
{
	// Relative to the game root; MO2's VFS maps Data/. A path with a separator
	// is resolved against the current directory, not the Windows directory.
	constexpr const char* kIni = "Data/SKSE/Plugins/LoadingThreader.ini";

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

	bool IniBool(const char* a_section, const char* a_key, bool a_default)
	{
		return GetPrivateProfileIntA(a_section, a_key, a_default ? 1 : 0, kIni) != 0;
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
		c.allowPatchedGate = IniBool("Advanced", "bAllowPatchedGate", c.allowPatchedGate);
		c.topN = static_cast<int>(GetPrivateProfileIntA("Report", "iTopN", c.topN, kIni));
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
	spdlog::info("=== LoadingThreader {}.{}.{} (LT-2 passive timing probe) -- game {} ===",
		ver.major(), ver.minor(), ver.patch(), REL::Module::get().version().string());

	std::error_code ec;
	const bool      iniFound = std::filesystem::exists(kIni, ec);
	const auto      cfg = ReadConfig();
	spdlog::info("[config] {} {}: bEnabled={} bVerboseLog={} bPerPlugin={} bRecord={} bLoadBody={} bRawRead={} "
				 "bInflate={} bPostLoop={} bAllowPatchedGate={} iTopN={} bFullTable={}",
		kIni, iniFound ? "found" : "NOT FOUND (defaults)", cfg.enabled, cfg.verbose, cfg.perPlugin, cfg.record,
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
