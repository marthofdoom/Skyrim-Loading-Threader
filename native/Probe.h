#pragma once

// LT-2 / LT-2b timing probe: PASSIVE. See Probe.cpp for the hook list and the
// rules that keep it passive.

#include <string>

namespace lt::probe
{
	struct Config
	{
		bool enabled = true;            // [General] bEnabled -- the kill-switch: 0 => no hook at all
		bool verbose = false;           // [General] bVerboseLog

		// v1 groups
		bool perPlugin = true;          // [Hooks] bPerPlugin   (13760)
		bool record = true;             // [Hooks] bRecord      (13763)
		bool loadBody = true;           // [Hooks] bLoadBody    (13690)
		bool rawRead = true;            // [Hooks] bRawRead     (13991, entry detour)
		bool inflate = true;            // [Hooks] bInflate     (14032)
		bool postLoop = true;           // [Hooks] bPostLoop    (13784)

		// v2 groups (LT-2b)
		bool lfCallees = true;          // [Hooks] bLfCallees   (13753's 25 direct callees)
		bool initPass = true;           // [Hooks] bInitPass    (13784's 22 callees, phase markers, 5 virtual sites)
		bool perForm = true;            // [Hooks] bPerForm     (the per-form InitItem call at 0x1BE221)
		bool initRefs = true;           // [Hooks] bInitRefs    (WRLD/cell/ref InitItem: 20455, 20563, 18882)
		bool loopSplit = true;          // [Hooks] bLoopSplit   (13760's 7 internal callees)
		bool newForms = true;           // [Hooks] bNewForms    (13763 -> 13693, forms created per type)

		bool runtimeEpisodes = true;    // [Episodes] bRuntimeLoadScreens (Loading Menu open..close)
		bool formDigest = true;         // [Oracle] bFormDigest (post-load identity digests at kDataLoaded)
		bool csv = true;                // [Report] bCsv (LoadingThreader-v2.csv next to the log)

		// [Episodes] sLabels: comma-separated free text; runtime episode n gets the n-th label (the
		// startup episode is labelled "launch"), to match the tester's routine to episodes by order.
		std::string episodeLabels = "saveload,door-in,door-out,fasttravel";

		bool allowPatchedGate = false;  // [Advanced] bAllowPatchedGate
		int  topN = 25;                 // [Report] iTopN
		bool fullTable = true;          // [Report] bFullTable
	};

	// Called once from SKSEPluginLoad, before the engine starts the data load.
	void Install(const Config& a_config);

	// Called from the SKSE kDataLoaded message (main thread). Writes the startup report
	// (or defers it to the LoadFiles exit if the load has not returned yet), registers the
	// read-only Loading Menu event sink for the runtime episodes, and ends the startup episode.
	void OnDataLoaded();
}
