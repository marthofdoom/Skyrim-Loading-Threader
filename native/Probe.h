#pragma once

// LT-2 stage-1 timing probe: PASSIVE. See Probe.cpp for the hook list and the
// rules that keep it passive.

namespace lt::probe
{
	struct Config
	{
		bool enabled = true;            // [General] bEnabled -- the kill-switch: 0 => no hook at all
		bool verbose = false;           // [General] bVerboseLog
		bool perPlugin = true;          // [Hooks] bPerPlugin   (13760)
		bool record = true;             // [Hooks] bRecord      (13763)
		bool loadBody = true;           // [Hooks] bLoadBody    (13690)
		bool rawRead = true;            // [Hooks] bRawRead     (13991, entry detour)
		bool inflate = true;            // [Hooks] bInflate     (14032)
		bool postLoop = true;           // [Hooks] bPostLoop    (13784)
		bool allowPatchedGate = false;  // [Advanced] bAllowPatchedGate
		int  topN = 25;                 // [Report] iTopN
		bool fullTable = true;          // [Report] bFullTable
	};

	// Called once from SKSEPluginLoad, before the engine starts the data load.
	void Install(const Config& a_config);

	// Called from the SKSE kDataLoaded message. Writes the report (or defers it
	// to the LoadFiles exit if the load has not returned yet) and then turns
	// every hook into a pure pass-through for the rest of the session.
	void OnDataLoaded();
}
