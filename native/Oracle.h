#pragma once

// POST-LOAD IDENTITY ORACLE (LT-2b milestone 3). Read-only digests of the form
// set the startup load produced, taken once at kDataLoaded on the main thread.
// Purpose: a future threaded load must reproduce these numbers exactly; the
// oracle is the correctness check for every later stage. Nothing is written
// into the engine.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace lt::probe::oracle
{
	inline constexpr std::size_t kTypes = 0x8A;  // RE::FormType::Max

	struct Result
	{
		bool        ran = false;
		std::string why;  // set when !ran

		// allForms map (read under its read lock)
		std::uint64_t forms = 0;       // non-null entries
		std::uint64_t nullEntries = 0;
		std::uint64_t unordered = 0;   // ORDER-INDEPENDENT: sum (mod 2^64) over forms of FNV-1a-64(formID, formType, formFlags)
		std::array<std::uint64_t, kTypes + 1> mapByType{};  // [kTypes] = formType >= kTypes

		// formArrays (order-dependent)
		std::array<std::uint64_t, kTypes> arrayLen{};
		std::array<std::uint64_t, kTypes> arrayDigest{};  // FNV-1a-64 over the FormID sequence (4 bytes LE each, 0 for a null element)
		std::uint64_t                     arraysTotal = 0;
		std::uint64_t                     ordered = 0;    // FNV-1a-64 over (type index, length, digest) of every array in index order

		double ms = 0.0;
	};

	// Takes allFormsMapLock for read for the duration of the map walk (the same
	// pattern as RE::TESForm::LookupByID). Must run when no load is in flight.
	[[nodiscard]] Result Run();

	// "LT-ORACLE v1 forms=N nulls=N unordered=0x... ordered=0x... types=NN" plus per-type hex pairs.
	[[nodiscard]] std::string MachineLine(const Result& a_r);
}
