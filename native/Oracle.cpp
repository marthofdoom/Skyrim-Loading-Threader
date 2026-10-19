#include "PCH.h"

#include "Oracle.h"

// Identity oracle. Fields hashed, exactly:
//   per form (order-independent digest): FNV-1a-64 over these 9 bytes, in order
//     formID    4 bytes, little endian   (TESForm::GetFormID)
//     formType  1 byte                   (TESForm::GetFormType, the engine's type byte)
//     formFlags 4 bytes, little endian   (TESForm::GetFormFlags, the full dword incl. runtime flags)
//   the 64-bit per-form hashes are SUMMED modulo 2^64 (commutative => independent of map order).
//   per formArray (order-dependent digest): FNV-1a-64 over the FormID (4 bytes LE) of every element
//     in array order (0 for a null element); arrays t = 0 .. 0x89.
//   ordered (combined): FNV-1a-64 over, for t = 0..0x89: t (1 byte), length (8 bytes LE), digest (8 bytes LE).
// FNV-1a-64: offset 0xcbf29ce484222325, prime 0x100000001b3 (same as Sites.h Fnv1a64).

namespace lt::probe::oracle
{
	namespace
	{
		constexpr std::uint64_t kBasis = 0xcbf29ce484222325ULL;
		constexpr std::uint64_t kPrime = 0x100000001b3ULL;

		inline void Mix(std::uint64_t& a_h, std::uint8_t a_b) noexcept
		{
			a_h ^= a_b;
			a_h *= kPrime;
		}

		template <class T>
		inline void MixLE(std::uint64_t& a_h, T a_v) noexcept
		{
			for (std::size_t i = 0; i < sizeof(T); ++i) {
				Mix(a_h, static_cast<std::uint8_t>((static_cast<std::uint64_t>(a_v) >> (8 * i)) & 0xFF));
			}
		}
	}

	Result Run()
	{
		Result r;
		const auto t0 = std::chrono::steady_clock::now();

		auto* dh = RE::TESDataHandler::GetSingleton();
		if (!dh) {
			r.why = "TESDataHandler singleton is null";
			return r;
		}

		const auto& [map, lock] = RE::TESForm::GetAllForms();
		if (!map) {
			r.why = "allForms map pointer is null";
			return r;
		}
		{
			const RE::BSReadLockGuard locker{ lock.get() };
			for (const auto& entry : *map) {
				const RE::TESForm* form = entry.second;
				if (!form) {
					++r.nullEntries;
					continue;
				}
				const std::uint32_t id = form->GetFormID();
				const auto          type = static_cast<std::uint8_t>(form->GetFormType());
				const std::uint32_t flags = form->GetFormFlags();
				std::uint64_t       h = kBasis;
				MixLE(h, id);
				Mix(h, type);
				MixLE(h, flags);
				r.unordered += h;  // wraps modulo 2^64 by definition
				++r.forms;
				++r.mapByType[type < kTypes ? type : kTypes];
			}
		}

		std::uint64_t all = kBasis;
		for (std::size_t t = 0; t < kTypes; ++t) {
			auto&         arr = dh->GetFormArray(static_cast<RE::FormType>(t));
			std::uint64_t h = kBasis;
			const auto    n = arr.size();
			for (std::uint32_t i = 0; i < n; ++i) {
				const RE::TESForm* f = arr[i];
				MixLE(h, static_cast<std::uint32_t>(f ? f->GetFormID() : 0u));
			}
			r.arrayLen[t] = n;
			r.arrayDigest[t] = h;
			r.arraysTotal += n;
			Mix(all, static_cast<std::uint8_t>(t));
			MixLE(all, static_cast<std::uint64_t>(n));
			MixLE(all, h);
		}
		r.ordered = all;
		r.ran = true;
		r.ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
		return r;
	}

	std::string MachineLine(const Result& a_r)
	{
		if (!a_r.ran) {
			return std::format("LT-ORACLE v1 NOT-RUN {}", a_r.why);
		}
		std::string s = std::format("LT-ORACLE v1 forms={} nulls={} unordered=0x{:016X} ordered=0x{:016X} arrays={}",
			a_r.forms, a_r.nullEntries, a_r.unordered, a_r.ordered, a_r.arraysTotal);
		for (std::size_t t = 0; t < kTypes; ++t) {
			if (a_r.mapByType[t] != 0 || a_r.arrayLen[t] != 0) {
				s += std::format(" T{:02X}={}/{}/0x{:016X}", t, a_r.mapByType[t], a_r.arrayLen[t], a_r.arrayDigest[t]);
			}
		}
		if (a_r.mapByType[kTypes] != 0) {
			s += std::format(" TOTHER={}", a_r.mapByType[kTypes]);
		}
		return s;
	}
}
