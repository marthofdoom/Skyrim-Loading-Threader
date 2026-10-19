# Skyrim-Loading-Threader

Goal: the "dialysis machine" for Skyrim SE's startup data load. Draw pure work (record framing, zlib inflate) out of
the engine's serial per-plugin loop onto workers, and return the results in the original serial order, so load-order
semantics never change. Design and findings: `Docs/FEASIBILITY.md`, `Docs/LT-1-contract-map.md`.

Current stage: **LT-2, a passive timing probe** (`native/`, SkyrimSE 1.6.1170.0 only). It measures how the startup
load splits between inflate, raw reads, Load bodies and the post-loop pass, and prints whether stage 2 is worth
building. Build, deploy and read it: `Docs/LT-2-probe-howto.md`.

Layout:
- `native/`: the SKSE plugin (CommonLibSSE-NG 3.7.0, C++23). Built only by GitHub Actions (`.github/workflows/native.yml`).
- `Data/SKSE/Plugins/LoadingThreader.ini`: every option, documented.
- `Docs/`: feasibility, the LT-1 contract map, the LT-2 how-to.
