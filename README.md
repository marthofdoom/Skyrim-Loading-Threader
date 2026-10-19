# Skyrim-Loading-Threader

Goal: the "dialysis machine" for Skyrim SE's startup data load. Draw pure work (record framing, zlib inflate) out of
the engine's serial per-plugin loop onto workers, and return the results in the original serial order, so load-order
semantics never change. Design and findings: `Docs/FEASIBILITY.md`, `Docs/LT-1-contract-map.md`.

Current stage: **LT-2b (v0.2.0), a passive timing probe with episodes** (`native/`, SkyrimSE 1.6.1170.0 only). It measures how the startup
load splits between inflate, raw reads, Load bodies and the post-loop pass, and prints whether stage 2 is worth
building. v2 adds loading EPISODES (startup plus every Loading Menu at runtime), 13784 phases, per-form-type and
per-signature tables, a kernel/user time split, a sectioned CSV and a post-load identity oracle. Build, deploy,
run the loading-episode test routine and read it: `Docs/LT-2-probe-howto.md`.

Layout:
- `native/`: the SKSE plugin (CommonLibSSE-NG 3.7.0, C++23). Built only by GitHub Actions (`.github/workflows/native.yml`).
- `Data/SKSE/Plugins/LoadingThreader.ini`: every option, documented.
- `Docs/`: feasibility, the LT-1 contract map, the LT-2 how-to.
