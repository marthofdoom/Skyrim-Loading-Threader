# LT-2 first field run: where Skyrim SE's startup data load goes

Build: commit 1d90a2a (CI run 39194613522), SkyrimSE 1.6.1170.0 under Proton, a 3499-plugin Requiem-based list.
One run, single sample, file cache state unknown. Probe overhead estimated at 0.4 s of 117 s. The game started
normally and reached the main menu with the probe installed; all 7 hook groups installed and fired.

LoadFiles (13753) total: **117.3 s**, one thread (the same thread that later receives kDataLoaded).

| Share | ms | % | What |
|---|---|---|---|
| Load bodies (13690) | 44155 | 37.6 | per-form-type Load, serial, impure (LT-1) |
| Post-loop InitItem pass (13784) | 40638 | 34.6 | one pass over all form arrays after the plugin loop |
| LoadFiles rest (13753 ex) | 20849 | 17.8 | pass 1, 13767, 13403, 30433: NOT yet characterised |
| Record dispatch (13763 ex) | 5612 | 4.8 | |
| Per-plugin loop (13760 ex) | 3948 | 3.4 | OpenTES, seek/header, editor IDs, progress, CloseTES |
| Raw read (13991) | 1219 | 1.0 | |
| Inflate (14032) | 869 | 0.7 | 73,298 inflates, 96.5 MB in, 197.4 MB out |

Counts: 1,343,279 records dispatched; 17,968,651 raw reads; each compressed record inflated exactly once.

## Conclusions
1. **Decompress-ahead (the pure seam found in LT-1) is worthless here: inflate is 0.7%.**
   **CORRECTION (2026-10-19):** the original wording here also said that file reading in general is ~2% and that
   I/O-side work cannot help. That was too strong. The 1.0% "raw read" figure is time inside `TESFile::ReadData`
   (13991), which copies from the engine's in-memory block buffer; it does NOT include the read() syscalls that fill
   that buffer. A separate project (usvfs read shim) measured that the same load is syscall-bound under Proton
   (20k-110k tiny read() calls per second, 35-55% of the main thread's CPU in the kernel). The kernel time therefore
   sits inside other buckets, most likely "Load bodies" and part of the per-plugin loop. Whether I/O-side work helps
   is OPEN until the probe splits user and kernel time per phase (probe v2 does).
2. **The time is in two serial CPU blocks:** Load bodies (37.6%) and the post-loop InitItem pass (34.6%), plus an
   unexplained 17.8%. Any real speedup must parallelize engine-state-mutating work.
3. **Next questions:** (a) is the InitItem pass (13784) splittable (per form type / per form, are InitItem bodies
   independent of each other)? It runs after all forms exist, which is a much friendlier setting than Load. (b) What
   are 13767, 13403, 30433 and pass 1 (17.8%)? (c) Load bodies stay impure; ~0x8A types.
