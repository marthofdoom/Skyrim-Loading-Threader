# Form counts, LoreRim (profile Ultra)

Header-only census of record signatures across the active plugins of one SkyrimSE modlist, to size the per-type InitItem pass (LT-1b).

## Totals

- Active plugins parsed: 3,424 (all resolved). By kind: 44 ESM, 121 ESP, 3,259 ESL-flagged. Combined size about 1.10 GB.
- Records: 2,977,423 (GRUPs and TES4 headers excluded).
- New (defined in the plugin): 2,494,504 (83.8%). Overrides of a master's form: 482,919 (16.2%).
- Compressed-flag records: 236,287 (7.9%). Compressed records are concentrated in CELL (94,202), NAVM (41,019), LAND (78,332) and NPC_ (22,734).

## Top 25 signatures by total

| Sig | New | Override | Total | Compressed |
|---|---|---|---|---|
| REFR | 1,760,914 | 229,321 | 1,990,235 | 0 |
| CELL | 106,186 | 81,178 | 187,364 | 94,202 |
| INFO | 117,135 | 12,594 | 129,729 | 0 |
| LAND | 68,770 | 17,549 | 86,319 | 78,332 |
| NPC_ | 57,736 | 23,673 | 81,409 | 22,734 |
| DIAL | 49,366 | 5,986 | 55,352 | 0 |
| NAVM | 35,875 | 5,205 | 41,080 | 41,019 |
| STAT | 30,918 | 6,506 | 37,424 | 0 |
| ACHR | 26,188 | 3,508 | 29,696 | 0 |
| WEAP | 12,557 | 13,267 | 25,824 | 0 |
| COBJ | 15,377 | 9,013 | 24,390 | 0 |
| HDPT | 22,616 | 1,638 | 24,254 | 0 |
| ARMO | 10,392 | 11,154 | 21,546 | 0 |
| LVLI | 10,314 | 7,110 | 17,424 | 0 |
| MGEF | 11,343 | 3,822 | 15,165 | 0 |
| PACK | 13,567 | 1,083 | 14,650 | 0 |
| SPEL | 8,357 | 5,776 | 14,133 | 0 |
| DLBR | 10,278 | 53 | 10,331 | 0 |
| SNDR | 6,206 | 4,098 | 10,304 | 0 |
| ARMA | 7,744 | 1,990 | 9,734 | 0 |
| TXST | 8,321 | 292 | 8,613 | 0 |
| BOOK | 4,445 | 4,053 | 8,498 | 0 |
| IDLE | 7,208 | 612 | 7,820 | 0 |
| QUST | 5,714 | 2,011 | 7,725 | 0 |
| GLOB | 6,757 | 567 | 7,324 | 0 |

## Cross-check against the engine count

Docs/LT-2-results-first-run.md reports 1,343,279 records dispatched by the startup load. This census gives 2,977,423 records, 2.2x higher: a MISMATCH, not the same ballpark. REFR alone is 1,990,235 (66.8%). Excluding REFR, ACHR and the few other placed-reference types (2,020,435 records) leaves 956,988. The engine's 1,343,279 sits between that and the full total, so the engine evidently does not dispatch every placed reference at startup (cell-child references are read when a cell is attached or loaded, not in the startup pass), while the non-reference forms are presumably all loaded. The difference cannot be reconciled from headers alone: it would take the probe's per-signature dispatch counts, which this document does not have. Treat the 1.34M figure and this census as measuring different sets.

## Implication for the InitItem pass

The per-type InitItem work scales with NEW forms of the types the loop visits, not with raw record counts. Excluding placed references, new forms total about 707,000 and are led by INFO (117k), CELL (106k), LAND (69k), NPC_ (58k), DIAL (49k), NAVM (36k) and STAT (31k). Overrides add less per-form work because the form already exists from a master and is patched. REFR/ACHR/ACRE references are 2.0M of the 3.0M records but are initialized in the worldspace and cell phases, not in the per-type loop, so the per-type InitItem cost should be modelled on the non-reference counts and the reference work treated separately.

## Method and limits

- Plugin order: the five base masters, then every '*' (enabled) line of the profile's plugins.txt in listed order. Names are matched case-insensitively. Each name resolves to the highest-priority enabled mod in the profile's modlist that contains the file at its top level, otherwise the stock game Data folder.
- Parse: TES4 header, then top-level GRUPs walked recursively by group size, including cell and world child groups. Headers only; nothing is decompressed.
- New vs override: count the MAST subrecords (N) in the TES4 record. A record whose formID high byte is N or above is new, below N is an override. The same rule is used for ESL plugins.
- Limits: runtime-created forms (save-game forms, dynamically generated leveled lists, etc.) are not counted. Creation Club plugins were counted only if listed as enabled in plugins.txt; none were added implicitly. Disabled plugins and plugins not in plugins.txt are ignored. A mod's loose-file overrides, BSA contents and records skipped by the engine (e.g. deleted-flag or ignored records) are not distinguished. Records in a plugin that duplicates a name in a lower-priority mod are taken from the winner only. Counts of new forms assume well-formed plugins (a high byte above N is treated as new).
