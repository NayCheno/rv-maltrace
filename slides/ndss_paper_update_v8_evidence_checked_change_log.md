# ndss_paper_update_v8_evidence_checked change log

Modified deck:
https://docs.google.com/presentation/d/1uouAZY-R_HCoehT3Sw_H7BtMzm3J0hwgGt-tdSWauBk

Original backup/source deck:
https://docs.google.com/presentation/d/10lqFlxV9RSFOzdAaaV6VFVdeyC5ddXSOOgPxCA6z1KQ

Local evidence root:
`results/evaluation/genesys2-cva6/current`

## Major changes accepted

- Created a copied v8 deck and left the original v7 deck unchanged.
- Replaced stale robustness counts with current artifact values: 128 accepted board reps, 142 attempts, 14 retained failed attempts, and P0 = 48 accepted / 62 attempts.
- Clarified unit boundaries: 12 board workloads = 4 P0 safe + 8 surrogate; 5 board benign controls are separate.
- Scoped 0 drops/wraps/gaps to the accepted marker-window gate, not to broad deployment or production logging.
- Added an end-to-end `file_open_read_write` reconstruction example tying raw events, ELF join, oracle order, and fd/path output.
- Reframed the contribution as provenance-aware semantic reconstruction, not malware detection accuracy.
- Added explicit system boundary, provenance flow, non-claims, and alternative explanations.
- Marked streaming/DMA throughput as FAIL/open and moved it to an appendix/non-claim.
- Clarified resource/timing data as implementation cost only, not cycle-level runtime overhead.
- Added recommendation slide: submit the scoped reconstruction + artifact claim, defer deployment/performance expansion.
- Updated reproducibility with package size/count/SHA and the external raw-release limitation.
- Scoped external closures to source-line, pointer-string, and board benign-control summaries.
- Added a 6-slide principle/module appendix covering system principle, capture, marker-window gating, context binding, semantic recovery, and provenance checks.

## Partial changes

- The deck remains uncompressed rather than being reduced to 8-10 slides. Main slides were repurposed, appendices preserved, and the principle/module appendix brings the deck to 28 slides.
- Problem and motivation remain separate slides, but both now use evidence-bound language.
- Source-line and pointer-string closures are included only within their external summary scope, not as a general source attribution claim.
- The all-1.0/0.0 metric presentation was narrowed to artifact fields and units. Some local artifacts do not expose every numerator/denominator directly, so the deck avoids unsupported precision beyond the named fields.

## Rejected or deliberately not claimed

- No real-malware generalization claim.
- No malware detector accuracy claim.
- No production streaming/transport throughput claim.
- No cycle-level runtime overhead claim.
- No confidence intervals or Wilson intervals. The local artifacts do not provide an independent-event denominator for the repeated marker-window reps, and the deck treats repeated windows as nested evidence rather than independent population samples.

## Unresolved items

- Exact statistical independence of repeated marker-window reps is not established.
- Whether one board attempt can produce multiple accepted windows was not confirmed; the deck avoids that claim.
- Formal event-level numerator/denominator for precision and argument reconstruction is not fully exposed in a named summary field.
- External raw release asset is not published.
- Production streaming/DMA remains open; current summary reports FAIL and sustained 0 B/s.
- Cycle-level runtime overhead has not been measured.
- Real malware is deliberately out of scope.

## Claim-evidence table

| Claim | Evidence artifacts | Slides | Boundary |
| --- | --- | --- | --- |
| Core trace-backed reconstruction claim | `statistical_robustness_summary.json`, `semantic_reconstruction_summary.json`, `case_study_manifest.json`, `semantic_provenance_summary.json` | 5, 11, 13 | 12 controlled RISC-V Linux workloads on Genesys2/CVA6 |
| Captured-window trace gates | `drop_accounting_summary.json`, `statistical_robustness_summary.json` | 6, 11, 15 | Accepted marker-window windows only |
| Provenance-labeled derived fields | `semantic_provenance_summary.json` | 6, 7, 9 | Hardware trace, exact ELF, runtime OS map, validation oracle |
| E2E reconstruction example | `file_open_read_write` case artifacts, board trace, exact ELF, semantic summary | 8 | Illustrative single workload, not full-log replay |
| Board benign controls | `external_closure/board_benign_control_summary.json` | 6, 12, 13, 14 | 5 non-network board benign controls; no general false-positive-rate claim |
| Source-line and pointer-string closures | `external_closure/board_native_source_lines_summary.json`, `external_closure/hardware_pointer_strings_summary.json` | 6, 14, 17 | Accepted external-summary scope only |
| Resource and timing cost | resource/timing summaries and resource report | 16, 22 | Implementation cost and timing closure only, not runtime slowdown |
| Artifact package | artifact package manifest and latest manifest | 18 | Local package is reviewable; external raw release asset is unpublished |
| Streaming/DMA | streaming summaries and external closure audit | 20 | FAIL/open/non-claim |
| System and module principles | `docs/08-publication/ndss2026-rv-maltrace/sections/design.tex`, `implementation.tex`, `semantic_reconstruction.tex`; `rtl/trace/*`; `tools/build_code_map.py`, `tools/join_trace_code_map.py`, `tools/package_genesys2_semantic_provenance.py`, `tools/check_genesys2_semantic_provenance.py` | 23-28 | Explanatory principle/implementation slides; no new empirical claim beyond existing artifact scope |

## Numbers that require careful wording

- `50 expected syscall labels` was computed during deck preparation from `semantic_reconstruction_summary.json`; it is not a single named field in the artifact summary.
- `323.1 MB` is decimal rounding of the raw archive byte size; the deck abbreviates the SHA as `57f48d...f611`.
- `1.618 MB/s` is from the streaming target at 50 MHz and is used as rounded context on the appendix slide.
- `3 scoped closures` is a manual count of accepted external closure categories: source lines, pointer strings, and board benign controls.
- No confidence intervals were computed.

## Validation

- Connector readback after the final p11 label fix confirmed deck id `1uouAZY-R_HCoehT3Sw_H7BtMzm3J0hwgGt-tdSWauBk`, title `ndss_paper_update_v8_evidence_checked`, revision `LAxsCNKz0OiOig`, and slide object IDs `p1` through `p22`.
- Fresh LARGE thumbnails were saved for all 22 slides under `slides/preview-v8-google`.
- Fresh contact sheet: `slides/preview-v8-google/contact-sheet-v8-google.png`.
- Visual checks were performed on the contact sheet and focused slides 8, 11, 13, and 17. The p11 label wrapping issue was fixed by changing `max drops/wraps/gaps` to `gate max`.

## 2026-06-26 principle/module appendix update

- Added slide 23 `SYSTEM PRINCIPLE`: hardware events become claims only after marker-window gating, ELF/runtime context binding, semantic recovery, and provenance checks.
- Added slide 24 `MODULE: CAPTURE`: CVA6 trace taps, event classification, `syscall_tap`, `trace_filter`, and the board-minimal ARG_MEM boundary.
- Added slide 25 `MODULE: WINDOW`: begin/end marker windows, BRAM ring behavior, sequence deduplication, and drop/wrap/full accounting boundary.
- Added slide 26 `MODULE: CONTEXT`: exact ELF code maps plus marker-scoped runtime maps for PC-to-binary/process binding.
- Added slide 27 `MODULE: SEMANTICS`: source-labeled behavior graph recovery, oracle/reference boundary, and `file_open_read_write` example.
- Added slide 28 `MODULE: CHECKS`: evidence-file/source-label gate, schema/artifact/SHA checks, and oracle-vs-hardware provenance boundary.

## Latest validation

- Connector readback after the principle/module appendix confirmed deck id `1uouAZY-R_HCoehT3Sw_H7BtMzm3J0hwgGt-tdSWauBk`, title `ndss_paper_update_v8_evidence_checked`, revision `xltWzix-EaACtQ`, and 28 slides.
- Final slide object IDs are `p1` through `p22`, then `m23_how_it_works`, `m24_capture`, `m25_window_gate`, `m26_context_bind`, `m27_semantic_recovery`, and `m28_provenance_checks`.
- Fresh LARGE thumbnails were saved for slides 23-28 under `slides/preview-v8-google`, and `contact-sheet-v8-google.png` was regenerated for all 28 slides.
- Visual checks were performed on the regenerated contact sheet and focused slides 23-28. No obvious overlap, clipping, or stale template text was visible.

## 2026-06-26 story-at-a-glance update

- Replaced slide 2 with a front summary answering: what problem is solved, how it is solved, what result is achieved, what limitation remains, what scoped claim follows, and what action is recommended.
- Added the slide 2 rows `SOLVES`, `METHOD`, `RESULT`, `LIMIT`, `CLAIM`, and `ACTION`.
- Updated slide 2 speaker notes to give the Chinese narration for the four-question summary.
- Kept the existing 28-slide structure unchanged; this update repurposes slide 2 instead of inserting a new slide.

## Latest validation after story slide

- Connector readback confirmed deck id `1uouAZY-R_HCoehT3Sw_H7BtMzm3J0hwgGt-tdSWauBk`, title `ndss_paper_update_v8_evidence_checked`, revision `MZyYb1gCNfiYJw`, and 28 slides.
- Slide 2 connector readback confirmed the headline `Problem, method, result, limit in one slide` and rows for `SOLVES`, `METHOD`, `RESULT`, `LIMIT`, `CLAIM`, and `ACTION`.
- A fresh LARGE thumbnail for slide 2 was saved as `slides/preview-v8-google/slide-02.png`, and `contact-sheet-v8-google.png` was regenerated for all 28 slides.
- Visual checks were performed on slide 2 and the regenerated contact sheet. No obvious overlap, clipping, or stale duplicate label was visible.

## 2026-06-26 final report polish

- Renamed the Drive presentation to `RV-MalTrace_final_report_2026-06-26`.
- Updated slide 1 from an NDSS update cover to a final-report cover and sharpened the claim sentence.
- Fixed slide 4 card-heading crowding by shortening the three card titles and reducing heading size.
- Fixed slide 7 data-flow crowding by shortening node labels and compacting body text.
- Fixed slide 9 lower-right card overlap by shortening `validation oracle` to `oracle labels`.
- Fixed slide 10 title/subtitle crowding by shortening the title to `RV-MalTrace reconstructs behavior, not detection`.
- Shortened slide 11 title to `128 accepted reps support the board claim`.

## Latest validation after final report polish

- Connector readback confirmed deck id `1uouAZY-R_HCoehT3Sw_H7BtMzm3J0hwgGt-tdSWauBk`, title `RV-MalTrace_final_report_2026-06-26`, revision `MsmNlmJ-9Lc4-g`, and 28 slides.
- Final slide object IDs are `p1` through `p22`, then `m23_how_it_works`, `m24_capture`, `m25_window_gate`, `m26_context_bind`, `m27_semantic_recovery`, and `m28_provenance_checks`.
- Connector readback confirmed final edited text on slides `p1`, `p4`, `p7`, `p9`, `p10`, and `p11`.
- Fresh LARGE thumbnails were saved for slides 1, 4, 7, 9, 10, and 11 under `slides/preview-v8-google`.
- `slides/preview-v8-google/contact-sheet-v8-google.png` and `slides/preview-v8-google/contact-sheet-v8-google-large.png` were regenerated for all 28 slides.
- Visual checks were performed on the focused thumbnails and regenerated contact sheet. No obvious overlap, clipping, or stale template text was visible.

## 2026-06-26 detailed speaker notes update

- Rewrote speaker notes for all 28 slides into a consistent Chinese narration structure:
  - `本页讲什么`
  - `讲述细节`
  - `实现细节` or `口径边界`
  - `过渡` or final close
- Expanded main-report notes to explain the solved problem, method, result, limitation, evidence scope, and recommendation.
- Expanded module appendix notes to explain capture, marker-window gating, context binding, semantic recovery, and provenance checks at implementation level.
- Kept the visible slide canvases unchanged; this pass only edited speaker notes.

## Latest validation after speaker notes update

- Connector readback confirmed deck id `1uouAZY-R_HCoehT3Sw_H7BtMzm3J0hwgGt-tdSWauBk`, title `RV-MalTrace_final_report_2026-06-26`, revision `cR1oBHqZaJigZg`, and 28 slides.
- Connector readback confirmed all 28 slides have speaker-notes object IDs.
- Spot-check readback confirmed the new detailed notes on slide 1, slide 2, and slide 28.
- Fresh LARGE thumbnails were fetched and saved for all 28 slides under `slides/preview-v8-google/notes-refresh`.
- `slides/preview-v8-google/notes-refresh/contact-sheet-notes-refresh-large.png` was regenerated from the post-write thumbnails.
- Visual check of the regenerated contact sheet showed no visible slide-layout change from the notes-only pass.

## 2026-06-26 weekly-meeting clarity polish

- Updated slide 3 subtitle to make the evidence-chain split explicit: software observers validate reconstruction, while hardware trace remains the evidence path.
- Expanded slide 3 and slide 4 speaker notes to distinguish isolation from validation: `strace`/`qemu` are validation oracles, not final evidence.
- Expanded slide 7 and slide 8 speaker notes to clarify that oracle comparisons are sanity/validation checks and do not change provenance labels.
- Updated slide 11 subtitle and notes so `128` is explained as gate-passed, reproducible marker-window evidence within the controlled scope, not raw repetition count inflation.
- Updated slide 14 subtitle and notes to frame bounded scope as a staged strategy: prove provenance first, then scale deployment evidence later.
- Updated slide 16 title, subtitle, and notes to separate static FPGA implementation cost from cycle-level runtime overhead.
- Updated slide 17 into an explicit recommendation and ask page: submit scoped claim, request 1-2 colleague artifact review/reproduction, defer deployment overhead, and finalize figures/citations/disclosures.
- Kept slide count and ordering unchanged at 28 slides; no new slide was inserted.

## Latest validation after weekly-meeting clarity polish

- Connector readback confirmed deck id `1uouAZY-R_HCoehT3Sw_H7BtMzm3J0hwgGt-tdSWauBk`, title `RV-MalTrace_final_report_2026-06-26`, revision `kc2HDfu04VdNHA`, and 28 slides.
- Presentation outline readback confirmed visible text changes on slides `p3`, `p11`, `p14`, `p16`, and `p17`.
- Notes readback confirmed the updated speaker notes on slides `p3`, `p4`, `p7`, `p8`, `p11`, `p14`, `p16`, and `p17`.
- Fresh LARGE thumbnails were fetched for slides `p3`, `p4`, `p7`, `p8`, `p11`, `p14`, `p16`, and `p17` under `slides/preview-v8-google/weekly-risk-polish`.
- `slides/preview-v8-google/weekly-risk-polish/contact-sheet-weekly-risk-polish.png` was regenerated from the post-write thumbnails.
- Visual checks were performed on the regenerated contact sheet plus focused slide 16 and slide 17 thumbnails. The initial slide 16 title wrap was fixed by shortening the title to `Trace bitstream meets timing with measured FPGA cost`.

## 2026-06-26 module diagram rewrite

- Rebuilt slides 23-28 as diagram-led module explanation pages instead of text-list pages.
- Slide 23 now shows the full system principle flow: CVA6 signals -> capture -> window gate -> context bind -> recovery -> provenance check, with validation oracle and open-boundary lanes separated.
- Slide 24 now shows the capture data path from CVA6 core signals through per-event taps, `trace_filter`, event records, and BRAM/FIFO readout.
- Slide 25 now shows the marker-window state/gate flow from `marker_enter` to accepted reps, with retained failures as an explicit red branch.
- Slide 26 now shows context binding as three inputs (`Raw trace`, `Exact ELF code map`, `Runtime OS map`) joining at `join_trace_code_map` and producing annotated events.
- Slide 27 now shows semantic recovery as a source-labeled behavior graph, with `qemu/strace oracle` kept in a separate validation lane.
- Slide 28 now shows provenance checks as artifact package -> check stack -> provenance filter -> report/open outputs, with allowed source labels shown as chips.
- Updated speaker notes on slides 23-28 to narrate the new diagrams and preserve implementation details, scope boundaries, and oracle/provenance distinctions.

## Latest validation after module diagram rewrite

- Connector readback confirmed deck id `1uouAZY-R_HCoehT3Sw_H7BtMzm3J0hwgGt-tdSWauBk`, title `RV-MalTrace_final_report_2026-06-26`, revision `N9iyy7Q-4nPorg`, and 28 slides.
- Presentation outline readback confirmed visible diagram text on slides `m23_how_it_works`, `m24_capture`, `m25_window_gate`, `m26_context_bind`, `m27_semantic_recovery`, and `m28_provenance_checks`.
- Fresh LARGE thumbnails were fetched and curled for slides 23-28 under `slides/preview-v8-google/module-diagram-polish`.
- `slides/preview-v8-google/module-diagram-polish/module-diagram-contact-sheet-final.png` was regenerated from the fresh post-write thumbnails.
- Visual checks were performed on each focused thumbnail and the final contact sheet. No obvious overlap, clipping, stale old-module text, or out-of-bounds objects were visible.

## 2026-06-26 advisor deep-dive appendix

- Appended slides 29-40 to make the advisor-facing mechanism concrete rather than abstract.
- Slide 29 introduces the full deep-dive chain: capture, gate, bind, and report.
- Slide 30 shows the end-to-end architecture from marker workload through CVA6/RVFI, BRAM readout, offline analysis, and provenance-filtered claims.
- Slide 31 shows the actual BRAM record schema and example records from `hello_write/rep_01/bram_records.jsonl`.
- Slide 32 explains marker-window acceptance and gate checks using begin/end marker, sequence, drop, wrap, and retained-failure evidence.
- Slide 33 explains the BRAM ring implementation state: `capture_fire`, `ring_mem`, `write_index`, sequence, drop/wrap counters, and dump readout.
- Slide 34 shows feature extraction from accepted windows, including MARKER, PRIV, TRAP, SYSCALL_ENTRY/RET, ARG_MEM, and quality counters.
- Slide 35 explains bounded pointer snapshot/ARG_MEM behavior and explicitly separates hardware fragments from full-string non-claims.
- Slide 36 explains context binding from raw PC to executable/process evidence using exact ELF and runtime OS maps.
- Slide 37 gives the `file_open_read_write` semantic recovery example with hardware window features, expected syscall order, fd/path graph, and oracle-labeled fields.
- Slide 38 adds a provenance matrix that states which fields can be reported as hardware, exact ELF, runtime-map, or validation-oracle evidence.
- Slide 39 shows the output artifact package as an inspectable file tree from raw board files through summaries and per-sample semantic artifacts.
- Slide 40 closes the appendix with the problem, solution, results, limits, and next advisor discussion decisions.

## Latest validation after advisor deep-dive appendix

- Connector readback confirmed deck id `1uouAZY-R_HCoehT3Sw_H7BtMzm3J0hwgGt-tdSWauBk`, title `RV-MalTrace_final_report_2026-06-26`, revision `W3eGDh2_5ZaqJg`, and 40 slides.
- Final new slide object IDs are `dd29_section`, `dd30_arch`, `dd31_record`, `dd32_window`, `dd33_bram`, `dd34_features`, `dd35_pointer`, `dd36_context`, `dd37_semantics`, `dd38_prov`, `dd39_outputs`, and `dd40_limits`.
- Fresh LARGE thumbnails were fetched and curled for slides 29-40 under `slides/preview-v8-google/advisor-deep-dive`.
- `slides/preview-v8-google/advisor-deep-dive/advisor-deep-dive-contact-sheet-29-40.png` was regenerated from the fresh post-write thumbnails.
- Visual checks were performed on each focused thumbnail and the 29-40 contact sheet. No obvious overlap, clipping, stale placeholder text, or out-of-bounds objects were visible.

## 2026-06-26 Chinese advisor-discussion deck

- Created a separate editable Google Slides copy titled `RV-MalTrace_中文汇报版_2026-06-26` instead of overwriting the English final report deck.
- Updated slide 2 from a one-slide story summary into a recommended narration route:
  - first define the problem and scoped claim,
  - then build the evidence chain,
  - then present key results,
  - then jump into slides 23-39 when the advisor asks for implementation details,
  - then close with slide 40 and the next actions.
- Localized the visible text across the 40-slide deck into Chinese while preserving implementation tokens and artifact terms such as `CVA6`, `RVFI`, `BRAM`, `ARG_MEM`, `qemu/strace`, `runtime_os_map`, `validation oracle`, and sample/file names.
- Kept the expanded advisor-facing principle diagrams, architecture diagrams, runtime process views, feature extraction views, provenance matrix, and output-artifact tree intact as editable Slides content.
- Updated slide 40 so the closing discussion explicitly answers what problem is solved, how it is solved, what results are supported, what remains limited, and what decision should be discussed next.

## Latest validation after Chinese advisor-discussion deck

- Connector readback confirmed deck id `1Gxld5G0iYeE6hsH0JO1EBiMeYUBXnR84F06rUv6uYAY`, title `RV-MalTrace_中文汇报版_2026-06-26`, revision `KwJRSiIUfXHepA`, and 40 slides.
- Final slide order was confirmed as `p1`-`p22`, `m23_how_it_works`-`m28_provenance_checks`, and `dd29_section`-`dd40_limits`.
- Connector readback confirmed the rebuilt slide 2 route objects with `zh2_*` IDs and the updated detailed Chinese speaker notes.
- Connector readback confirmed slide 40 contains the Chinese problem/solution/results/limits/next-discussion close.
- Fresh LARGE thumbnails were fetched and curled after each visible write pass. Final validation assets are under `slides/preview-v8-google/chinese-version`.
- Final 40-slide contact sheet: `slides/preview-v8-google/chinese-version/final/contact_all_40_v2.png`.
- Visual checks of the final contact sheet plus focused slide 2 and deep-dive contact sheets showed no obvious overlap, clipping, stale placeholder text, or out-of-bounds objects. Some low-level implementation labels intentionally remain in English where they are code/module names.
