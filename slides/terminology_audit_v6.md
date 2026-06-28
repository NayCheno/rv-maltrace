# RV-MalTrace Terminology Audit V6

This file records terminology that was replaced, retained, or defined to avoid unsupported invented terms in the deck.

| Old / candidate term | Decision | Deck wording | Reason |
| --- | --- | --- | --- |
| hardware-rooted | Replaced | hardware-assisted | Hardware-assisted tracing is a standard systems term; hardware-rooted sounded like a slogan. |
| trace facts | Replaced | trace events / hardware observations | Trace event is the standard term for records emitted by a tracing system. |
| evidence-chain audit | Replaced | trace-backed behavior analysis | The new phrase describes the actual pipeline without inventing a named method. |
| lower surface | Replaced | out-of-band trace / hardware path | Out-of-band and sideband are standard trace/monitoring terms. |
| evidence planes | Replaced | data sources | Data source is clear and standard; no new abstraction is needed. |
| derived rows | Replaced | malware-derived behavior cases | Behavior case is clearer and maps to the repository's case-study evidence. |
| No free source lines | Replaced | No source-line attribution claim | Source-line attribution is the standard term. |
| P0 safe | Removed from slides and notes | safe baseline | Internal grouping labels do not help the weekly argument. |
| oracle | Explained | reference/oracle | Oracle is a standard testing term; main slides use reference for readability. |
| provenance | Moved out of main slide text | source labels | Source label is clearer for weekly discussion; provenance remains a standard term if needed in notes. |
| surrogate | Kept and scoped | safe malware-behavior surrogate | Surrogate is standard for safety-controlled replacements; notes define it as repo-authored and non-payload. |
