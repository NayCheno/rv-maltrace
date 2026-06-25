# RV-MalTrace NDSS 2026 Draft

This directory is a standalone NDSS-style LaTeX paper workspace for the
RV-MalTrace CVA6/Genesys2 line.

The official NDSS 2026 template files were downloaded from:

- https://www.ndss-symposium.org/ndss2026/submissions/templates/

Formatting requirements recorded from the official page:

- US letter paper.
- Two-column layout.
- Columns no more than 9.25 in. high and 3.5 in. wide.
- Times font, 10 pt or larger, with 11 pt or larger line spacing.
- Initial submissions are anonymous.
- Submissions are PDF.

## Layout

- `main.tex`: paper entry point using the official NDSS/IEEEtran class.
- `IEEEtran.cls`: official class file from the NDSS 2026 template page.
- `sections/`: body text split by paper section.
- `figures/`: LaTeX-native figure placeholders.
- `tables/`: scope and evaluation tables extracted from the current evidence docs.
- `references.bib`: initial bibliography.
- `templates/`: official NDSS template reference files for comparison.
- `notes/source_material.md`: source documents used to extract this draft.

## Build

From this directory:

```sh
latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=build main.tex
```

Or from the repository root:

```sh
latexmk -pdf -interaction=nonstopmode -halt-on-error \
  -outdir=docs/08-publication/ndss2026-rv-maltrace/build \
  docs/08-publication/ndss2026-rv-maltrace/main.tex
```

## Current Scope

This draft uses the CVA6/Genesys2 current evidence directory:

```text
results/evaluation/genesys2-cva6/current/
```

It intentionally does not evaluate real-malware validation, production
streaming/DMA throughput, JTAG RAM boot, SD-card-free kernel update, or
board cycle-overhead measurements.

The older 35T/LiteX/VexRiscv prototype evidence is not mixed into this
paper's main result. It can become a separate paper or appendix only after the
scope is explicitly changed.
