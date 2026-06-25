BUILD_DIR := build
MAIN := main

.PHONY: all clean

all:
	latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=$(BUILD_DIR) $(MAIN).tex

clean:
	latexmk -C -outdir=$(BUILD_DIR) $(MAIN).tex
