# Build the manuscript. Needs a TeX Live with latexmk; elsarticle.cls and the
# elsarticle-num style are vendored here from the Elsevier distribution.
all: main.pdf
main.pdf: main.tex refs.bib figures/*.pdf figures/*.png
	latexmk -pdf -interaction=nonstopmode main.tex
figures: ../results/evaluation.json ../results/evaluation_runs.jsonl.gz
	python3 make_figures.py
clean:
	latexmk -C; rm -f *.bbl *.spl
.PHONY: all figures clean
