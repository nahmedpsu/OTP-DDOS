# Build the manuscript. Needs a TeX Live with latexmk; elsarticle.cls and the
# elsarticle-num style are vendored here from the Elsevier distribution.
all: main.pdf
main.pdf: main.tex refs.bib figures/*.pdf
	latexmk -pdf -interaction=nonstopmode main.tex
figures: ../results/evaluation.json
	python3 figures.py
rebuttal: rebuttal_round6.docx
rebuttal_round6.docx: rebuttal_round6.js
	node rebuttal_round6.js
clean:
	latexmk -C; rm -f *.bbl *.spl
.PHONY: all figures rebuttal clean
