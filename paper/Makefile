# Build the manuscript. Needs a TeX Live with latexmk; the journal's template class IEEEoj.cls and its
# logo ojcoms.png (IEEE_OJCOMS-template-LaTex_202401) and IEEEtran-doi.bst (numeric IEEE references with
# DOIs, for the cite package the template loads) are vendored here.
all: main.pdf
main.pdf: main.tex refs.bib figures/*.pdf
	latexmk -pdf -interaction=nonstopmode main.tex
DRAWN = figures/alg1_v1.pdf figures/alg2_v2.pdf figures/alg3_sim.pdf
figures: ../results/evaluation.json $(DRAWN)
	python3 figures.py
figures/alg1_v1.pdf: figures/alg1_v1_body.tex
figures/alg2_v2.pdf: figures/alg2_v2_body.tex
figures/alg3_sim.pdf: figures/alg3_sim_body.tex
$(DRAWN): %.pdf: %.tex
	cd figures && pdflatex -interaction=nonstopmode $(notdir $<) && rm -f $(notdir $*).aux $(notdir $*).log \
	  && pdftoppm -r 300 -png -singlefile $(notdir $*).pdf $(notdir $*)
rebuttal: rebuttal_round8.docx
rebuttal_round8.docx: rebuttal_round8.js
	node rebuttal_round8.js
word: main.pdf
	python3 make_docx.py && rm -f build_word.tex
clean:
	latexmk -C; rm -f *.bbl *.spl
.PHONY: all figures rebuttal word clean
