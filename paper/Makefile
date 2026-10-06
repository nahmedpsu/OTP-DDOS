# Build the manuscript. Needs a TeX Live with latexmk; elsarticle.cls and the
# elsarticle-harv style are vendored here from the Elsevier distribution.
all: main.pdf
main.pdf: main.tex refs.bib figures/*.pdf
	latexmk -pdf -interaction=nonstopmode main.tex
DRAWN = figures/fig8_defense_path.pdf figures/fig9_threat_model.pdf figures/fig10_steps.pdf figures/alg1_v1.pdf figures/alg2_v2.pdf
figures: ../results/evaluation.json $(DRAWN)
	python3 figures.py
figures/alg1_v1.pdf: figures/alg1_v1_body.tex
figures/alg2_v2.pdf: figures/alg2_v2_body.tex
$(DRAWN): %.pdf: %.tex
	cd figures && pdflatex -interaction=nonstopmode $(notdir $<) && rm -f $(notdir $*).aux $(notdir $*).log \
	  && pdftoppm -r 220 -png -singlefile $(notdir $*).pdf $(notdir $*)
rebuttal: rebuttal_round8.docx
rebuttal_round8.docx: rebuttal_round8.js
	node rebuttal_round8.js
word: main.pdf
	python3 make_docx.py && rm -f build_word.tex
clean:
	latexmk -C; rm -f *.bbl *.spl
.PHONY: all figures rebuttal word clean
