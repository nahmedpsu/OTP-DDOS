# Build the manuscript. Needs a TeX Live with latexmk; elsarticle.cls and the
# elsarticle-harv style are vendored here from the Elsevier distribution.
all: main.pdf
main.pdf: main.tex refs.bib figures/*.pdf
	latexmk -pdf -interaction=nonstopmode main.tex
figures: ../results/evaluation.json figures/fig8_defense_path.pdf
	python3 figures.py
figures/fig8_defense_path.pdf: figures/fig8_defense_path.tex
	cd figures && pdflatex -interaction=nonstopmode fig8_defense_path.tex && rm -f fig8_defense_path.aux fig8_defense_path.log \
	  && pdftoppm -r 220 -png -singlefile fig8_defense_path.pdf fig8_defense_path
rebuttal: rebuttal_round8.docx
rebuttal_round8.docx: rebuttal_round8.js
	node rebuttal_round8.js
word: main.pdf
	python3 make_docx.py && rm -f build_word.tex
clean:
	latexmk -C; rm -f *.bbl *.spl
.PHONY: all figures rebuttal word clean
