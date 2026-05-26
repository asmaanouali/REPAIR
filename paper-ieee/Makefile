TEX      := tectonic
SRC      := main.tex
PDF      := main.pdf

.PHONY: all clean watch

all: $(PDF)

$(PDF): $(SRC) refs.bib
	$(TEX) --keep-logs --keep-intermediates $(SRC)

clean:
	rm -f main.pdf main.aux main.log main.bbl main.blg main.out

watch:
	$(TEX) -X watch $(SRC)
