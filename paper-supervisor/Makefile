TEX      := tectonic
SRC      := main.tex
PDF      := main.pdf

.PHONY: all clean

all: $(PDF)

$(PDF): $(SRC)
	$(TEX) --keep-logs --keep-intermediates $(SRC)

clean:
	rm -f main.pdf main.aux main.log main.toc main.out
