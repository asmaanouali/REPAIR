# IR-SAM IEEE Conference Paper

This folder contains the IEEE-style conference paper draft for IR-SAM.

## Build

The recommended toolchain is [tectonic](https://tectonic-typesetting.github.io/),
which is a single self-contained binary that resolves missing packages on demand.

```powershell
# Windows (chocolatey)
choco install tectonic
# or via cargo
cargo install tectonic

# Build
cd paper-ieee
make
```

The output is `main.pdf`.

## Numeric placeholders

The empirical tables and figures contain `XX.X` placeholders that are filled in
by re-running `testing-code/scripts/run-irsam-scan.ps1` and aggregating to
`testing-code/results/summary.csv`. The Python helper
`testing-code/scripts/inject-results-into-paper.py` (TODO) reads that CSV and
substitutes the placeholders into a copy of `main.tex`.
