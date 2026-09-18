# GridSec Sim - Overleaf project

Project GitHub: https://github.com/neerajjayesh/GridSec-project

## Open in Overleaf

1. Choose **New Project > Upload Project** and upload `GridSec_Sim_Overleaf.zip`.
2. Set **Main document** to `main.tex` and **Compiler** to **pdfLaTeX**.
3. Click **Recompile**. All required source files, figures, and listings are included.

No shell escape, Python runtime, external fonts, bibliography service, or online asset fetch is needed to compile this project.

Official upload instructions: https://www.overleaf.com/learn/latex/Kb/Uploading_a_project

## Edit the manual

- `main.tex`: cover, contents, and chapter order.
- `gridsec.sty`: colors, type, page geometry, tables, listings, and navigation.
- `chapters/`: editable chapter text and tables.
- `figures/`: vector PDF diagrams and their Mermaid source descriptions.
- `examples/`: complete topology and Python examples printed in the manual.
- `reference/`: machine-readable OpenAPI and topology-schema files.

The downloadable PDF contains companion-file attachments added during packaging. Overleaf compilation creates the same visible manual; the companion files remain available in the project file tree.

To compile locally with TeX Live or MiKTeX, run `pdflatex main.tex` twice, or `latexmk -pdf main.tex`.
