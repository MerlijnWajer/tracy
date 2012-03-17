
.PHONY: default clean report

default: report

report: dot
	texi2pdf report.tex -s

clean:
	rm *.pdf -f

dot: ptrace1 ptrace2

ptrace1: ptrace.dot
	dot -Tpng ptrace.dot > ptrace.png

ptrace2: ptrace2.dot
	dot -Tpng ptrace.dot > ptrace.png

