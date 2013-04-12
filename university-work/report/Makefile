
.PHONY: default clean report

default: report

report: dot
	texi2pdf report.tex

clean:
	rm *.pdf -f

dot: ptrace1 ptrace2 pre post

ptrace1: ptrace.dot
	dot -Tpng ptrace.dot > ptrace.png

pre: pre.dot
	dot -Tpng pre.dot > pre.png

post: post.dot
	dot -Tpng post.dot > post.png

ptrace2: ptrace2.dot
	dot -Tpng ptrace2.dot > ptrace2.png

