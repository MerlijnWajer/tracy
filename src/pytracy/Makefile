
default:
	$(MAKE) -C ../tracy
	python setup.py build

run: default
	python -ic 'import sys ; sys.path.append("build/lib.linux-x86_64-2.7") ; import tracy'

clean:
	rm -rf build/
