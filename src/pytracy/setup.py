from distutils.core import setup, Extension

setup(name='tracy', version='0.1',
    ext_modules=[Extension('tracy', ['tracymodule.c'],
    include_dirs=['../tracy'],
    extra_objects=['../tracy/tracy.o', '../tracy/ll.o', '../tracy/trampy.o'],
    extra_compile_args=['-std=c99'])])
