from distutils.core import setup, Extension

setup(name='tracy', version='0.1',
    ext_modules=[Extension('tracy', ['tracymodule.c'],
    include_dirs=['../tracy'],
    library_dirs=['../tracy'],
    libraries=['tracy'],
    extra_compile_args=['-std=c99'])])
