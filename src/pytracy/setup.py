from distutils.core import setup, Extension

setup(name='tracy', version='0.1',
    ext_modules=[Extension('tracy', ['tracymodule.c'])])
