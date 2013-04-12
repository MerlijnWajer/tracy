Introduction to Tracy
=====================

Tracy is a library written in C that makes it easy to trace, modify and inject
system calls on Linux. Currently the only supported platform is Linux,
but we are working on supporting other platforms.

While Tracy has been in development for quite a while, there's still some issues
to be ironed out before we will make an 'official' release.

Motivation
----------

Cross platform system call tracing is not a fun task; especially since ptrace
differs quite a bit per platform and operating system. We aimed to create a
mostly cross platform tracing library with additional features such as system
call modification and injection. A more detailed motivation (amongst other
things) can be found in the report we wrote on Tracy.

Limitations
-----------

Tracy is still under heavy development and we may break the API a few more
times. Regardless, current main 'limitations' are:

- Tracy in general needs more testing; any kind of application using Tracy
  helps, as well as writing actual tests.
- Platform support is currently limited to Linux.

Source code
-----------

Source code can currently be found on github:

    git clone git://github.com/MerlijnWajer/tracy.git

Contributing
------------

You can find us at:

- Our mailing list tracy@ the free mailing list website: freelists.org
- Our IRC channel: #tracy on freenode.net
- Our Bug tracker (currently github; will be migrated later)
