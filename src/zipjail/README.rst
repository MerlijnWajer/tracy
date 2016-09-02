ZipJail
=======

ZipJail is a usermode sandbox for unpacking archives using the ``unzip``,
``rar``, and ``7z`` utilities. Through the use of the ``tracy`` library it
limits the attack surfaces to an absolute minimum in case a malicious archive
tries to exploit known or unknown vulnerabilities in said archive tools.

Usage
=====

The ``zipjail`` command itself requires two parameters followed by the command
that should be executed and jailed (i.e., sandboxed). The two parameters
belonging to ``zipjail`` define the filepath to the archive and the output
directory to which file writes should be restricted.

.. code-block:: bash

    $ zipjail
    zipjail 0.1 - safe unpacking of potentially unsafe archives.
    Copyright (C) 2016, Jurriaan Bremer.
    Based on Tracy by Merlijn Wajer and Bas Weelinck.
        (https://github.com/MerlijnWajer/tracy)

    Usage: zipjail <input> <output> [-v] <command...>
      input:  input archive file
      output: directory to extract files to
      verbose: some verbosity

    Please refer to the README for the exact usage.

Following we will demonstrate ``zipjail``'s usage based on an input file
called ``archive.zip`` and the output directory ``/tmp/unpacked/``.

Unzip
^^^^^

In order to run ``zipjail`` with ``unzip`` the command-line should be
constructed as follows.

.. code-block:: bash

    $ zipjail file.zip /tmp/unpacked unzip -o -d /tmp/unpacked file.zip

Rar
^^^

Just like for the ``7z`` command we require setting the multithreaded count
for the ``rar`` command. It should be noted that ``unrar`` version
``5.00 beta 8`` does not support the multithreaded option and thus ``zipjail``
is not capable of running with that version. So far we have only tested that
``zipjail`` works with ``rar`` version ``4.20``. Its usage is as follows.

.. code-block:: bash

    $ zipjail file.zip /tmp/unpacked rar x -mt1 file.zip /tmp/unpacked

7z
^^

Running ``zipjail`` with ``7z`` may be done as follows. Note that we pass
along the ``-mmt=off`` option which disables multithreaded decompression for
``bzip2`` targets. By keeping ``zipjail``'s sandboxing single-threaded we keep
its logic easy and secure (using multithreading race conditions would be
fairly trivial). In fact, as per our unittests, trying to instantiate
multithreading (e.g., through ``pthread``, which internally invokes the
``clone(2)`` system call) is blocked completely.

.. code-block:: bash

    $ zipjail file.zip /tmp/unpacked 7z x -mmt=off -o /tmp/unpacked file.zip

Security
========

Given its security implications (and use in, e.g., `Cuckoo Sandbox`_) it is of
utmost importance that ``zipjail`` is completely secure. Therefore, may you
locate a potential security issue, please reach out to us at
``jbr@cuckoo.sh``.

.. _`Cuckoo Sandbox`: https://github.com/cuckoosandbox/cuckoo
