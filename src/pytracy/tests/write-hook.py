import sys
sys.path.append('build/lib.linux-x86_64-2.7')
import unittest, tracy

def a(c, e, a):
    sys.stderr.write('%s\n' % ('pre' if c.pre else 'post'))
    if c.post:
        sys.stderr.write('%s %d %d %d\n' % (e, a.a0, a.a1, a.a2))
        sys.stderr.write('buf: "%s"\n' % c.read(a.a1, a.a2))
    return tracy.HOOK_CONTINUE

t = tracy.Tracy()
t.hook('write', a)
c = t.execv('/bin/cat', 'setup.py')
t.loop()
