import sys
sys.path.append('build/lib.linux-x86_64-2.7')
import unittest, tracy

def a(event):
    args = event.args
    sys.stderr.write('%s %d %d %d\n' % (event, args.a0, args.a1, args.a2))
    return tracy.HOOK_CONTINUE

t = tracy.Tracy()
t.hook('write', a)
c = t.execv('/bin/cat', 'setup.py')
t.loop()
