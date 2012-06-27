import sys
sys.path.append('build/lib.linux-x86_64-2.7')
import tracy

t = tracy.Tracy()
t.hook('read',
    lambda c, e, a: None if c.post else sys.stderr.write(c.read(a.a1, a.a2)))

t.execv('/bin/cat', 'setup.py')
t.loop()
