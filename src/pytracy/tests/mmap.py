import sys, socket
sys.path.append('build/lib.linux-x86_64-2.7')
import tracy

def w(c, e, a):
    print '%x' % c.mmap(0x1000)
    print '%x' % c.mmap(0x2000, True)

t = tracy.Tracy()
t.hook('write', w)
t.execv('/bin/cat', 'setup.py')
t.loop()
