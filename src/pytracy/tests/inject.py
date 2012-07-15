import sys
sys.path.append('build/lib.linux-x86_64-2.7')
import tracy

def read(c, e, a):
    print a, c.inject(39, tracy.SyscallArguments())
    c.deny()

t = tracy.Tracy()
t.hook('read', read)

t.execv('/bin/cat', 'setup.py')
t.loop()
