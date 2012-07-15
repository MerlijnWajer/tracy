import sys
sys.path.append('build/lib.linux-x86_64-2.7')
import tracy

t = tracy.Tracy()
t.execv('/bin/cat', 'setup.py')
t.loop()
