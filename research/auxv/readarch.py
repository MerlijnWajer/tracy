import ctypes, struct

f = open('/proc/self/auxv', 'r')
a = f.read()
for x in range(len(a)/16):
    dat = struct.unpack('LL', a[x*16:(x+1)*16])
    #print dat
    if dat[0] == 15:
        ptr = dat[1]
        v = ctypes.c_char_p(ptr)
        print v.value
exit(0)


print '*' * 80

f = open('/proc/self/auxv', 'r')
a = f.read()
for x in range(len(a)/8):
    dat = struct.unpack('<LL', a[x*8:(x+1)*8])
    print dat
    if dat[0] == 15:
        ptr = dat[1]
        v = ctypes.c_char_p(ptr)
        print v.value

