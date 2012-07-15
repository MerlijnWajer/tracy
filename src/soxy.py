import sys, socket, struct
sys.path.append('pytracy/build/lib.linux-x86_64-2.7')
import tracy

SC = tracy.SyscallArguments

def parse_sockaddr(addr):
    if struct.unpack('H', addr[:2])[0] == socket.AF_INET:
        ip, port = addr[4:8], struct.unpack('H', addr[2:4])[0]
        return socket.inet_ntoa(ip), socket.htons(port)

def create_sockaddr((ip, port)):
    return struct.pack('HH', socket.AF_INET, socket.htons(port)) + \
        socket.inet_aton(ip) + '\x00' * 8

def proxy_addr():
    """Returns the address of the Proxy Server."""
    return '127.0.0.1', 2222

def hook_socket(c, e, a):
    if c.post and a.a0 == socket.AF_INET and a.a1 == socket.SOCK_STREAM:
        sockets[c, a.retcode] = c.mmap(0x1000)

def hook_connect(c, e, a):
    fd = a.a0
    if c.pre and (c, fd) in sockets:
        ip, port = parse_sockaddr(c.read(a.a1, a.a2))

        addr = create_sockaddr(proxy_addr())
        mem = sockets[c, fd]

        # connect to our proxy server
        c.write(mem, addr)
        if c.inject(42, SC(fd, mem, len(addr))) < 0:
            print 'invalid connect'
            return False

        # request auth method (only no-auth is supported)
        c.write(mem, '\x05\x01\x00')
        if c.inject(1, SC(fd, mem, 3)) != 3:
            print 'invalid auth method send'
            return False

        # get auth response
        if c.inject(0, SC(fd, mem, 2)) != 2:
            print 'invalid auth method recv'
            return False

        # check the auth response
        if c.read(mem, 2) != '\x05\x00':
            print 'invalid auth response'
            return False

        # send the requested ipv4 address
        c.write(mem, '\x05\x01\x00\x01' + struct.pack('IH', ip, port))
        if c.inject(1, mem, 10) != 10:
            print 'invlaid requested ip send'
            return False

        # read the response
        if c.inject(0, SC(fd, mem, 10)) != 10:
            print 'invalid response recv'
            return False

        # check the reply header (success with ipv4 address)
        reply = c.read(mem, 10)
        if reply[:4] != '\x05\x00\x00\x01':
            print 'invalid reply header'
            return False

        # store the ip:port of the proxy
        # ...

    else:
        a.retcode = 0

def hook_close(c, e, a):
    if c.pre and (c, a.a0) in sockets:
        c.munmap(sockets[c, a.a0], 0x1000)
        del sockets[c, a.a0]

if __name__ == '__main__':
    t = tracy.Tracy(tracy.TRACE_CHILDREN)

    t.hook('socket', hook_socket)
    t.hook('connect', hook_connect)
    t.hook('close', hook_close)

    c = t.execv(*sys.argv[1:])

    # initialize stuff
    sockets = {}

    t.loop()
