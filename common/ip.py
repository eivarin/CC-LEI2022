import ctypes as C
from re import fullmatch
from random import randrange

# data IPv4 = IPPort { a :: Word8, b :: Word8, c :: Word8, d :: Word8, e :: Word16 } | 
#             IP { a :: Word8, b :: Word8, c :: Word8, d :: Word8 }

class IP:
    def __init__(self, ip: str, port = 53, has_port = False):

        if has_port and port != None:
            ip, port = ip.split(':')
            port = int(port)
        if ip[-1] == ".":
            ip = ip[:-1]
        ip = [int(i) for i in ip.split('.')]
        self.ip = (
            C.c_uint8(ip[0]),
            C.c_uint8(ip[1]),
            C.c_uint8(ip[2]),
            C.c_uint8(ip[3]),
            C.c_uint16(port)
        )

    def __str__(self):
        a,b,c,d,e = self.ip
        return f'{a.value}.{b.value}.{c.value}.{d.value}:{e.value}'

    def __repr__(self):
        return self.__str__()

    def ip_tuple(self):
        ip, port = str(self).split(':')
        return ip, int(port)

def check_ip(ip):
    ip_match = fullmatch(r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d).?\b){4}(\d|[1-9]\d{1,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])?$', ip)
    return (True, ':' in ip) if ip_match != None else (False, False)
