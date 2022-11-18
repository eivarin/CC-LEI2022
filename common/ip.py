import ctypes as C
from re import fullmatch

# data IPv4 = IPPort { a :: Word8, b :: Word8, c :: Word8, d :: Word8, e :: Word16 } | IP { a :: Word8, b :: Word8, c :: Word8, d :: Word8 }

class IP:
    def __init__(self, ip: str, port = True):
        self.port = port
        if port:
            ip, port = ip.split(':')

        ip = [int(i) for i in ip.split('.')]
        ip_tmp = (
            C.c_uint8(ip[0]),
            C.c_uint8(ip[1]),
            C.c_uint8(ip[2]),
            C.c_uint8(ip[3])
        )
        a, b, c, d = ip_tmp
        self.ip = ip_tmp if port == True else a, b, c, d, C.c_uint16(int(port))
    
    def __str__(self):
        a,b,c,d,e = self.ip
        if self.port:
            return f'{a.value}.{b.value}.{c.value}.{d.value}:{e.value}'
        return f'{a.value}.{b.value}.{c.value}.{d.value}'

    def __repr__(self):
        return self.__str__()

    def ip_and_port(self):
        if self.port:
            a, b, c, d, port = self.ip
            return f'{a.value}.{b.value}.{c.value}.{d.value}', port
        return None

    def check_ip(self, ip):
        ip_match = fullmatch('^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d).?\b){4}(\d|[1-9]\d{1,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])?$', ip)

        return True, ':' in ip if ip_match != None else False, False