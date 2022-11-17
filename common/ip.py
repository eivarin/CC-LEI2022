import ctypes as C

class IP:
    def __init__(self, ip: str, port = true):
        if port:
            self.port = port
            ip, port = ip.split(':')
            ip = ip.split('.')
            self.ip = (
                C.c_uint8(ip[0]),
                C.c_uint8(ip[1]),
                C.c_uint8(ip[2]),
                C.c_uint8(ip[3]),
                C.c_uint16(port)
            )
        else:
            ip = ip.split('.')
            self.ip = (
                C.c_uint8(ip[0]),
                C.c_uint8(ip[1]),
                C.c_uint8(ip[2]),
                C.c_uint8(ip[3])
            )

    
    def __str__(self):
        if self.port:
            a,b,c,d,e = self.ip
            return f'{a}.{b}.{c}.{d}:{e}'
        else:
            a,b,c,d = self.ip
            return f'{a}.{b}.{c}.{d}'

    def __repr__(self):
        return self.__str__()

    def ip_and_port():
        return , port if self.port else None       
