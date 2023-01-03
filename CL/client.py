import socket
from sys import argv, path
from pathlib import Path
from time import sleep # if you haven't already done so

file = Path(__file__).resolve()
parent, root = file.parent, file.parents[1]
path.append(str(root))

# Additionally remove the current file's directory from sys.path
try:
    path.remove(str(parent))
except ValueError: # Already removed
    pass

# isto ficou mais bonito
from common import udp_handler as udp, ip, dns_packet as dns, logger

def main(argv):
    help = '''
dnscl IP[:port] DOMAIN [MX | A | NS | PTR] ?[R]

R
    Recursive query execution. This is off by default.
    Can be combined with other types.

MX
    Specifies an e-mail server for the domain mail indicated.

A
    Specifies an IPv4 address of a host/server indicated by argument as a name.
    This supports priorities.

CNAME
    Specifies a canonic name (or alias) associated to the name given in argument.

PTR
    Specifies a name of a server/host using the IPv4 presented as argument.
'''
    # verificar IP
    is_ip, has_port = ip.check_ip(argv[1])
    destiny_ip = argv[1]
    
    # verificar reverse
    is_ptr, _ = ip.check_ip(argv[2])

    # verificar o resto dos argumentos juntamente do IP
    if len(argv) not in range(5,6) or not is_ip:
        print(len(argv))
        return print(help)
    

    # verificar argumentos
    possible_types = set([
        'NS',
        'CNAME',
        'A',
        'R',
        'MX'
    ])
    if any([x not in possible_types for x in argv[3:]]):
        return print(help)

    query = dns.dns_packet(
        flags = (
            True,
            len(argv) == 5,
            False
        ),
        queryInfo = (
            argv[2],
            argv[3]
        )
    )
    log_maker = logger.Logger(None, True)

    if is_ip and not has_port:
        destiny_ip += ":53"
        
    ptr = argv[2]
    if is_ptr:
        ptr = ptr.split('.')
        ptr = f'{ptr[3]}.{ptr[2]}.{ptr[1]}.{ptr[0]}'
        
    udp_skt = udp.UDP_Handler()
    udp_skt.send(query.encodePacket(), ip.IP(destiny_ip, has_port= True))
    result, _ = udp_skt.receive()

    this_ip = ip.IP(argv[1], has_port)
    this_ip, port = this_ip.ip_tuple()
    result = dns.dns_packet(encoded_bytes = result)

    log_maker.log_rr(argv[2], this_ip, result, port)


if __name__ == "__main__":
    main(argv)