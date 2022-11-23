from sys import argv
# isto não pode ficar mais bonito?
from common import ip
from common import udp_handler as udp
from src import dns_packet as dns

def main(argv):
    help = '''
dnscl IP[:port] DOMAIN TYPE {R}

R
    Recursive query execution. This is off by default.
    Can be combined with other types.

TYPE can be:

MX
    Specifies an e-mail server for the domain mail indicated.

A
    Specifies an IPv4 address of a host/server indicated by argument as a name.
    This supports priorities.

CNAME
    Specifies an canonic name (or alias) associated to the name given in argument.

PTR
    Specifies a name of a server/host using the IPv4 presented as argument.
'''
    is_ip, has_port = ip.check_ip(argv[1])
    
    # verificar se o IP está correto
    if len(argv) in range(3,4) or not is_ip:
        return print(help)

    # verificar argumentos
    possible_types = set([
        # 'DEFAULT',
        'SOAADMIN',
        'SOASERIAL',
        'SOAREFRESH',
        'SOARETRY',
        'SOAEXPIRE',
        'R',
        'MX',
        'NS',
        'PTR',
        'CNAME'
    ])

    if all([x in possible_types for x in argv[3:]]):
        return print(help)

    ip = ip.IP(argv[1], has_port)

    query = dns.dns_packet(
        flags = (
            True,
            argv[4] == 'R',
            False
        ),
        queryInfo = (
            argv[2],
            argv[3]
        )
    )

    udp_skt = udp.UDP_Handler()
    udp_skt.send(query, ip)
    result = udp_skt.receive().decode('UTF-8')

    # por enquanto
    print(result)

if __name__ == "__main__":
    main(argv)