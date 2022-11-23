from sys import argv
import common.ip as ip
import common.udp_handler as udp
import src.dns_packet as dns

def main(argv):
    help = '''
dnscl IP[:port] DOMAIN [ARGS]

ARGS can be:
R
    Recursive query execution. This is off by default.

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
    if len(argv) <= 5 or not is_ip:
        return print(help)

    # verificar argumentos
    possible_args = set(['R', 'MX', 'NS', 'A', 'PTR', 'CNAME'])
    if all([x in possible_args for x in argv[3:]]):
        return print(help)

    ip = ip.IP(argv[1], has_port)
    
    query = dns.dns_packet()        # depois meter os argumentos corretos

    skt = udp.UDP_Handler()         # qual IP? 😅
    skt.send(query, ip)             # a redefinir com métodos quando houver dns_queries
    result = skt.receive().decode('UTF-8')

    # por enquanto
    print(result)

if __name__ == "__main__":
    main(argv)