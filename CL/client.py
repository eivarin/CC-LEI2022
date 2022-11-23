import sys
import Common.ip as ip

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
    Specifies a name of a server/host using the IPv4 used presented as argument.
'''
    is_ip, has_port = ip.check_ip(argv[1])
    if len(argv) >= 5 and is_ip:
        ip = ip.IP(argv[1], has_port)
        
        # verificar se isto precisam de ser funções
        possible_args = set(['R', 'MX', 'NS', 'A', 'PTR', 'CNAME'])

        for arg in argv[3:]:
            if not arg not in possible_args:
                break

        # query parsing to send goes here

    print(help)

    # vtable de args

if __name__ == "__main__":
    main(sys.argv)