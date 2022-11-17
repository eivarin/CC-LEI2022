import sys

def main(argv):
    help = '''
dnscl IP[:port] DOMAIN [ARGS]

ARGS can be:
R   Recursive query execution. This is off by default

MX  
'''
    possible_args = {
        'R': execute_recursive(),
        'MX': ...,

    }

    if len(argv) < 5:
        print(help)

def execute_recursive():
    ...

def 

if __name__ == "__main__":
    main(sys.argv)