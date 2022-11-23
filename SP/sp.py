import socket
import sys
from pathlib import Path
from time import sleep # if you haven't already done so
file = Path(__file__).resolve()
parent, root = file.parent, file.parents[1]
sys.path.append(str(root))

# Additionally remove the current file's directory from sys.path
try:
    sys.path.remove(str(parent))
except ValueError: # Already removed
    pass
from common import ip 
from common.parser import Parser, ArgsParser
from common.logger import Logger

class SP:
    def __init__(self, argv):
        args ,flags = ArgsParser(argv, 3)
        self.args = self.gen_args(args, flags)
        self.configs = Parser(self.args["config_file"])
        self.logger = Logger(self.configs, self.args["debug"])
        self.logger.log_st("all",self.args)
        self.db_copy = Parser(self.args["db_file"])
        self.st_list = self.parse_st_file(self.args["st_file"])
        self.ip = ip.IP(socket.gethostbyname(socket.gethostname()), self.args["port"])

    def gen_args(self, args, flags):
        d = flags
        d["config_file"] = args[0]
        d["db_file"] = args[1]
        d["st_file"] = args[2]
        return d

    def tcp_waiter(self):
        tcp_sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sck.bind(self.ip.ip_value_tuple())
        tcp_sck.listen()
        while True:
            con, senderIp = tcp_sck.accept()
            domain = con.recv(128).decode()
            #check if domain exists
            con.sendall(self.db.entry_len(domain).to_bytes(2, byteorder='big'))
            resp = con.recv(128).decode()
            if resp == "ok":
                self.db.zone_transfer(con, domain)


    def parse_st_file(self, st_file):
        f = open(st_file,'r')
        possible_ips = f.read().splitlines()
        r = []
        for i in possible_ips:
            is_ip, has_port = ip.check_ip(i)
            if is_ip:
                r.append(ip.IP(i, has_port=has_port))
        return r

    def stop(self, reason):
        self.logger.log_sp("all", reason)
        exit()

    def run(self):
        i = 0
        while True:
            i += 1

if __name__ == "__main__":
    server = SP(sys.argv)
    try:
        server.run()
    except Exception as e:
        server.stop(str(e))
    except KeyboardInterrupt:
        server.stop("Interrupted by user")
    finally:
        exit()
