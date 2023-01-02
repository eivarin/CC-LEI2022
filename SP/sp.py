import socket
import sys
from pathlib import Path
import threading
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
from common.udp_handler import UDP_Handler
from common.dns_packet import dns_packet
from common.database import DB, DB_entry

class SP:
    def __init__(self, argv):
        args ,flags = ArgsParser(argv, 3)
        self.args = self.gen_args(args, flags)
        self.configs = Parser(self.args["config_file"])
        self.logger = Logger(self.configs, self.args["debug"])
        self.logger.log_st("all",self.args)
        if "ST" in self.configs.result:
            self.st_list = self.configs.result["ST"]
        self.db = DB(self.configs, self.logger, self.st_list)
        self.ip: ip.IP = self.args["ip"]
        self.thrds = []

    def gen_args(self, args, flags):
        d = flags
        d["config_file"] = args[0]
        return d

    def wait_time(self, refresh: int, expire: int):
        min_time = lambda d: ('refresh', 'expire') if d['refresh'] > d['expire'] else ('expire', 'refresh')
        times = { 'refresh': refresh, 'expire': expire }
        max, min = min_time(times)
        sleep(times[min])
        return times[max] - times[min], min == 'refresh'
    
    def zone_transfer_ss_checker(self, domain, lock):
        sp_ip = None
        if domain in self.ss_domains:
            sp_ip = self.ss_domains[domain]
        
        refresh, expire, retry, serial = self.aux(domain)
        while True:
            other_time, needs_refresh =  self.wait_time(refresh,expire)
            if needs_refresh:
                print("refreshing")
                has_response=False
                expire = other_time
                print(f"d:{domain} r:{refresh} e:{expire}")
                packet = dns_packet(queryInfo= (domain,"SOASERIAL"), flags=(True,False,False))
                ip_zt,_ = self.ip.ip_tuple()
                lock.acquire()
                h = UDP_Handler(ip.IP(ip_zt, 1234))
                self.thrds.append(h)
                h.socket.settimeout(5)
                h.send(packet.encodePacket(), sp_ip)
                try:
                    bytes, sender = h.receive()
                    packet = dns_packet(encoded_bytes = bytes)
                    self.logger.log_rr(domain, sender, packet, 1234)
                    has_response = True
                    refresh, _, _, _ = self.aux(domain)
                except socket.timeout:
                    refresh = retry
                finally:
                    h.close()
                    lock.release()
                if has_response and int(packet.val_response[0].split()[2]) > serial:
                    print(f"{int(packet.val_response[0].split()[2])} > {serial}")
                    self.zone_transfer_ss_com(sp_ip, domain)
                    print(f"{domain} {self.aux(domain)}")
                    refresh, expire, retry, serial = self.aux(domain)
            else:
                self.zone_transfer_ss_com(sp_ip, domain)
                refresh, expire, retry, serial = self.aux(domain)

    def aux(self,domain):
        d = self.db.get_domain_SOA(domain)
        result = []
        for k in d:
            result.append(int(k[0].value))
        return result

    def zone_transfer_ss_com(self, sp_ip: ip.IP, domain):
        tcp_sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.thrds.append(tcp_sck)
        tcp_sck.bind(self.ip.ip_tuple())
        tcp_sck.connect(sp_ip.ip_tuple())
        #send domain
        tcp_sck.sendall(domain.encode())
        #receive number of entries
        entries  = int.from_bytes(tcp_sck.recv(128), byteorder='big')
        print(entries)
        #send ok message
        tcp_sck.sendall("ok".encode())
        #receive zone transfer
        self.db.zone_transfer(tcp_sck, domain, True)


    def zone_transfer_sp(self):
        tcp_sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sck.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_sck.bind(self.ip.ip_tuple())
        tcp_sck.listen()
        self.thrds.append(tcp_sck)
        while True:
            con, senderIp = tcp_sck.accept()
            self.thrds.append(con)
            domain = con.recv(128).decode()
            print(domain)
            if domain in self.db.zones and self.db.zones[domain][0] and ip.IP(senderIp[0], senderIp[1]) in self.configs["SS"]:
                con.sendall(len(self.db.zone_to_domains[domain]).to_bytes(2, byteorder='big'))
                resp = con.recv(128).decode()
                print(resp)
                if resp == "ok":
                    print("transfering")
                    self.db.zone_transfer(con, domain, False)

    def udp_waiter(self):
        h = UDP_Handler(self.ip)
        self.thrds.append(h)
        while True:
            bytes, sender = h.receive()
            packet = dns_packet(encoded_bytes = bytes)
            if packet.q_info in self.db.domain_to_zones:
                z = self.db.domain_to_zones[packet.q_info]
                self.logger.log_qr(z, sender, packet)
            self.logger.log_qr("all", sender, packet)
            
            response = self.db.query(packet)
            
            needs_recursivity = response.responseCode == 2 or (response.responseCode == 1 and self.db.is_domain_cache(packet.q_info))
            if packet.flags[1] and needs_recursivity:
                response = self.recursive_query(packet,response,h)


            if packet.q_info in self.db.domain_to_zones:
                z = self.db.domain_to_zones[packet.q_info]
                self.logger.log_rp(z, sender, packet)
            self.logger.log_rp("all", sender, packet)
            
            h.send(response.encodePacket(), ip.IP(sender[0], sender[1]))

    def recursive_query(self, own_response: dns_packet, handler: UDP_Handler) -> dns_packet:
        i = own_response.q_info
        t = own_response.q_type
        query = dns_packet(flags = (True, False, False), queryInfo = (i,t))
        visited_ns = set()
        visited_ns.add(self.ip)
        while own_response.responseCode == 2 or (own_response.responseCode == 1 and own_response.flags[1]):
            ns_list = own_response.val_zone.copy()
            ns_list = list(map(lambda x: DB_entry(from_str=x), ns_list))
            ns_list.sort(key=lambda x: x.priority)
            a_list = own_response.val_extra.copy()
            a_list = list(map(lambda x: DB_entry(from_str=x), ns_list))
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
        for s in self.thrds:
            s.close()
        exit()

    def run(self):
        i = 0
        self.ss_domains = {}
        self.sp_domains = {}
        for domain, (is_sp, server_ip) in [(domain, self.db.zones[domain]) for domain in self.db.zones]:
            if is_sp:
                self.sp_domains[domain] = server_ip
            else:
                self.ss_domains[domain] = server_ip

        self.zone_transfer_threads = []

        print(self.ss_domains)
        zone_transfer_lock = threading.Lock()
        for domain in self.ss_domains:
            print(f"\n{domain}\n")
            self.zone_transfer_ss_com(self.ss_domains[domain], domain)
            t = threading.Thread(target = self.zone_transfer_ss_checker, args=(domain,zone_transfer_lock))
            t.start()
            self.zone_transfer_threads.append(t)

        if len(self.sp_domains) > 0:
            self.tcp_t = threading.Thread(target = self.zone_transfer_sp)
            self.tcp_t.start()
        self.udp_waiter()
        print("adeus")


if __name__ == "__main__":
    server = SP(sys.argv)
    #try:
    server.run()
    #except Exception as e:
    #    server.stop(str(e))
    #except KeyboardInterrupt:
    #    server.stop("Interrupted by user")
    #finally:
    #    exit()
