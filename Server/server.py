import socket
import sys
from pathlib import Path
import threading
from time import sleep
import time # if you haven't already done so
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
            self.st_list = self.parse_st_file(self.configs.result["ST"][0][1])
        self.DD = {}
        if "DD" in self.configs.result:
            for d,i in self.configs.result["DD"]:
                self.DD[d] = ip.IP(i)
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
        return times[max] - times[min], min == 'refresh' # log de qual foi o resultado do wait qual o  valor que foi alterado 
    
    def zone_transfer_ss_checker(self, domain, lock):
        sp_ip = None
        if domain in self.ss_domains:
            sp_ip = self.ss_domains[domain]
        
        refresh, expire, retry, serial = self.aux(domain)
        while True:
            other_time, needs_refresh =  self.wait_time(refresh,expire)
            if needs_refresh:
                self.logger.log_ev(domain, f"refreshing-zone-serial") # log 
                has_response=False
                expire = other_time
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
                    self.logger.log_ev(domain, f"zone-refreshing-failed - retrying") 
                    refresh = retry
                finally:
                    h.close()
                    lock.release()
                if has_response and int(packet.val_response[0].split()[2]) > serial:
                    print(f"{int(packet.val_response[0].split()[2])} > {serial}") # log da resposta
                    self.zone_transfer_ss_com(sp_ip, domain)
                    print(f"{domain} {self.aux(domain)}")
                    refresh, expire, retry, serial = self.aux(domain)
            else:
                self.logger.log_ev(domain, f"zone-serial-expired") 
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
        ans = tcp_sck.recv(128)
        if ans.decode() == "Refused":
            start = time.time()
            entries = int.from_bytes(ans, byteorder='big')
            #send ok message
            tcp_sck.sendall("ok".encode())
            #receive zone transfer
            total = self.db.zone_transfer(tcp_sck, domain, True)
            end = time.time()
            self.logger.log_zt(domain, sp_ip, ("SS", start-end, total))

    # log
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
            ss_ip = ip.IP(senderIp[0], senderIp[1])
            # if domain in self.db.zones and self.db.zones[domain][0] and ss_ip in self.configs.result["SS"]:
            start = time.time()
            con.sendall(len(self.db.zone_to_domains[domain]).to_bytes(2, byteorder='big'))
            resp = con.recv(128).decode()
            if resp == "ok":
                total = self.db.zone_transfer(con, domain, False)
                end = time.time()
                self.logger.log_zt(domain, ss_ip, ("SP", start-end, total))
            # else:
                # con.sendall("Refused".encode())
                # self.logger.log_ev(domain, f"zone-transfer-refused - {ss_ip} tried to zone transfer but isnt allowed")

    def udp_waiter(self):
        h = UDP_Handler(self.ip)
        self.thrds.append(h)
        while True:
            bytes, sender = h.receive()
            packet = dns_packet(encoded_bytes = bytes)
            d = packet.q_info
            if packet.q_info in self.db.domain_to_zones:
                z = self.db.domain_to_zones[packet.q_info]
                self.logger.log_qr(z, sender, packet)
            else: 
                self.logger.log_qr("all", sender, packet)
            if d in self.DD and (d in self.db.domain_to_zones and self.db.domain_to_zones[d] not in ["", "cache"]) and self.DD[d].ip_tuple() != ip.IP(sender[0], sender[1]).ip_tuple():
                p = dns_packet(flags = (False,False,False), responseCode = 4, queryInfo=(packet.q_info,packet.q_type))
                h.send(p.encodePacket(), ip.IP(sender[0], sender[1]))
                if packet.q_info in self.db.domain_to_zones:
                    z = self.db.domain_to_zones[packet.q_info]
                    self.logger.log_rp(z, sender, p)
                else: 
                    self.logger.log_rp("all", sender, p)
                continue
            
            response = self.db.query(packet)
            print(response)

            needs_recursivity = response.responseCode == 2 or (response.responseCode == 1 and self.db.is_domain_cache(packet.q_info))
            if packet.flags[1] and needs_recursivity:
                response = self.check_sr_dd(packet,response,h)
            needs_recursivity = response.responseCode == 2 or (response.responseCode == 1 and self.db.is_domain_cache(packet.q_info))
            if packet.flags[1] and needs_recursivity:
                response = self.recursive_query(packet,response,h)

            if packet.q_info in self.db.domain_to_zones:
                z = self.db.domain_to_zones[packet.q_info]
                self.logger.log_rp(z, sender, response)
            else: 
                self.logger.log_rp("all", sender, response)
            
            h.send(response.encodePacket(), ip.IP(sender[0], sender[1]))

    def check_sr_dd(self, packet: dns_packet, own_response: dns_packet, handler: UDP_Handler):
        if own_response.q_info in self.DD:
            handler.send(packet.encodePacket(), self.DD[own_response.q_info])
            result, _ = handler.receive()
            own_response = dns_packet(encoded_bytes = result)
        return own_response

    def recursive_query(self, packet: dns_packet, own_response: dns_packet, handler: UDP_Handler) -> dns_packet:
        visited_ips = set()
        visited_ips.add(self.ip)
        # while own_response.responseCode == 2 or (own_response.responseCode == 1 and own_response.flags[1]):
        while own_response.responseCode in [1, 2]:
            ns_list = own_response.val_zone.copy()
            ns_list = list(map(lambda x: DB_entry(from_str=x, is_Eternal=False), ns_list))
            ns_list.sort(key=lambda x: x.priority)
            handler.socket.settimeout(2.0)
            for next_domain_to_be_queryd in ns_list:
                possible_IPs = list(map(lambda x: ip.IP(x.value), self.db.get_extra(str(next_domain_to_be_queryd))))
                chosen_IP = possible_IPs[0]
                if chosen_IP in visited_ips:
                    break
                visited_ips.add(chosen_IP)
                handler.send(packet.encodePacket(), chosen_IP)
                try:
                    result, _ = handler.receive() # log
                except:
                    continue
                break
            handler.socket.settimeout(None)
            own_response = dns_packet(encoded_bytes = result)
            self.cache_query(own_response)
        own_response.flags = (own_response.flags[0], own_response.flags[1], False)
        return own_response

    #log aqui
    def cache_query(self, response: dns_packet):
        for r in response.val_response + response.val_zone + response.val_extra:
            self.db.add_cache_entry(DB_entry(from_str=r, is_Eternal=False)) # query a cache

    def parse_st_file(self, st_file):
        f = open(st_file,'r')
        possible_ips = f.read().splitlines()
        r = []
        for i in possible_ips:
            if i[0] == "#":
                r.append(i) # log
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
