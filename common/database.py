import socket
from common.dns_packet import dns_packet
from common import parser
from common import ip
from time import time

from common.logger import Logger

class DB_entry:
    def __init__(self, type = "", value_list = [], defaults = {}, is_Eternal = True, from_str = ""):
        if from_str == "":
            value_list = [self.replace_defaults(v,defaults) for v in value_list] if type != "DEFAULT" else value_list
            self.parameter = value_list[0]
            self.type = type
            self.value = value_list[1]
            self.default_TTL = int(value_list[2]) if len(value_list) > 2 else 0
            self.priority = int(value_list[3]) if len(value_list) > 3 else 255
        else:
            l = from_str.split()
            self.parameter = l[0]
            self.type = l[1]
            self.value = l[2]
            self.default_TTL = int(l[3]) if len(l) > 3 else 0
            self.priority = int(l[4]) if len(l) > 4 else 255
        self.is_Eternal = is_Eternal
        self.expiring_TTL = -1 if (self.is_Eternal or self.default_TTL == 0) else int(time()) + self.default_TTL

    def replace_defaults(self, s, defaults):
        for d in defaults:
            if d in s:
                s = s.replace(d,defaults[d])
        s = s if s[-1] == "." or all(char.isdigit() for char in s) else f"{s}.{defaults['@']}"
        while ".." in s:
            s = s.replace("..",".")
        return s

    def __hash__(self):
        return hash(str(self))

    def __eq__(self,other):
        return str(self) == str(other)

    def __str__(self):
        unparsed_str = f"{self.entry} {self.type} {self.value} {self.default_TTL} {self.priority}"
        return unparsed_str

    def is_Alive(self):
        return self.is_Eternal and self.expiring_TTL - int(time()) < 0

class DB:

    def __init__(self, configs, logger: Logger, st_list):
        '''
        self.__args = set([
            # 'DEFAULT',
            'MX',
            'A',
            'CNAME',
            'NS',
            'SOASP',
            'SOAADMIN',
            'SOAREFRESH',
            'SOARETRY',
            'SOAEXPIRE',
            'PTR'
        ])
        '''
        self.logger: Logger = logger
        self.__db = {}
        self.zones = {}

        #add domains which this database is ss to.
        if "SP" in configs.result:
            for domain, server_ip in configs.result["SP"]:

                is_ip, has_port = ip.check_ip(server_ip)
                if is_ip:
                    if not has_port:
                        server_ip+= ":53"
                    server_ip = ip.IP(server_ip, has_port=True)

                if domain not in self.zones:
                    self.zones[domain] = (False, server_ip)

        #add domains which this database is sp to.
        a = []
        if "SS" in configs.result:
            a += configs.result["SS"]
        if "DB" in configs.result:
            a += configs.result["DB"]
        if len(a) > 0:
            for domain, server_ip in configs.result["SS"] + configs.result["DB"]:
                is_ip, has_port = ip.check_ip(server_ip)
                if is_ip:
                    if not has_port:
                        server_ip+= ":53"
                    server_ip = ip.IP(server_ip, has_port=True)
                if domain not in self.zones:
                    self.zones[domain] = (True, server_ip)
        

        # parse file databases and populate __db and zone_to_domains
        self.zone_to_domains = {"cache":set()}
        if "DB" in configs.result:
            for zone, value in configs.result["DB"]:    
                unparsed_db = parser.Parser(value)
                defaults = {}
                if zone not in self.zone_to_domains:
                    self.zone_to_domains[zone] = set()
                for type in unparsed_db.result.keys():
                    new_entry = DB_entry(type, unparsed_db.result[type], defaults)
                    self.zone_to_domains[zone].add(new_entry.parameter)
                    if new_entry.type == "Default":
                        defaults[new_entry.parameter] = new_entry.value
                    self.add(new_entry)
        if "SP" in configs.result:
            for zone, value in configs.result["SP"]:
                if zone not in self.zone_to_domains:
                    self.zone_to_domains[zone] = set()
        
        #add st entrys
        for st in st_list:
            ns_entry = DB_entry("NS", [".","."])
            a_entry = DB_entry("A", [".",st])
            self.add(ns_entry)
            self.add(a_entry)


        #generate domain_to_zones
        self.domain_to_zones = {}
        for z in self.zone_to_domains:
            self.__gen_domain_to_zones(z)

    def __gen_domain_to_zones(self, zone):
        if zone in self.zone_to_domains:
            for d in self.zone_to_domains[zone]:
                self.domain_to_zones[d] = zone

    def __str__(self):
        result = ""
        for domain in self.__db:
            result += f"\n{domain}:\n"
            for type in self.__db[domain]:
                result += f"    -{type}:\n"
                for entry in self.__db[domain][type]:
                    entry_str = str(entry)
                    result += f"        --{entry_str};\n"
        result += f"\n\nself.domains:{str(self.zones)}"
        result += f"\n\nself.zone_to_domains:{str(self.zone_to_domains)}"
        return result

    def add(self, entry: DB_entry):
        if entry.parameter not in self.__db:
            self.__db[entry.parameter] = {}
        if entry.type not in self.__db[entry.parameter]:
            self.__db[entry.parameter][entry.type] = []
        self.__db[entry.parameter][entry.type].append(entry)   

    def count_entries_for_domain(self, parameter: str):
        count = 0
        for type_value in self.__db[parameter]:
            count += len(type_value)
        return count 

    def delete_zone_entrys(self, zone):
        if zone in self.zone_to_domains:
            for dom in self.zone_to_domains[zone]:
                del self.__db[dom]
                del self.domain_to_zones[dom]
            self.zone_to_domains[zone] = set()

    def is_domain_cache(self, domain):
        return domain in self.zone_to_domains["cache"]

    def is_domain_from_ss_zone(self, domain) -> bool:
        if domain in self.domain_to_zones:
            zone = self.domain_to_zones[zone]
            if zone in self.zones:
                return not self.zones[zone][0]
        return None

    def zone_transfer(self, con: socket.socket, zone: str, receiving: bool):
        if receiving:
            self.delete_zone_entrys(zone)
            while True:
                size = int.from_bytes(con.recv(2), byteorder='big')
                entry = con.recv(size).decode()
                if not entry:
                    break
                print(entry + "\n")
                new_entry = DB_entry(from_str = entry, defaults = {"@":"."})
                self.zone_to_domains[zone].add(new_entry.parameter)
                self.add(entry)
            self.__gen_domain_to_zones(zone)
            print(self.__db)
        else:
            print(self.zone_to_domains[zone])
            for d in self.zone_to_domains[zone]:
                for type in self.__db[d]:
                    for entry in self.__db[d][type]:
                        unparsed_str = str(entry)
                        con.sendall(len(unparsed_str).to_bytes(2, byteorder='big'))
                        con.sendall(unparsed_str.encode())
            print(self.__db)
        con.close()

    def get_domain_SOA(self,domain):
        x = self.__db[domain]
        return x["SOAREFRESH"], x["SOAEXPIRE"], x["SOARETRY"], x["SOASERIAL"]


#check CNAME
#check DDs -> needs sender IP
#
#
#
#
    def query(self, packet: dns_packet) -> dns_packet:
        # try:
            response_code = 0

            #check cname
            if packet.q_info in self.__db and "CNAME" in self.__db[packet.q_info]:
                packet.q_info = self.__db[packet.q_info]["CNAME"][0].value

            response = []

            queryed_param = packet.q_info
            queryed_param.reverse()
            best_match = (".",1)
            for test_param in self.__db:
                test_param.reverse()
                i=0
                points=0
                while i<len(test_param) and i<len(queryed_param):
                    if test_param[i] == queryed_param[i]:
                        points += 1 if test_param[i] == "." else 0 
                        i+=1
                    else:
                        break
                test_param.reverse()
                if best_match[1] < points:
                    best_match = (test_param, points)
            
            def check_extra(x: DB_entry, db):
                    domain = x.value
                    if 'A' in db[domain]:
                        result = ""
                        for entry in self.__db[domain]["A"]:
                            result += f"{str(entry)},"
                        return result[:-1]
            
            p = ""
            t = ""
            if packet.q_info not in self.__db:
                response_code = 2
                p = best_match[0]
            elif packet.q_type not in self.__db[packet.q_info]:
                response_code = 1
                p = packet.q_info
            else:
                p = packet.q_info
                response = [str(x) for x in self.__db[p][packet.q_type]]

            auths = [str(x) for x in self.__db[p]['NS']]
            extra = [check_extra(x, self.__db) for x in auths]

            if packet.q_type not in ["A", "DEFAULT", "SOASP", "SOAADMIN", "SOASERIAL", "SOAREFRESH", "SOARETRY", "SOAEXPIRE"] and response != []:
                extra += [check_extra(x, self.__db) for x in response]

            is_cache = packet.q_info in self.zone_to_domains["cache"]
            is_ss_domain = response_code < 2 and (self.is_domain_from_ss_zone(packet.q_info))
            #flag_r might need change
            flag_r = is_cache
            flag_a = not (is_cache or is_ss_domain)
            flags = (False, flag_r, flag_a)

            return dns_packet.dns_packet(
                flags = flags,
                # 0 = sucesso, 
                # 1 = o nome existe, mas não há name e type,
                # 2 = resposta negativa - retorna autoridades
                # 3 = mensagem não foi descodificada corretamente
                responseCode = response_code,
                # numero de entries com aquele nome e tipo
                numValues = len(response),
                # numero de entries com match no nome, com tipo NS
                numAuths = len(auths),
                # numero de IP com match no nome em auths e extra, com tipo A
                numExtra = len(extra),
                queryInfo = packet.queryInfo,
                responseValues = response,
                authValues = auths,
                extraValues = extra,
                msgID = packet.message_id
            )

        # except:
        #     print("bum")
        #     return dns_packet.dns_packet(
        #         flags = packet.flags,
        #         responseCode = 3,
        #         queryInfo = packet.queryInfo,
        #         msgID = packet.message_id
        #     )

    # def default(self, parameter_dict):



# def foo():
#     config = parser.Parser("config")
    # return DB(config), dns_packet.dns_packet(flags=(True,False,False), queryInfo=("dias.", "MX"))