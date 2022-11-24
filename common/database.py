import socket
from common import dns_packet
from common import parser
from common import ip

class DB:

    def __init__(self, configs):
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
        self.__db = {}
        self.domains = {}
        if "SP" in configs.result:
            for domain, server_ip in configs.result["SP"]:

                is_ip, has_port = ip.check_ip(server_ip)
                if is_ip:
                    if not has_port:
                        server_ip+= ":53"
                    server_ip = ip.IP(server_ip, has_port=True)

                if domain not in self.domains:
                    self.domains[domain] = (False, server_ip)

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
                if domain not in self.domains:
                    self.domains[domain] = (True, server_ip)
        

        self.authority_to_domains = {}
        if "DB" in configs.result:
            for authority, value in configs.result["DB"]:    
                unparsed_db = parser.Parser(value)
                if authority not in self.authority_to_domains:
                    self.authority_to_domains[authority] = set()
                for type in unparsed_db.result.keys():
                    value_list = unparsed_db.result[type]
                    for t in value_list:
                        self.authority_to_domains[authority].add(t[0])
                        match len(t):
                            case 2:
                                self.add(authority, t[0], type, t[0])
                            case 3:
                                self.add(authority, t[0], type, t[1], t[2])
                            case 4:
                                self.add(authority, t[0], type, t[1], t[2], t[3])

    def __str__(self):
        result = ""
        for domain in self.__db:
            result += f"\n{domain}:\n"
            for type in self.__db[domain]:
                result += f"    -{type}:\n"
                for entry in self.__db[domain][type]:
                    entry_str = self.default_entry_repr(domain, type, entry)
                    result += f"        --{entry_str};\n"
        result += f"\n\nself.domains:{str(self.domains)}"
        result += f"\n\nself.authority_to_domains:{str(self.authority_to_domains)}"
        return result




    def add(self, authority, parameter, value_type, value, ttl = 0, priority = 1):
        parameter = self.gen_complete_domain(authority, parameter)
        if parameter not in self.__db:
            self.__db[parameter] = {}
        parameters = self.__db[parameter]
        if value_type not in self.__db[parameter]:
            self.__db[parameter][value_type] = []
        parameters[value_type].append((value, ttl, priority))
        self.__db[parameter] = parameters # is this really necessary?

    def gen_complete_domain(self, authority, domain):
        if domain[-1] != ".":
            domain+=f".{authority}"
        return domain       

    def count_entries_for_domain(self, parameter: str):
        count = 0
        for type_value in self.__db[parameter]:
            count += len(type_value)
        return count 
        
    def zone_transfer(self, con: socket.socket, domain: str, receiving: bool):
        if receiving:
            if domain in self.authority_to_domains:
                for dom in self.authority_to_domains[domain]:
                    del self.__db[dom]
            while True:
                size = int.from_bytes(con.recv(2), byteorder='big')
                entry = con.recv(size).decode()
                if not entry:
                    break
                print(entry + "\n")
                p = entry.split()
                self.add(domain, p[0], p[1], p[2], p[3], p[4])
            print(self.__db)
        else:
            print(self.authority_to_domains[domain])
            for d in [self.gen_complete_domain(domain, d) for d in self.authority_to_domains[domain]]:
                for type in self.__db[d]:
                    for entry in self.__db[d][type]:
                        unparsed_str = self.default_entry_repr(d, type, entry)
                        print(unparsed_str + "\n")
                        con.sendall(len(unparsed_str).to_bytes(2, byteorder='big'))
                        con.sendall(unparsed_str.encode())
            print(self.__db)
        con.close()
    
    def default_entry_repr(self,domain, type, entry):
        unparsed_str = f"{domain} {type} {entry[0]}"
        match len(entry):
            case 2:
                unparsed_str += f" {entry[1]}"
            case 3:
                unparsed_str += f" {entry[1]} {entry[2]}"
        return unparsed_str

    def get_domain_SOA(self,domain):
        x = self.__db[domain]
        return x["SOAREFRESH"], x["SOAEXPIRE"], x["SOARETRY"], x["SOASERIAL"]

    def query(self, packet):
        # try:
            response_code = 0

            def check_extra(x, db):
                    splits = x.split() # 0: domain, 1: type, 2: entry
                    address = splits[2]
                    if 'A' in db[address]:
                        result = ""
                        for entry in self.__db[address]["A"]:
                            result += f"{self.default_entry_repr(address, 'A', entry)},"
                        return result[:-1]

            response = []
            num_responses = 0

            if packet.q_info not in self.__db:
                response_code = 2
                auths = [self.default_entry_repr(packet.q_info, "NS", x) for x in self.__db[packet.q_info]['NS']]
                extra = [check_extra(x, self.__db) for x in auths]
            elif packet.q_type not in self.__db[packet.q_info]:
                response_code = 1
                auths = [self.default_entry_repr(packet.q_info, "NS", x) for x in self.__db[packet.q_info]['NS']]
                extra = [check_extra(x, self.__db) for x in auths]
            else:
                response = [self.default_entry_repr(packet.q_info, packet.q_type, x) for x in self.__db[packet.q_info][packet.q_type]]
                auths = [self.default_entry_repr(packet.q_info, "NS", x) for x in self.__db[packet.q_info]['NS']]
                extra = [check_extra(x, self.__db) for x in auths]
                if packet.q_type not in ['A', "DEFAULT", "SOASP", "SOAADMIN", "SOASERIAL", "SOAREFRESH", "SOARETRY", "SOAEXPIRE"]:
                    extra += [check_extra(x, self.__db) for x in response]
                num_responses = len(response)
                

            


            if packet.q_info in self.domains:
                flags = (False, self.domains[packet.q_info][0], packet.flags[1])

            return dns_packet.dns_packet(
                flags = flags,
                # 0 = sucesso, 
                # 1 = o nome existe, mas não há name e type,
                # 2 = resposta negativa - retorna autoridades
                # 3 = mensagem não foi descodificada corretamente
                responseCode = response_code,
                # numero de entries com aquele nome e tipo
                numValues = num_responses,
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