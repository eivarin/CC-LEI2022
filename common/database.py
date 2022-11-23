import socket
import dns_packet

class DB:
    def __init__(self, parameter_dict, configs, server_type = 'SS'):
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
        self.id = 0
        self.server_type = server_type # 'SS' e 'SP'
        self.__db = {}
        # self.__macros = {}
        for k in parameter_dict.keys():
            l = parameter_dict[k]
            for b, c, d, e in l:
                self.add(k, b, c, d, e)

        self.domains = {}
        for domain, _ in configs["SP"]:
            if domain not in self.domains:
                self.domains[domain] = False
        for domain, _ in configs["SS"] + configs["DB"]:
            if domain not in self.domains:
                self.domains[domain] = True



    def add(self, parameter, value_type, value, ttl, priority):
        parameters = self.__db[parameter]
        if parameters == None:
            parameters = []
        parameters[value_type].append((value, ttl, priority))
        self.__db[parameter] = parameters # is this really necessary?

        

    def count_entries_for_domain(self, parameter: str):
        count = 0
        for type_value in self.__db[parameter]:
            count += len(type_value)
        return count 

    def add_domain(self, server):
        self.__server_list.add(server)
        
    def zone_transfer(self, con: socket.socket, domain: str):
        for type in self.__db[domain]:
            for entry in self.__db[domain][type]:
                unparsed_str = self.unparsed_str(domain, type, entry)
                con.sendall(unparsed_str.encode())
        con.close()
    
    def default_entry_repr(self,domain, type, entry):
        unparsed_str = f"{domain} {type} {entry[0]}"
        match len(entry):
            case 2:
                unparsed_str += f" {entry[1]}"
            case 3:
                unparsed_str += f" {entry[1]} {entry[2]}"
        return unparsed_str


    def query(self, packet):
        try:
            response_code = 0
            
            if packet.q_info not in self.__db:
                reponse_code = 2
            elif packet.q_type not in self.__db[packet.q_info]:
                reponse_code = 1


            response = [self.default_entry_reprlt(x) for x in self.__db[packet.q_info][packet.q_type]]
            auths = [self.default_query_repr(x) for x in self.__db[packet.q_info]['NS']]

            # def check_extra(x, db):
            #     splits = x.split() # 0: domain, 1: type, 2: entry
            #     return db[splits[0]][splits[1]]

            # extra = [x for x in auths if x.split(' ')[1] == 'A']
            # if packet.q_type != 'A':
            #     extra += [x for x in response if ]

            num_responses = len(response)
            
            # caso do 2
            if num_responses == 0:
                response_code = 2
                response = []              

            return dns_packet.dns_packet(
                flags = packet.flags,
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

        except:
            return dns_packet.dns_packet(
                flags = packet.flags,
                responseCode = 3,
                queryInfo = packet.queryInfo,
                msgID = packet.message_id
            )

    # def default(self, parameter_dict):
        