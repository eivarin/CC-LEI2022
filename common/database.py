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
        self.server_type = server_type # 'SS' e 'SP'
        self.__db = {}
        # self.__macros = {}
        for k in parameter_dict.keys():
            l = parameter_dict[k]
            for b, c, d, e in l:
                self.add(k, b, c, d, e)

        self.__server_list = set()
        
        self.__auths = set()
        for i in configs:
            if i is 'server':
                self.__auths.add(i)

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
        
    def zone_transfer(self, con, domain: str):
        ...
    
    def query(self, packet):
        try:
            response_code = 0
            
            if packet.q_info not in self.__db:
                reponse_code = 2
            elif packet.q_type not in self.__db[packet.q_info]:
                reponse_code = 1

            response = self.__db[packet.q_info][packet.q_type]
            auths = self.__db[packet.q_info]['NS']
            # TODO: melhor parse para os A
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
                numValues = ,
                # numero de entries com match no nome, com tipo NS
                numAuths = len(auths),
                # numero de IP com match no nome em auths e extra, com tipo A
                numExtra = ,
                queryInfo = packet.queryInfo,
                responseValues = results,
                authValues = auths,
                extraValues = ,
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
        