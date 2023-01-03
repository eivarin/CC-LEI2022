import random
from struct import pack, unpack
import ctypes as C

class dns_packet:

    format_string = "HBBBB"
    joiner_inner = '+'
    joiner_outer = '~'

    def encodePacket(self):
        flags_and_response = self.encode_flags_and_response()

        result = pack(self.format_string, self.message_id, flags_and_response.value, self.num_values, self.num_auths, self.num_extra)

        result += self.dataFields.encode(encoding="ascii", errors="replace")
        return result

    def decodePacket(self, packet):
        header = packet[:6]
        datafields = packet[6:].decode(encoding="ascii", errors="replace")
        
        self.message_id, flags_and_response, self.num_values, self.num_auths, self.num_extra = unpack(self.format_string, header)

        self.decode_flags_and_response(flags_and_response)

        unpacked_data_fields = datafields.split(self.joiner_outer)
        self.q_info = unpacked_data_fields[0]
        self.q_type = unpacked_data_fields[1]
        self.queryInfo = (self.q_info, self.q_type)
        self.val_response =  list(filter(lambda s: s!="", unpacked_data_fields[2].split(self.joiner_inner)))
        self.val_zone = list(filter(lambda s: s!="", unpacked_data_fields[3].split(self.joiner_inner)))
        self.val_extra =     list(filter(lambda s: s!="", unpacked_data_fields[4].split(self.joiner_inner)))
        inter_list = [
                self.q_info,
                self.q_type,
                self.gen_str_of_strs(self.val_response,self.joiner_inner),
                self.gen_str_of_strs(self.val_zone, self.joiner_inner),
                self.gen_str_of_strs(self.val_extra,self.joiner_inner)
            ]
        self.dataFields = self.gen_str_of_strs(inter_list, self.joiner_outer)


    def encode_flags_and_response(self):
        a, b, c = self.flags
        # queres guardar na classe ou return?
        return C.c_uint8(int(f'{a:01b}{b:01b}{c:01b}{self.responseCode:03b}', 2))

    def decode_flags_and_response(self, to_decode: C.c_uint8):
        self.flags = (
            (to_decode & 32) == 32,
            (to_decode & 16) == 16,
            (to_decode & 8) == 8
        )
        self.responseCode = to_decode & 7

    def __str__(self):
        header = f"{self.message_id},{self.flags},{self.responseCode},{self.num_values},{self.num_auths},{self.num_extra};{self.q_info},{self.q_type}\n"
        values = "values:\n"
        for value in self.val_response:
            values += f"{value},\n"
        auths = "auths:\n"
        for auth in self.val_zone:
            auths += f"{auth},\n"
        extras = "extras:\n"
        for extra in self.val_extra:
            extras += f"{extra},\n"    
        return header + values + auths + extras

    #qra:query,recursive,auth
    def __init__(self,
                flags: tuple[bool,bool,bool] = [False,False,False],
                responseCode = 0,
                numValues = 0,
                numAuths = 0,
                numExtra = 0,
                queryInfo: tuple[str,str] = ("",""),
                responseValues = [],
                authValues = [],
                extraValues = [],
                msgID = random.randint(1,65535),
                encoded_bytes = []):
        if encoded_bytes != []:
            self.decodePacket(encoded_bytes)
        else:
            self.message_id=msgID
            self.flags = flags
            self.responseCode=responseCode
            self.num_values = numValues
            self.num_auths = numAuths
            self.num_extra = numExtra
            self.queryInfo = queryInfo
            if self.queryInfo:
                self.q_info, self.q_type = queryInfo
            self.val_response = responseValues
            self.val_zone = authValues
            self.val_extra = extraValues
            inter_list = [
                self.q_info,
                self.q_type,
                self.gen_str_of_strs(self.val_response,self.joiner_inner),
                self.gen_str_of_strs(self.val_zone, self.joiner_inner),
                self.gen_str_of_strs(self.val_extra,self.joiner_inner)
            ]
            self.dataFields = self.gen_str_of_strs(inter_list, self.joiner_outer)
            # dataFields = responseCode ++ numValues ++ numAuths ++ numExtra
            # if len(self.enconde(dataFields)) > 1024:
            #     print("data is to big")
            #     return -1
            # if responseCode in [1,2,3] and numValues < 255 and numAuths < 255 and numExtra < 255:
            #     msg ++ responseCode ++ numValues ++ numAuths ++ numExtra
            # else:
            #     print("values are out of scope")
            #     return -1
            # if queryInfo is not None:
            #     msg ++ queryInfo
            # msg ++ responseValues ++ authValues ++ extraValues
            # self.msgDNS = msg
        
    def gen_str_of_strs(self, list, joiner):
        s = joiner.join(list)
        return s

    