import random
from struct import pack, unpack
import ctypes as C

class dns_packet:

    format_string = "HBBBB"
    joiner_inner = '+'
    joiner_outer = '~'

    def encodePacket(self):
        flags_and_response = self.encode_flags_and_response()

        result = pack(self.format_string, self.message_id, flags_and_response, self.num_values, self.num_auths, self.num_extra)

        result += self.dataFields.encode(encoding="ascii", errors="replace")
        return result

    def decodePacket(self, packet):
        header = packet[:48]
        datafields = packet[48:].decode(encoding="ascii", errors="replace")
        
        self.message_id, flags_and_response, self.num_values, self.num_auths, self.num_extra = unpack(self.format_string, header)

        self.decode_flags_and_response(flags_and_response)

        unpacked_data_fields = datafields.split(self.joiner_outer)
        self.q_info = unpacked_data_fields[0]
        self.q_type = unpacked_data_fields[1]
        self.num_values = unpacked_data_fields[0].split(self.joiner_inner)
        self.num_auths = unpacked_data_fields[0].split(self.joiner_inner)
        self.num_extra = unpacked_data_fields[0].split(self.joiner_inner)

    def encode_flags_and_response(self):
        a, b, c = self.flags
        # queres guardar na classe ou return?
        return C.c_uint8_t(int(f'{a:01b}{b:01b}{c:01b}{self.responseCode:03b}', 2))

    def decode_flags_and_response(self, to_decode: C.c_uint8_t):
        self.flags = (
        (to_decode & 8) == 8,
        (to_decode & 16) == 16,
        (to_decode & 32) == 32
        )
        self.responseCode = to_decode & 7;

    def __init__(self,flags: Tuple[bool,bool,bool],responseCode,numValues,numAuths,numExtra,queryInfo: Tuple[str,str],responseValues,authValues,extraValues,msgID = random.randint(1,65535)):
        self.message_id=msgID
        self.flags = flags
        self.responseCode=responseCode
        self.num_values = numValues
        self.num_auths = numAuths
        self.num_extra = numExtra
        if self.queryInfo:
            self.q_info, self.q_type = queryInfo
        self.val_response = responseValues
        self.val_authority = authValues
        self.val_extra = extraValues
        inter_list = [
            self.q_info,
            self.q_type,
            self.gen_str_of_strs(self.val_response,self.joiner_inner),
            self.gen_str_of_strs(self.val_authority, self.joiner_inner),
            self.gen_str_of_strs(self.val_extra,self.joiner_inner)
        ]
        self.dataFields = self.gen_str_of_strs(inter_list, self.joiner_outer)
        self.encode()
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

    