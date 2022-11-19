import random

class dns_packet:

    def encodePacket(self,s):
        return s.encode('utf-8')

    def decodePacket(self,s):
        return s.decode('utf-8')
    # Flags - 0 - Q; 1 - R; 10 - A ; 1111 - nulo
    def __init__(self,responseCode,numValues,numAuths,numExtra,responseValues,authValues,extraValues,flags = 1111 ,msgID = random.randint(1,65535),queryInfo = None):
        msg = msgID.__str__()
        msg ++ flags.__str__()
        dataFields = responseCode ++ numValues ++ numAuths ++ numExtra
        if len(self.enconde(dataFields)) > 1000:
            print("data is to big")
            return -1
        if responseCode in [1,2,3] and numValues < 255 and numAuths < 255 and numExtra < 255:
            msg ++ responseCode ++ numValues ++ numAuths ++ numExtra
        else:
            print("values are out of scope")
            return -1
        if queryInfo is not None:
            msg ++ queryInfo
        msg ++ responseValues ++ authValues ++ extraValues
        self.msgDNS = msg