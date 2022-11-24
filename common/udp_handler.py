import socket
from common.ip import IP

#funciona com mensagens ate 2048
#mensagens maiores que 2048 so recebe 2048 bytes
#falta calcular overhead de headers
class UDP_Handler:
    def __init__(self, ip: IP = None):
        self.ip = ip
        self.bufferSize = 2048
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if ip != None:    
            self.socket.bind(self.ip.ip_tuple())
        else:    
            self.socket.bind(('', 53))

    def receive(self):
        return self.socket.recvfrom(self.bufferSize)
    
    def send(self, message, destiny: IP):
        self.socket.sendto(message, destiny.ip_tuple())

    def close(self):
        self.socket.close()
